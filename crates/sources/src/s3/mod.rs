//! S3 bucket source: lists text-like objects with ListObjectsV2 and downloads
//! each candidate object for scanning. Large or non-text objects are skipped.

use std::io::Read;
use std::path::Path;

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use reqwest::blocking::Client;

mod auth;
mod listing;

use auth::AwsSigV4Config;
use listing::{encode_s3_key_path, parse_s3_listing};

const DEFAULT_S3_HOST_SUFFIX: &str = "s3.amazonaws.com";
const DEFAULT_MAX_OBJECTS: usize = 100_000;
const MAX_S3_OBJECT_BYTES: u64 = 10 * 1024 * 1024;

/// Scan text objects in an S3 bucket via the ListObjectsV2 REST API.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::Source;
/// use keyhog_sources::S3Source;
///
/// let source = S3Source::new("bucket-name").with_prefix("configs/");
/// assert_eq!(source.name(), "s3");
/// ```
pub struct S3Source {
    bucket: String,
    prefix: Option<String>,
    endpoint: Option<String>,
    max_objects: usize,
    /// Shared HTTP policy (proxy, insecure_tls, ua_suffix, timeout). Defaults
    /// to `HttpClientConfig::default()` (env-var fallbacks honored). Set via
    /// `with_http_config` so the CLI's `--proxy` / `--insecure` reach this
    /// source instead of silently bypassing it.
    http: crate::http::HttpClientConfig,
}

impl S3Source {
    /// Create a source that lists and downloads text objects from `bucket`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Source;
    /// use keyhog_sources::S3Source;
    ///
    /// let source = S3Source::new("bucket-name");
    /// assert_eq!(source.name(), "s3");
    /// ```
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            prefix: None,
            endpoint: None,
            max_objects: DEFAULT_MAX_OBJECTS,
            http: crate::http::HttpClientConfig {
                ua_suffix: Some("s3".into()),
                ..Default::default()
            },
        }
    }

    /// Override the shared HTTP policy (proxy, insecure TLS, UA suffix,
    /// per-request timeout). Used by the CLI to thread `--proxy` /
    /// `--insecure` through to the S3 client; without this every S3 fetch
    /// would silently bypass the configured proxy and corp-mandated MITM CA.
    pub fn with_http_config(mut self, http: crate::http::HttpClientConfig) -> Self {
        self.http = http;
        self
    }

    /// Limit scanning to objects whose keys start with `prefix`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Source;
    /// use keyhog_sources::S3Source;
    ///
    /// let source = S3Source::new("bucket-name").with_prefix("configs/");
    /// assert_eq!(source.name(), "s3");
    /// ```
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// Override the S3 endpoint, for example for MinIO or other S3-compatible APIs.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Source;
    /// use keyhog_sources::S3Source;
    ///
    /// let source = S3Source::new("bucket-name").with_endpoint("https://minio.example.com");
    /// assert_eq!(source.name(), "s3");
    /// ```
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Limit the number of objects listed from the bucket before stopping.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Source;
    /// use keyhog_sources::S3Source;
    ///
    /// let source = S3Source::new("bucket-name").with_max_objects(25);
    /// assert_eq!(source.name(), "s3");
    /// ```
    pub fn with_max_objects(mut self, max_objects: usize) -> Self {
        self.max_objects = max_objects;
        self
    }
}

impl Source for S3Source {
    fn name(&self) -> &str {
        "s3"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        match collect_s3_chunks(
            &self.bucket,
            self.prefix.as_deref(),
            self.endpoint.as_deref(),
            self.max_objects,
            &self.http,
        ) {
            Ok(chunks) => Box::new(chunks.into_iter().map(Ok)),
            Err(error) => Box::new(std::iter::once(Err(error))),
        }
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn collect_s3_chunks(
    bucket: &str,
    prefix: Option<&str>,
    endpoint: Option<&str>,
    max_objects: usize,
    http: &crate::http::HttpClientConfig,
) -> Result<Vec<Chunk>, SourceError> {
    let bucket = validate_bucket_name(bucket)?;
    // Honor the shared HTTP policy (proxy, insecure TLS, UA). Falls back to
    // the per-source default timeout when `http.timeout` is None - keeps the
    // existing behavior for callers that don't override.
    let http = if http.timeout.is_none() {
        let mut h = http.clone();
        h.timeout = Some(crate::timeouts::HTTP_REQUEST);
        h
    } else {
        http.clone()
    };
    let client = crate::http::blocking_client_builder(&http)
        .map_err(SourceError::Other)?
        .build()
        .map_err(|e| SourceError::Other(format!("failed to build S3 client: {e}")))?;
    let base_url = build_base_url(&bucket, endpoint)?;
    // Issue #4: scope SigV4 auto-signing to AWS-owned endpoints. When the
    // user points `--s3-endpoint` at a non-AWS host (MinIO, Ceph, attacker-
    // controlled), reading `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
    // and attaching a signed `Authorization` header to that request hands
    // the developer's AWS identity material to a third party they never
    // explicitly opted into. Default policy: refuse to forward ambient
    // creds to custom endpoints. The operator opts in via
    // `KEYHOG_S3_ALLOW_CREDENTIAL_FORWARD=1` (env-only, no CLI surface
    // so it can't be set accidentally by shell history) when they've
    // verified the endpoint and accept the credential-leak exposure.
    let aws_auth = if endpoint.is_none() || endpoint_is_aws(endpoint.unwrap_or("")) {
        AwsSigV4Config::from_env(&base_url)
    } else if credential_forward_allowed() {
        tracing::warn!(
            endpoint = %endpoint.unwrap_or(""),
            "KEYHOG_S3_ALLOW_CREDENTIAL_FORWARD=1: forwarding ambient AWS \
             credentials to non-AWS endpoint. Verify you trust this host."
        );
        AwsSigV4Config::from_env(&base_url)
    } else {
        if std::env::var("AWS_ACCESS_KEY_ID").is_ok() {
            tracing::warn!(
                endpoint = %endpoint.unwrap_or(""),
                "AWS credentials present but endpoint is non-AWS; refusing to \
                 forward. Set KEYHOG_S3_ALLOW_CREDENTIAL_FORWARD=1 to opt in."
            );
        }
        None
    };
    let mut continuation_token = None::<String>;
    let mut chunks = Vec::new();
    let mut listed_objects = 0usize;

    loop {
        if listed_objects >= max_objects {
            break;
        }

        let mut request = client.get(&base_url).query(&[("list-type", "2")]);
        if let Some(prefix) = prefix {
            request = request.query(&[("prefix", prefix)]);
        }
        if let Some(token) = continuation_token.as_deref() {
            request = request.query(&[("continuation-token", token)]);
        }
        if let Some(auth) = aws_auth.as_ref() {
            request = auth.sign(request, &base_url)?;
        }

        let response = request
            .send()
            .map_err(|e| SourceError::Other(format!("failed to list S3 objects: {e}")))?;

        if !response.status().is_success() {
            return Err(SourceError::Other(format!(
                "failed to list S3 objects: bucket request returned {}",
                response.status()
            )));
        }

        let body = response
            .text()
            .map_err(|e| SourceError::Other(format!("failed to read S3 listing: {e}")))?;
        let listing = parse_s3_listing(&body)?;
        let remaining = max_objects.saturating_sub(listed_objects);
        let reached_limit = listing.contents.len() > remaining;
        let page: Vec<_> = listing.contents.into_iter().take(remaining).collect();
        listed_objects += page.len();

        // Concurrent per-page fetcher. S3 is designed for massive concurrent
        // GETs; the previous sequential loop wasted 90%+ of wall-clock on
        // large buckets. We use rayon (the workspace's parallelism primitive)
        // bounded to 16 in-flight downloads - high enough to saturate
        // reasonable bandwidth, low enough to avoid hammering small buckets.
        use rayon::prelude::*;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(16)
            .build()
            .map_err(|e| SourceError::Other(format!("rayon pool build: {e}")))?;
        let page_chunks: Vec<Result<Option<Chunk>, SourceError>> = pool.install(|| {
            page.par_iter()
                .map(|object| -> Result<Option<Chunk>, SourceError> {
                    if object.size == 0 || !is_probably_text(&object.key) {
                        return Ok(None);
                    }
                    fetch_object_chunk(
                        &client,
                        &base_url,
                        &bucket,
                        &object.key,
                        object.size,
                        aws_auth.as_ref(),
                    )
                })
                .collect()
        });
        for result in page_chunks {
            if let Some(chunk) = result? {
                chunks.push(chunk);
            }
        }

        if reached_limit || !listing.is_truncated {
            break;
        }
        continuation_token = listing.next_continuation_token;
        if continuation_token.is_none() {
            break;
        }
    }

    Ok(chunks)
}

fn fetch_object_chunk(
    client: &Client,
    base_url: &str,
    bucket: &str,
    key: &str,
    object_size: u64,
    aws_auth: Option<&AwsSigV4Config>,
) -> Result<Option<Chunk>, SourceError> {
    if object_size > MAX_S3_OBJECT_BYTES {
        tracing::debug!(
            "failed to read S3 object: {}/{} exceeds {} byte limit with {} bytes",
            bucket,
            key,
            MAX_S3_OBJECT_BYTES,
            object_size
        );
        return Ok(None);
    }

    let encoded_key = encode_s3_key_path(key);
    let url = format!("{}/{}", base_url.trim_end_matches('/'), encoded_key);
    let request = client.get(&url);
    let request = if let Some(auth) = aws_auth {
        auth.sign(request, &url)?
    } else {
        request
    };
    let response = request
        .send()
        .map_err(|e| SourceError::Other(format!("failed to download S3 object: {key}: {e}")))?;

    if !response.status().is_success() {
        return Ok(None);
    }

    if let Some(content_length) = response.content_length() {
        if content_length > MAX_S3_OBJECT_BYTES {
            tracing::debug!(
                "failed to read S3 object: {}/{} content-length {} exceeds {} byte limit",
                bucket,
                key,
                content_length,
                MAX_S3_OBJECT_BYTES
            );
            return Ok(None);
        }
    }

    // Skip objects that declare a binary content type - they won't contain text secrets.
    if let Some(ct) = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
    {
        let ct_lower = ct.to_ascii_lowercase();
        if ct_lower.starts_with("image/")
            || ct_lower.starts_with("audio/")
            || ct_lower.starts_with("video/")
            || ct_lower == "application/octet-stream"
            || ct_lower == "application/zip"
            || ct_lower == "application/gzip"
        {
            tracing::debug!("skipping S3 object {key}: binary content-type {ct}");
            return Ok(None);
        }
    }

    // Read the response body with a hard size cap. The blocking client
    // lacks byte-stream support, so we use `copy()` into a size-limited
    // buffer to abort before the full response is buffered into memory.
    let mut body = Vec::new();
    let mut reader = response.take(MAX_S3_OBJECT_BYTES + 1);
    std::io::Read::read_to_end(&mut reader, &mut body)
        .map_err(|e| SourceError::Other(format!("failed to read S3 object body: {key}: {e}")))?;
    if body.len() as u64 > MAX_S3_OBJECT_BYTES {
        tracing::debug!(
            "failed to read S3 object: {}/{} downloaded size exceeds {} byte limit",
            bucket,
            key,
            MAX_S3_OBJECT_BYTES
        );
        return Ok(None);
    }
    // Strict UTF-8 because the content-type guard above already
    // accepted this as a text object. If the bytes don't decode it
    // usually means the server lied about Content-Type (gzip body
    // claiming `text/plain`, EBCDIC mainframe export, etc.).
    // Surface the skip so a user staring at "0 findings" on a bucket
    // they know has text objects can see what happened, instead of
    // silently dropping the chunk.
    let object_text = match String::from_utf8(body) {
        Ok(text) => text,
        Err(error) => {
            let valid_up_to = error.utf8_error().valid_up_to();
            tracing::warn!(
                bucket,
                key,
                valid_up_to,
                "skipping S3 object: body claimed text content-type but failed UTF-8 decode"
            );
            return Ok(None);
        }
    };

    Ok(Some(Chunk {
        data: object_text.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            source_type: "s3".into(),
            path: Some(format!("{bucket}/{key}")),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: None,
        },
    }))
}

/// True iff `endpoint` resolves to an AWS-owned host (S3 regional or
/// dual-stack). Issue #4: only AWS-owned endpoints should receive
/// ambient `AWS_ACCESS_KEY_ID` SigV4-signed traffic by default.
///
/// AWS S3 hostnames take the shape `<bucket>.s3.<region>.amazonaws.com`,
/// `<bucket>.s3.amazonaws.com`, or the dual-stack variant
/// `<bucket>.s3.dualstack.<region>.amazonaws.com`. We treat any host
/// whose registrable suffix is `amazonaws.com` as AWS-owned and
/// everything else as third-party. Conservative on purpose: a typo'd
/// host (`s3.amazonaws.co`) falls into the non-AWS bucket and the
/// operator must opt in explicitly.
pub fn endpoint_is_aws(endpoint: &str) -> bool {
    let parsed = match reqwest::Url::parse(endpoint) {
        Ok(u) => u,
        Err(_) => return false,
    };
    let host = match parsed.host_str() {
        Some(h) => h.to_ascii_lowercase(),
        None => return false,
    };
    host == "amazonaws.com"
        || host.ends_with(".amazonaws.com")
        || host.ends_with(".amazonaws.com.cn")
}

/// True iff the operator has explicitly opted into forwarding ambient
/// AWS credentials to non-AWS endpoints. `KEYHOG_S3_ALLOW_CREDENTIAL_FORWARD`
/// is env-only (no CLI surface) so it can't be silently set by shell
/// history or a stale `--flag` in someone's notes.
pub fn credential_forward_allowed() -> bool {
    matches!(
        std::env::var("KEYHOG_S3_ALLOW_CREDENTIAL_FORWARD")
            .ok()
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

fn build_base_url(bucket: &str, endpoint: Option<&str>) -> Result<String, SourceError> {
    match endpoint {
        Some(endpoint) => {
            let endpoint = validate_endpoint(endpoint)?;
            Ok(format!(
                "{}/{}",
                endpoint.trim_end_matches('/'),
                urlencoding::encode(bucket)
            ))
        }
        None => Ok(format!("https://{bucket}.{DEFAULT_S3_HOST_SUFFIX}")),
    }
}

fn validate_bucket_name(bucket: &str) -> Result<String, SourceError> {
    let bucket = bucket.trim();
    if bucket.len() < 3 || bucket.len() > 63 {
        return Err(SourceError::Other("invalid S3 bucket name length".into()));
    }
    if bucket.starts_with('.')
        || bucket.ends_with('.')
        || bucket.starts_with('-')
        || bucket.ends_with('-')
        || bucket.contains("..")
        || bucket.contains('/')
        || bucket.chars().any(char::is_control)
    {
        return Err(SourceError::Other(format!("invalid S3 bucket '{bucket}'")));
    }
    if !bucket
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '-'))
    {
        return Err(SourceError::Other(format!("invalid S3 bucket '{bucket}'")));
    }
    Ok(bucket.to_string())
}

fn validate_endpoint(endpoint: &str) -> Result<String, SourceError> {
    let endpoint = endpoint.trim();
    let parsed = reqwest::Url::parse(endpoint)
        .map_err(|e| SourceError::Other(format!("invalid S3 endpoint: {e}")))?;

    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(SourceError::Other("invalid S3 endpoint".into()));
    }

    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn is_probably_text(key: &str) -> bool {
    let ext = Path::new(key)
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());

    !matches!(
        ext.as_deref(),
        Some(
            "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "webp"
                | "zip"
                | "gz"
                | "tgz"
                | "tar"
                | "7z"
                | "pdf"
                | "woff"
                | "woff2"
                | "mp3"
                | "mp4"
                | "mov"
                | "dll"
                | "so"
                | "dylib"
        )
    )
}
