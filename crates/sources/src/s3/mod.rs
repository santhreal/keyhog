//! S3 bucket source: lists text-like objects with ListObjectsV2 and downloads
//! each candidate object for scanning. Large or non-text objects are skipped.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use reqwest::blocking::Client;
use std::io::Read;

mod auth;
mod listing;

use auth::AwsSigV4Config;
use listing::parse_s3_listing;

const DEFAULT_S3_HOST_SUFFIX: &str = "s3.amazonaws.com";
const DEFAULT_MAX_OBJECTS: usize = 100_000;

/// Scan text objects in an S3 bucket via the ListObjectsV2 REST API.
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
pub struct S3Source {
    bucket: String,
    prefix: Option<String>,
    endpoint: Option<String>,
    max_objects: usize,
    limits: crate::SourceLimits,
    /// Shared HTTP policy (proxy, insecure_tls, ua_suffix, timeout). Defaults
    /// to `HttpClientConfig::default()` (no ambient proxy/TLS env). Set via
    /// `with_http_config` so the CLI's `--proxy` / `--insecure` reach this
    /// source instead of silently bypassing it.
    http: crate::http::HttpClientConfig,
    allow_credential_forward: bool,
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
            limits: crate::SourceLimits::default(),
            http: crate::http::HttpClientConfig {
                ua_suffix: Some("s3".into()),
                ..Default::default()
            },
            allow_credential_forward: false,
        }
    }

    /// Override the shared HTTP policy (proxy, insecure TLS, UA suffix,
    /// per-request timeout). Used by the CLI to thread `--proxy` /
    /// `--insecure` through to the S3 client; without this every S3 fetch
    /// would silently bypass the configured proxy and corp-mandated MITM CA.
    pub(crate) fn with_http_config(mut self, http: crate::http::HttpClientConfig) -> Self {
        self.http = http;
        self
    }

    /// Allow forwarding ambient AWS credentials to a non-AWS S3-compatible
    /// endpoint. This is intentionally caller-explicit; no keyhog env var can
    /// weaken the credential-forwarding policy.
    pub(crate) fn with_allow_credential_forward(mut self, allow: bool) -> Self {
        self.allow_credential_forward = allow;
        self
    }

    pub(crate) fn with_limits(mut self, limits: crate::SourceLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Limit scanning to objects whose keys start with `prefix`.
    ///
    pub(crate) fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// Override the S3 endpoint, for example for MinIO or other S3-compatible APIs.
    pub(crate) fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Limit the number of objects listed from the bucket before stopping.
    pub(crate) fn with_max_objects(mut self, max_objects: usize) -> Self {
        self.max_objects = max_objects;
        self
    }
}

impl Source for S3Source {
    fn name(&self) -> &str {
        "s3"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        // `reqwest::blocking` must run off the CLI's `#[tokio::main]` thread
        // (dropping its internal runtime in an async context aborts the
        // process). Collection is eager, so run it on a scoped std thread with
        // no ambient tokio runtime.
        let result = std::thread::scope(|s| {
            match s
                .spawn(|| {
                    collect_s3_chunks(
                        &self.bucket,
                        self.prefix.as_deref(),
                        self.endpoint.as_deref(),
                        self.max_objects,
                        self.limits,
                        &self.http,
                        self.allow_credential_forward,
                    )
                })
                .join()
            {
                Ok(result) => result,
                Err(_panic) => Err(SourceError::Other("s3 fetch thread panicked".to_string())),
            }
        });
        match result {
            Ok(rows) => Box::new(rows.into_iter()),
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
    limits: crate::SourceLimits,
    http: &crate::http::HttpClientConfig,
    allow_credential_forward: bool,
) -> Result<Vec<Result<Chunk, SourceError>>, SourceError> {
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
    // creds to custom endpoints. The operator opts in only through an
    // explicit caller-supplied flag after verifying the endpoint and accepting
    // the credential-leak exposure.
    let endpoint_is_aws_host = match endpoint {
        Some(value) => endpoint_is_aws(value),
        None => true,
    };
    let aws_auth = if endpoint_is_aws_host {
        AwsSigV4Config::from_env(&base_url)
    } else if credential_forward_allowed(allow_credential_forward) {
        tracing::warn!(
            endpoint = %endpoint.unwrap_or(""),  // LAW10: missing/non-string field => empty/placeholder; recall-safe
            "explicit S3 credential-forwarding override active: forwarding \
             ambient AWS credentials to non-AWS endpoint. Verify you trust this host."
        );
        AwsSigV4Config::from_env(&base_url)
    } else {
        if std::env::var("AWS_ACCESS_KEY_ID").is_ok() {
            tracing::warn!(
                endpoint = %endpoint.unwrap_or(""),  // LAW10: missing/non-string field => empty/placeholder; recall-safe
                "AWS credentials present but endpoint is non-AWS; refusing to \
                 forward. Pass the explicit S3 credential-forwarding flag only \
                 for endpoints you trust."
            );
        }
        None
    };
    let mut continuation_token = None::<String>;
    let mut chunks = Vec::new();
    let mut listed_objects = 0usize;
    let mut source_truncated_reported = false;
    use rayon::prelude::*;
    let fetch_pool = crate::cloud::object_fetch_pool("s3")?;

    loop {
        if listed_objects >= max_objects {
            if let Some(error) = crate::cloud::record_source_truncated_once(
                "s3",
                "max_objects limit reached before listing all objects",
                &mut source_truncated_reported,
            ) {
                chunks.push(Err(error));
            }
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

        // Concurrent object fetcher. S3 is designed for massive concurrent
        // GETs; the previous sequential loop wasted 90%+ of wall-clock on
        // large buckets. We use rayon (the workspace's parallelism primitive)
        // bounded to 16 in-flight downloads - high enough to saturate
        // reasonable bandwidth, low enough to avoid hammering small buckets.
        let page_chunks: Vec<Result<Option<Chunk>, SourceError>> = fetch_pool.install(|| {
            page.par_iter()
                .map(|object| -> Result<Option<Chunk>, SourceError> {
                    if object.size == 0 {
                        return Ok(None);
                    }
                    if !crate::cloud::is_probably_text_object_key(&object.key) {
                        tracing::warn!(
                            bucket = %bucket,
                            key = %object.key,
                            "skipping S3 object: extension is treated as binary/container content; NOT scanned as text",
                        );
                        let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
                        return Ok(None);
                    }
                    fetch_object_chunk(
                        &client,
                        &base_url,
                        &bucket,
                        &object.key,
                        object.size,
                        aws_auth.as_ref(),
                        limits.s3_object_bytes,
                    )
                })
                .collect()
        });
        for result in page_chunks {
            match result {
                Ok(Some(chunk)) => chunks.push(Ok(chunk)),
                Ok(None) => {}
                Err(error) => chunks.push(Err(error)),
            }
        }

        if reached_limit || !listing.is_truncated {
            if reached_limit {
                if let Some(error) = crate::cloud::record_source_truncated_once(
                    "s3",
                    "max_objects limit reached within the current S3 listing page",
                    &mut source_truncated_reported,
                ) {
                    chunks.push(Err(error));
                }
            }
            break;
        }
        continuation_token = listing.next_continuation_token;
        if continuation_token.is_none() {
            if let Some(error) = crate::cloud::record_source_truncated_once(
                "s3",
                "S3 listing response was truncated but omitted NextContinuationToken",
                &mut source_truncated_reported,
            ) {
                chunks.push(Err(error));
            }
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
    max_object_bytes: u64,
) -> Result<Option<Chunk>, SourceError> {
    if object_size > max_object_bytes {
        // Law 10: an over-cap object is dropped from the scan — an UNKNOWN, not a
        // clean object. The old `tracing::debug!` was invisible at default
        // verbosity, so a secret in an oversized object vanished with no trace.
        // Surface loudly + count it (as over-max-size, the matching category the
        // CLI already reports) so end-of-scan coverage reflects the drop.
        tracing::warn!(
            bucket,
            key,
            object_size,
            cap = max_object_bytes,
            "skipping S3 object: listed size exceeds the per-object byte cap; NOT scanned",
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        return Ok(None);
    }

    let encoded_key = crate::cloud::encode_object_key_path(key);
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
        let status = response.status();
        tracing::warn!(
            bucket,
            key,
            %status,
            "skipping S3 object: GET returned non-success status; NOT scanned",
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        return Err(SourceError::Other(format!(
            "failed to scan S3 object s3://{bucket}/{key}: GET returned {status}; object was not scanned"
        )));
    }

    if let Some(content_length) = response.content_length() {
        if content_length > max_object_bytes {
            // Law 10: the object's real (Content-Length) size exceeds the cap, so
            // it is dropped — an UNKNOWN. Surface loudly + count (over-max-size)
            // exactly like the listed-size guard above so the drop is auditable.
            tracing::warn!(
                bucket,
                key,
                content_length,
                cap = max_object_bytes,
                "skipping S3 object: Content-Length exceeds the per-object byte cap; NOT scanned",
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            return Ok(None);
        }
    }

    // Skip objects that declare a binary content type - they won't contain text secrets.
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| match v.to_str() {
            Ok(value) => Some(value),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "S3 object content-type header is not valid text; scanning body as unknown content type"
                );
                None
            }
        });
    if let Some(ct) = content_type {
        if crate::cloud::is_binary_content_type(ct) {
            // Law 10: a binary content-type skip is a deliberate non-text drop —
            // the SAME category as the filesystem walker's binary-extension skip.
            // Route it to the SKIPPED_BINARY counter (already CLI-surfaced) so it
            // is visible, not a silent `tracing::debug!` return.
            tracing::warn!(
                bucket,
                key,
                content_type = %ct,
                "skipping S3 object: binary content-type; NOT scanned as text",
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
            return Ok(None);
        }
    }

    // Read the response body with a hard size cap. The blocking client
    // lacks byte-stream support, so we use `copy()` into a size-limited
    // buffer to abort before the full response is buffered into memory.
    let mut body = Vec::new();
    let mut reader = response.take(max_object_bytes + 1);
    std::io::Read::read_to_end(&mut reader, &mut body)
        .map_err(|e| SourceError::Other(format!("failed to read S3 object body: {key}: {e}")))?;
    if body.len() as u64 > max_object_bytes {
        // Law 10: the server streamed more than it declared (lying/absent
        // Content-Length) and we hit the `.take(cap + 1)` ceiling — the body is
        // truncated/over-cap and dropped. An UNKNOWN, not a clean object. Surface
        // loudly + count (over-max-size) so the drop is auditable.
        tracing::warn!(
            bucket,
            key,
            downloaded = body.len(),
            cap = max_object_bytes,
            "skipping S3 object: streamed body exceeds the per-object byte cap \
             (Content-Length was absent or understated); NOT scanned",
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
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
            // Law 10: a body the server labelled text but that fails UTF-8 is an
            // UNKNOWN dropped from the scan (server lied about Content-Type, gzip
            // body claiming text/plain, EBCDIC export, ...). The `tracing::warn!`
            // alone left it out of the end-of-scan coverage numbers — count it as
            // unreadable so "0 findings" on a bucket the user knows has text is
            // not mistaken for full coverage.
            let valid_up_to = error.utf8_error().valid_up_to();
            tracing::warn!(
                bucket,
                key,
                valid_up_to,
                "skipping S3 object: body claimed text content-type but failed UTF-8 decode; NOT scanned"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return Err(SourceError::Other(format!(
                "failed to scan S3 object s3://{bucket}/{key}: body failed UTF-8 decode at byte {valid_up_to}; object was not scanned"
            )));
        }
    };

    Ok(Some(Chunk {
        data: object_text.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "s3".into(),
            path: Some(format!("{bucket}/{key}")),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: None,
            decoded_span: None,
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
pub(crate) fn endpoint_is_aws(endpoint: &str) -> bool {
    let parsed = match reqwest::Url::parse(endpoint) {
        Ok(u) => u,
        Err(_) => return false, // LAW10: failure => fail-closed error (blocked/refused), never proceeds; security guard
    };
    let host = match parsed.host_str() {
        Some(h) => h.to_ascii_lowercase(),
        None => return false,
    };
    host == "amazonaws.com"
        || host.ends_with(".amazonaws.com")
        || host.ends_with(".amazonaws.com.cn")
}

/// True iff the caller explicitly opted into forwarding ambient AWS
/// credentials to non-AWS endpoints. This must stay parameter-driven: a keyhog
/// env var cannot weaken this policy.
pub(crate) fn credential_forward_allowed(allow_explicit: bool) -> bool {
    allow_explicit
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
