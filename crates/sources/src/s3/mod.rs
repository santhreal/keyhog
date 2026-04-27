//! S3 bucket source: lists text-like objects with ListObjectsV2 and downloads
//! each candidate object for scanning. Large or non-text objects are skipped.

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use reqwest::blocking::Client;

mod auth;
mod listing;

use auth::AwsSigV4Config;
use listing::{encode_s3_key_path, parse_s3_listing};

const DEFAULT_S3_HOST_SUFFIX: &str = "s3.amazonaws.com";
const S3_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
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
        }
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
) -> Result<Vec<Chunk>, SourceError> {
    let bucket = validate_bucket_name(bucket)?;
    let client = Client::builder()
        .timeout(S3_REQUEST_TIMEOUT)
        .build()
        .map_err(|e| SourceError::Other(format!("failed to build S3 client: {e}")))?;
    let base_url = build_base_url(&bucket, endpoint)?;
    let aws_auth = AwsSigV4Config::from_env(&base_url);
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
        // bounded to 16 in-flight downloads — high enough to saturate
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

    // Skip objects that declare a binary content type — they won't contain text secrets.
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
    let object_text = match String::from_utf8(body) {
        Ok(text) => text,
        Err(_) => return Ok(None),
    };

    Ok(Some(Chunk {
        data: object_text,
        metadata: ChunkMetadata {
            source_type: "s3".into(),
            path: Some(format!("{bucket}/{key}")),
            commit: None,
            author: None,
            date: None,
        },
    }))
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
