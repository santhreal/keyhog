//! S3 bucket source: lists text-like objects with ListObjectsV2 and downloads
//! each candidate object for scanning. Large or non-text objects are skipped.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use reqwest::blocking::Client;

mod auth;
mod listing;

use auth::AwsSigV4Config;
use listing::{parse_s3_listing, ListBucketResult, ListObject};

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
    max_objects: Option<usize>,
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
            max_objects: None,
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
        self.max_objects = Some(max_objects);
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
        let result = crate::cloud::collect_on_blocking_thread("s3", || {
            collect_s3_chunks(
                &self.bucket,
                self.prefix.as_deref(),
                self.endpoint.as_deref(),
                match self.max_objects {
                    Some(max_objects) => max_objects,
                    None => self.limits.cloud_max_objects, // LAW10: no explicit per-source object-count override => use resolved Tier-A SourceLimits default
                },
                self.limits,
                &self.http,
                self.allow_credential_forward,
            )
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
    let client = crate::cloud::blocking_client("S3", http)?;
    let base_url = build_base_url(&bucket, endpoint)?;
    let aws_auth = resolve_s3_auth(&base_url, endpoint, allow_credential_forward)?;
    let mut continuation_token = None::<String>;
    let mut chunks = Vec::new();
    let mut coverage = crate::cloud::CloudListingCoverage::new("s3", "objects", max_objects);
    let fetch_pool = crate::cloud::object_fetch_pool("s3")?;

    loop {
        if !coverage.has_capacity_or_record(&mut chunks) {
            break;
        }

        let listing = fetch_s3_listing_page(
            &client,
            &base_url,
            prefix,
            continuation_token.as_deref(),
            aws_auth.as_ref(),
            limits.web_response_bytes,
        )?;
        let (page, reached_limit) = coverage.take_page(listing.contents);

        let page_chunks = download_s3_listing_page(
            &fetch_pool,
            &page,
            &client,
            &base_url,
            &bucket,
            aws_auth.as_ref(),
            limits.s3_object_bytes,
        );
        crate::cloud::push_page_chunks(&mut chunks, page_chunks);

        if reached_limit || !listing.is_truncated {
            if reached_limit {
                coverage.record_truncated(
                    &mut chunks,
                    "max_objects limit reached within the current S3 listing page",
                );
            }
            break;
        }
        continuation_token = listing.next_continuation_token;
        if continuation_token.is_none() {
            coverage.record_truncated(
                &mut chunks,
                "S3 listing response was truncated but omitted NextContinuationToken",
            );
            break;
        }
    }

    Ok(chunks)
}

fn resolve_s3_auth(
    base_url: &str,
    endpoint: Option<&str>,
    allow_credential_forward: bool,
) -> Result<Option<AwsSigV4Config>, SourceError> {
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
    if endpoint_is_aws_host {
        return AwsSigV4Config::from_env(base_url);
    }
    if crate::cloud::credential_forward_allowed(allow_credential_forward) {
        tracing::warn!(
            endpoint = %endpoint.unwrap_or(""),  // LAW10: missing/non-string field => empty/placeholder; recall-safe
            "explicit S3 credential-forwarding override active: forwarding \
             ambient AWS credentials to non-AWS endpoint. Verify you trust this host."
        );
        return AwsSigV4Config::from_env(base_url);
    }
    if ambient_s3_credentials_present() {
        let endpoint_display = match endpoint {
            Some(endpoint) => endpoint,
            None => "<default AWS endpoint>",
        };
        return Err(SourceError::Other(format!(
            "AWS credentials are present but endpoint {} is non-AWS; refusing to run anonymously after dropping credentials. Pass the explicit S3 credential-forwarding flag only for endpoints you trust, or unset AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY for anonymous S3-compatible scans.",
            endpoint_display
        )));
    }
    Ok(None)
}

fn ambient_s3_credentials_present() -> bool {
    [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some())
}

fn fetch_s3_listing_page(
    client: &Client,
    base_url: &str,
    prefix: Option<&str>,
    continuation_token: Option<&str>,
    aws_auth: Option<&AwsSigV4Config>,
    max_response_bytes: usize,
) -> Result<ListBucketResult, SourceError> {
    let mut request = client.get(base_url).query(&[("list-type", "2")]);
    if let Some(prefix) = prefix {
        request = request.query(&[("prefix", prefix)]);
    }
    if let Some(token) = continuation_token {
        request = request.query(&[("continuation-token", token)]);
    }
    if let Some(auth) = aws_auth {
        request = auth.sign(request, base_url)?;
    }

    let response = request.send().map_err(|error| {
        crate::cloud::record_unreadable_listing_skip(
            "S3",
            "objects",
            format!("failed to list objects: {error}"),
        )
    })?;

    if !response.status().is_success() {
        let status = response.status();
        return Err(crate::cloud::record_unreadable_listing_skip(
            "S3",
            "objects",
            format!("bucket request returned {status}"),
        ));
    }

    let body =
        crate::cloud::read_listing_response_body(response, "S3", "objects", max_response_bytes)?;
    parse_s3_listing(&body).map_err(|error| {
        crate::cloud::record_unreadable_listing_skip(
            "S3",
            "objects",
            format!("failed to parse listing response: {error}"),
        )
    })
}

fn download_s3_listing_page(
    fetch_pool: &rayon::ThreadPool,
    page: &[ListObject],
    client: &Client,
    base_url: &str,
    bucket: &str,
    aws_auth: Option<&AwsSigV4Config>,
    max_object_bytes: u64,
) -> Vec<Result<Option<Chunk>, SourceError>> {
    use rayon::prelude::*;

    // Concurrent object fetcher. S3 is designed for massive concurrent GETs.
    fetch_pool.install(|| {
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
                    return Err(crate::cloud::record_unscanned_object_skip(
                        crate::SourceSkipEvent::Binary,
                        "S3 object",
                        "object",
                        &format!("s3://{bucket}/{}", object.key),
                        "extension is treated as binary/container content",
                    ));
                }
                fetch_object_chunk(
                    client,
                    base_url,
                    bucket,
                    &object.key,
                    object.size,
                    aws_auth,
                    max_object_bytes,
                )
            })
            .collect()
    })
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
        return Err(crate::cloud::record_unscanned_object_skip(
            crate::SourceSkipEvent::OverMaxSize,
            "S3 object",
            "object",
            &format!("s3://{bucket}/{key}"),
            format!("listed size {object_size} exceeds the per-object byte cap {max_object_bytes}"),
        ));
    }

    let encoded_key = crate::cloud::encode_object_key_path(key);
    let url = format!("{}/{}", base_url.trim_end_matches('/'), encoded_key);
    let display_path = format!("s3://{bucket}/{key}");
    let request = client.get(&url);
    let request = if let Some(auth) = aws_auth {
        auth.sign(request, &url)?
    } else {
        request
    };
    let response = request.send().map_err(|error| {
        crate::cloud::record_unreadable_object_skip(
            "S3 object",
            "object",
            &display_path,
            format!("download failed for {key}: {error}"),
        )
    })?;
    let Some(object_text) = crate::cloud::read_text_object_body(
        response,
        crate::cloud::TextObjectBodyContext {
            source: "S3 object",
            item_kind: "object",
            item_name: key,
            display_path,
            max_bytes: max_object_bytes,
        },
    )?
    else {
        return Ok(None);
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
        Some(h) => h,
        None => return false,
    };
    crate::cloud::host_matches_domain_ascii_ci(host, "amazonaws.com")
        || crate::cloud::host_matches_domain_ascii_ci(host, "amazonaws.com.cn")
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
        None => Ok(format!(
            "https://{bucket}.{}",
            crate::cloud::DEFAULT_S3_HOST_SUFFIX
        )),
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
    let parsed = crate::cloud::parse_http_endpoint(endpoint, "S3")?;
    if parsed.query().is_some() {
        return Err(SourceError::Other("invalid S3 endpoint".into()));
    }

    Ok(parsed.to_string().trim_end_matches('/').to_string())
}
