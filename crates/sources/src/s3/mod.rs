//! S3 bucket source: lists text-like objects with ListObjectsV2 and downloads
//! each candidate object for scanning. Large or non-text objects are skipped.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use reqwest::blocking::Client;

mod auth;
mod listing;

use auth::AwsSigV4Config;
use listing::{parse_s3_listing, ListBucketResult};

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
#[derive(Clone)]
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
        crate::cloud::set_optional(&mut self.prefix, prefix.into());
        self
    }

    /// Override the S3 endpoint, for example for MinIO or other S3-compatible APIs.
    pub(crate) fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Limit the number of objects listed from the bucket before stopping.
    pub(crate) fn with_max_objects(mut self, max_objects: usize) -> Self {
        crate::cloud::set_optional(&mut self.max_objects, max_objects);
        self
    }
}

impl Source for S3Source {
    fn name(&self) -> &str {
        "s3"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        let lease = crate::acquire_scan_read_lease();
        let source = self.clone();
        let worker_lease = lease.clone();
        let profile_runtime = crate::profile::current_runtime();
        let stream = crate::parallel_fetch::RemoteChunkStream::spawn(
            "keyhog-s3",
            "s3",
            worker_lease,
            move |sender, worker_lease| {
                let _attributed = worker_lease.enter();
                let _profile_guard = profile_runtime.as_ref().map(|runtime| runtime.enter());
                let result = stream_s3_chunks(
                    &source.bucket,
                    source.prefix.as_deref(),
                    source.endpoint.as_deref(),
                    source
                        .max_objects
                        .unwrap_or(source.limits.cloud_max_objects), // LAW10: absent per-source object cap uses the configured global cloud limit; enumeration remains bounded.
                    source.limits,
                    &source.http,
                    source.allow_credential_forward,
                    &worker_lease,
                    |row| sender.send(row).is_ok(),
                );
                if let Err(error) = result {
                    let _ = sender.send(Err(error)); // LAW10: a failed send means the stream consumer is already closed; no recipient remains for this source error.
                }
            },
        );
        match stream {
            Ok(stream) => crate::attach_scan_lease(lease, Box::new(stream)),
            Err(error) => crate::attach_scan_lease(lease, Box::new(std::iter::once(Err(error)))),
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn stream_s3_chunks(
    bucket: &str,
    prefix: Option<&str>,
    endpoint: Option<&str>,
    max_objects: usize,
    limits: crate::SourceLimits,
    http: &crate::http::HttpClientConfig,
    allow_credential_forward: bool,
    scan_lease: &crate::skip::ScanReadLease,
    mut emit: impl FnMut(Result<Chunk, SourceError>) -> bool,
) -> Result<(), SourceError> {
    let bucket = validate_bucket_name(bucket)?;
    let _acquire = crate::profile::acquire_span();
    let (base_url, screened) = build_base_url(&bucket, endpoint, http.allow_private_endpoint)?;
    let client = crate::cloud::blocking_client("S3", http, screened.as_ref())?;
    let aws_auth = resolve_s3_auth(&base_url, endpoint, allow_credential_forward)?;
    drop(_acquire);
    let mut coverage = crate::cloud::CloudListingCoverage::new("s3", "objects", max_objects);
    let mut control_rows = Vec::new();
    let mut listing = {
        let _page = crate::profile::walk_span();
        fetch_s3_listing_page(
            &client,
            &base_url,
            prefix,
            None,
            aws_auth.as_ref(),
            limits.web_response_bytes,
        )?
    };

    loop {
        if !coverage.has_capacity_or_record(&mut control_rows) {
            emit_s3_control_rows(&mut control_rows, &mut emit);
            break;
        }

        let (page, reached_limit) = coverage.take_page(listing.contents);
        let next_token = if reached_limit || !listing.is_truncated {
            None
        } else {
            crate::cloud::meaningful_continuation_token(listing.next_continuation_token.as_deref())
                .map(str::to_string)
        };
        let empty_cursor = listing.is_truncated && !reached_limit && next_token.is_none();
        let prefetch = match next_token {
            Some(token) if coverage.has_listed_capacity() => {
                let client = client.clone();
                let base_url = base_url.clone();
                let prefix = prefix.map(str::to_string);
                let aws_auth = aws_auth.clone();
                let max_response_bytes = limits.web_response_bytes;
                crate::cloud::ListingPrefetch::spawn(move || {
                    fetch_s3_listing_page(
                        &client,
                        &base_url,
                        prefix.as_deref(),
                        Some(&token),
                        aws_auth.as_ref(),
                        max_response_bytes,
                    )
                })
            }
            _ => crate::cloud::ListingPrefetch::none(),
        };

        let accepted = {
            let _download = crate::profile::read_span();
            crate::parallel_fetch::stream_ordered_fetch(
                &page,
                crate::cloud::OBJECT_FETCH_THREADS,
                scan_lease,
                |object| {
                    match object.size {
                        Some(0) => return Ok(None),
                        Some(_) | None => {}
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
                        &client,
                        &base_url,
                        &bucket,
                        &object.key,
                        object.size,
                        aws_auth.as_ref(),
                        limits.s3_object_bytes,
                    )
                },
                |result| match result {
                    Ok(Some(chunk)) => {
                        crate::profile::add_input_units(1);
                        crate::profile::add_input_bytes(chunk.data.len() as u64);
                        emit(Ok(chunk))
                    }
                    Ok(None) => true,
                    Err(error) => emit(Err(error)),
                },
            )
        };
        if !accepted {
            let _ = prefetch.join(); // LAW10: callback rejection means the downstream consumer closed; joining only reclaims the abandoned prefetch worker.
            return Ok(());
        }

        if reached_limit {
            coverage.record_truncated(
                &mut control_rows,
                "max_objects limit reached within the current S3 listing page",
            );
            emit_s3_control_rows(&mut control_rows, &mut emit);
            break;
        }
        if !listing.is_truncated {
            break;
        }
        if empty_cursor {
            coverage.record_truncated(
                &mut control_rows,
                "S3 listing response was truncated but omitted or emptied NextContinuationToken",
            );
            emit_s3_control_rows(&mut control_rows, &mut emit);
            break;
        }
        match prefetch.join() {
            Some(next_listing) => listing = next_listing?,
            None => {
                coverage.has_capacity_or_record(&mut control_rows);
                emit_s3_control_rows(&mut control_rows, &mut emit);
                break;
            }
        }
    }

    Ok(())
}

fn emit_s3_control_rows(
    rows: &mut Vec<Result<Chunk, SourceError>>,
    emit: &mut impl FnMut(Result<Chunk, SourceError>) -> bool,
) -> bool {
    for row in rows.drain(..) {
        if !emit(row) {
            return false;
        }
    }
    true
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

fn fetch_object_chunk(
    client: &Client,
    base_url: &str,
    bucket: &str,
    key: &str,
    listed_size: Option<u64>,
    aws_auth: Option<&AwsSigV4Config>,
    max_object_bytes: u64,
) -> Result<Option<Chunk>, SourceError> {
    if let Some(object_size) = listed_size {
        if object_size > max_object_bytes {
            // Law 10: an over-cap object is dropped from the scan, an UNKNOWN, not a
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
                format!(
                    "listed size {object_size} exceeds the per-object byte cap {max_object_bytes}"
                ),
            ));
        }
    }

    let encoded_key = crate::cloud::encode_object_key_path(key);
    let url = format!("{}/{}", base_url.trim_end_matches('/'), encoded_key);
    let display_path = format!("s3://{bucket}/{key}");
    // KH-1413: when ListObjects omitted Size, request at most the cap via
    // Range so the network path cannot stream a multi-GB object before the
    // client-side capped reader stops.
    let mut request = client.get(&url);
    if listed_size.is_none() && max_object_bytes > 0 {
        let end = max_object_bytes.saturating_sub(1);
        request = request.header("Range", format!("bytes=0-{end}"));
    }
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
            source_type: keyhog_core::intern_source_type("s3"),
            path: Some(format!("{bucket}/{key}").into()),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            ctime_ns: None,
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
    // LAW10: shared helper fails closed (non-AWS) on a malformed/host-less
    // endpoint, so ambient AWS creds are never auto-forwarded to it.
    crate::cloud::endpoint_host_matches_domain(endpoint, "amazonaws.com")
        || crate::cloud::endpoint_host_matches_domain(endpoint, "amazonaws.com.cn")
}

fn build_base_url(
    bucket: &str,
    endpoint: Option<&str>,
    allow_private: bool,
) -> Result<(String, Option<crate::endpoint_screen::ScreenedEndpoint>), SourceError> {
    match endpoint {
        Some(endpoint) => {
            let (endpoint, screened) =
                crate::cloud::validate_cloud_endpoint(endpoint, "S3", allow_private, false)?;
            Ok((
                format!(
                    "{}/{}",
                    endpoint.trim_end_matches('/'),
                    urlencoding::encode(bucket)
                ),
                screened,
            ))
        }
        // The provider's own default host is not operator-supplied, so there is
        // no custom endpoint to screen and nothing to pin.
        None => Ok((
            format!("https://{bucket}.{}", crate::cloud::DEFAULT_S3_HOST_SUFFIX),
            None,
        )),
    }
}

/// S3 bucket-name length bounds (AWS bucket naming rules): 3–63 characters.
/// https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
const S3_BUCKET_NAME_MIN_LEN: usize = 3;
const S3_BUCKET_NAME_MAX_LEN: usize = 63;

fn validate_bucket_name(bucket: &str) -> Result<String, SourceError> {
    let bucket = bucket.trim();
    if bucket.len() < S3_BUCKET_NAME_MIN_LEN || bucket.len() > S3_BUCKET_NAME_MAX_LEN {
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

#[cfg(test)]
mod builder_setter_tests {
    use super::S3Source;

    #[test]
    fn with_prefix_and_max_objects_route_through_shared_set_optional() {
        // Defaults start unset.
        let source = S3Source::new("bucket-name");
        assert_eq!(source.prefix, None);
        assert_eq!(source.max_objects, None);

        // Shared setter wraps the value in `Some`.
        let source = source.with_prefix("archive/").with_max_objects(3);
        assert_eq!(source.prefix.as_deref(), Some("archive/"));
        assert_eq!(source.max_objects, Some(3));

        // Overwrites the prior `Some`, it does not merge or ignore the update.
        let source = source.with_prefix("current/").with_max_objects(128);
        assert_eq!(source.prefix.as_deref(), Some("current/"));
        assert_eq!(source.max_objects, Some(128));
    }
}
