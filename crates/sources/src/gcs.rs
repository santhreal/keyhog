//! Google Cloud Storage bucket source: lists objects with the JSON API and
//! downloads text-like object bodies for scanning.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use reqwest::blocking::Client;
use serde::Deserialize;

#[derive(Clone)]
pub struct GcsSource {
    bucket: String,
    prefix: Option<String>,
    endpoint: String,
    max_objects: Option<usize>,
    limits: crate::SourceLimits,
    http: crate::http::HttpClientConfig,
    allow_token_forward: bool,
}

impl GcsSource {
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            prefix: None,
            endpoint: crate::cloud::DEFAULT_GCS_ENDPOINT.to_string(),
            max_objects: None,
            limits: crate::SourceLimits::default(),
            http: crate::http::HttpClientConfig {
                ua_suffix: Some("gcs".into()),
                ..Default::default()
            },
            allow_token_forward: false,
        }
    }

    pub(crate) fn with_http_config(mut self, http: crate::http::HttpClientConfig) -> Self {
        self.http = http;
        self
    }

    /// Allow forwarding ambient GCS bearer tokens to a non-Google custom
    /// endpoint. This is intentionally caller-explicit; no keyhog env var can
    /// weaken the credential-forwarding policy.
    pub(crate) fn with_allow_token_forward(mut self, allow: bool) -> Self {
        self.allow_token_forward = allow;
        self
    }

    pub(crate) fn with_limits(mut self, limits: crate::SourceLimits) -> Self {
        self.limits = limits;
        self
    }

    pub(crate) fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        crate::cloud::set_optional(&mut self.prefix, prefix.into());
        self
    }

    pub(crate) fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    pub(crate) fn with_max_objects(mut self, max_objects: usize) -> Self {
        crate::cloud::set_optional(&mut self.max_objects, max_objects);
        self
    }
}

impl Source for GcsSource {
    fn name(&self) -> &str {
        "gcs"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        let lease = crate::acquire_scan_read_lease();
        let source = self.clone();
        let worker_lease = lease.clone();
        let profile_runtime = crate::profile::current_runtime();
        let stream = crate::parallel_fetch::RemoteChunkStream::spawn(
            "keyhog-gcs",
            "gcs",
            worker_lease,
            move |sender, worker_lease| {
                let _attributed = worker_lease.enter();
                let _profile_guard = profile_runtime.as_ref().map(|runtime| runtime.enter());
                let result = stream_gcs_chunks(
                    &source.bucket,
                    source.prefix.as_deref(),
                    &source.endpoint,
                    source
                        .max_objects
                        .unwrap_or(source.limits.cloud_max_objects), // LAW10: absent per-source object cap uses the configured global cloud limit; enumeration remains bounded.
                    source.limits,
                    &source.http,
                    source.allow_token_forward,
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

#[derive(Debug, Deserialize)]
struct GcsListResponse {
    #[serde(default)]
    items: Vec<GcsObject>,
    #[serde(default, rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GcsObject {
    name: String,
    #[serde(default)]
    size: Option<String>,
}

impl GcsObject {
    fn size_bytes(&self) -> Result<Option<u64>, SourceError> {
        match self.size.as_deref() {
            Some(raw) => raw.parse::<u64>().map(Some).map_err(|error| {
                SourceError::Other(format!(
                    "failed to parse GCS object size for '{}': {error}",
                    self.name
                ))
            }),
            None => Ok(None),
        }
    }
}

fn stream_gcs_chunks(
    bucket: &str,
    prefix: Option<&str>,
    endpoint: &str,
    max_objects: usize,
    limits: crate::SourceLimits,
    http: &crate::http::HttpClientConfig,
    allow_token_forward: bool,
    scan_lease: &crate::skip::ScanReadLease,
    mut emit: impl FnMut(Result<Chunk, SourceError>) -> bool,
) -> Result<(), SourceError> {
    let bucket = validate_bucket_name(bucket)?;
    let _acquire = crate::profile::acquire_span();
    let (endpoint, screened) =
        crate::cloud::validate_cloud_endpoint(endpoint, "GCS", http.allow_private_endpoint, true)?;
    let client = crate::cloud::blocking_client("GCS", http, screened.as_ref())?;
    let bearer = resolve_gcs_auth(&endpoint, allow_token_forward)?;
    drop(_acquire);
    let mut coverage = crate::cloud::CloudListingCoverage::new("gcs", "objects", max_objects);
    let mut control_rows = Vec::new();
    let mut listing = {
        let _page = crate::profile::walk_span();
        fetch_gcs_listing_page(
            &client,
            &endpoint,
            &bucket,
            prefix,
            None,
            bearer.as_deref(),
            limits.web_response_bytes,
        )?
    };

    loop {
        if !coverage.has_capacity_or_record(&mut control_rows) {
            emit_gcs_control_rows(&mut control_rows, &mut emit);
            break;
        }

        let (page, reached_limit) = coverage.take_page(listing.items);
        let next_token = if reached_limit {
            None
        } else {
            crate::cloud::meaningful_continuation_token(listing.next_page_token.as_deref())
                .map(str::to_string)
        };
        let prefetch = match &next_token {
            Some(token) if coverage.has_listed_capacity() => {
                let client = client.clone();
                let endpoint = endpoint.clone();
                let bucket = bucket.clone();
                let prefix = prefix.map(str::to_string);
                let bearer = bearer.clone();
                let token = token.clone();
                let max_response_bytes = limits.web_response_bytes;
                crate::cloud::ListingPrefetch::spawn(move || {
                    fetch_gcs_listing_page(
                        &client,
                        &endpoint,
                        &bucket,
                        prefix.as_deref(),
                        Some(&token),
                        bearer.as_deref(),
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
                    let listed_size = object.size_bytes()?;
                    if listed_size == Some(0) {
                        return Ok(None);
                    }
                    if !crate::cloud::is_probably_text_object_key(&object.name) {
                        tracing::warn!(
                            bucket = %bucket,
                            key = %object.name,
                            "skipping GCS object: extension is treated as binary/container content; NOT scanned as text",
                        );
                        return Err(crate::cloud::record_unscanned_object_skip(
                            crate::SourceSkipEvent::Binary,
                            "GCS object",
                            "object",
                            &format!("gs://{bucket}/{}", object.name),
                            "extension is treated as binary/container content",
                        ));
                    }
                    fetch_gcs_object_chunk(
                        &client,
                        &endpoint,
                        &bucket,
                        &object.name,
                        listed_size,
                        bearer.as_deref(),
                        limits.gcs_object_bytes,
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
                "max_objects limit reached within the current GCS listing page",
            );
            emit_gcs_control_rows(&mut control_rows, &mut emit);
            break;
        }
        if next_token.is_none() {
            break;
        }
        match prefetch.join() {
            Some(next_listing) => listing = next_listing?,
            None => {
                coverage.has_capacity_or_record(&mut control_rows);
                emit_gcs_control_rows(&mut control_rows, &mut emit);
                break;
            }
        }
    }

    Ok(())
}

fn emit_gcs_control_rows(
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

fn resolve_gcs_auth(
    endpoint: &str,
    allow_token_forward: bool,
) -> Result<Option<String>, SourceError> {
    gcs_bearer_token(endpoint, allow_token_forward)
}

fn fetch_gcs_listing_page(
    client: &Client,
    endpoint: &str,
    bucket: &str,
    prefix: Option<&str>,
    page_token: Option<&str>,
    bearer: Option<&str>,
    max_response_bytes: usize,
) -> Result<GcsListResponse, SourceError> {
    let list_url = gcs_list_url(endpoint, bucket);
    let mut request = client
        .get(&list_url)
        .query(&[("alt", "json"), ("maxResults", "1000")]);
    if let Some(prefix) = prefix {
        request = request.query(&[("prefix", prefix)]);
    }
    if let Some(token) = page_token {
        request = request.query(&[("pageToken", token)]);
    }
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }

    let response = request.send().map_err(|error| {
        crate::cloud::record_unreadable_listing_skip(
            "GCS",
            "objects",
            format!("failed to list objects: {error}"),
        )
    })?;
    if !response.status().is_success() {
        let status = response.status();
        return Err(crate::cloud::record_unreadable_listing_skip(
            "GCS",
            "objects",
            format!("bucket request returned {status}"),
        ));
    }
    let body =
        crate::cloud::read_listing_response_body(response, "GCS", "objects", max_response_bytes)?;
    parse_gcs_listing(&body).map_err(|error| {
        crate::cloud::record_unreadable_listing_skip(
            "GCS",
            "objects",
            format!("failed to parse listing response: {error}"),
        )
    })
}

fn fetch_gcs_object_chunk(
    client: &Client,
    endpoint: &str,
    bucket: &str,
    name: &str,
    listed_size: Option<u64>,
    bearer: Option<&str>,
    max_object_bytes: u64,
) -> Result<Option<Chunk>, SourceError> {
    if let Some(size) = listed_size {
        if size > max_object_bytes {
            tracing::warn!(
                bucket,
                key = name,
                object_size = size,
                cap = max_object_bytes,
                "skipping GCS object: listed size exceeds the per-object byte cap; NOT scanned",
            );
            return Err(crate::cloud::record_unscanned_object_skip(
                crate::SourceSkipEvent::OverMaxSize,
                "GCS object",
                "object",
                &format!("gs://{bucket}/{name}"),
                format!("listed size {size} exceeds the per-object byte cap {max_object_bytes}"),
            ));
        }
    }

    let url = gcs_media_url(endpoint, bucket, name);
    let mut request = client.get(&url);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    let display_path = format!("gs://{bucket}/{name}");
    let response = request.send().map_err(|error| {
        crate::cloud::record_unreadable_object_skip(
            "GCS object",
            "object",
            &display_path,
            format!("download failed for {name}: {error}"),
        )
    })?;
    let Some(object_text) = crate::cloud::read_text_object_body(
        response,
        crate::cloud::TextObjectBodyContext {
            source: "GCS object",
            item_kind: "object",
            item_name: name,
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
            source_type: keyhog_core::intern_source_type("gcs"),
            path: Some(format!("gs://{bucket}/{name}").into()),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: listed_size,
            decoded_span: None,
        },
    }))
}

fn parse_gcs_listing(body: &str) -> Result<GcsListResponse, SourceError> {
    serde_json::from_str(body).map_err(|error| {
        SourceError::Other(format!("failed to parse GCS object listing JSON: {error}"))
    })
}

fn gcs_list_url(endpoint: &str, bucket: &str) -> String {
    format!(
        "{}/storage/v1/b/{}/o",
        endpoint.trim_end_matches('/'),
        urlencoding::encode(bucket)
    )
}

fn gcs_media_url(endpoint: &str, bucket: &str, name: &str) -> String {
    format!(
        "{}/storage/v1/b/{}/o/{}?alt=media",
        endpoint.trim_end_matches('/'),
        urlencoding::encode(bucket),
        crate::cloud::encode_object_key_path(name)
    )
}

/// GCS bucket-name length bounds (Google Cloud Storage naming rules): 3–222
/// characters. https://cloud.google.com/storage/docs/buckets#naming
const GCS_BUCKET_NAME_MIN_LEN: usize = 3;
const GCS_BUCKET_NAME_MAX_LEN: usize = 222;

fn validate_bucket_name(bucket: &str) -> Result<String, SourceError> {
    let bucket = bucket.trim();
    if bucket.len() < GCS_BUCKET_NAME_MIN_LEN || bucket.len() > GCS_BUCKET_NAME_MAX_LEN {
        return Err(SourceError::Other("invalid GCS bucket name length".into()));
    }
    if bucket.contains("..") || bucket.contains('/') || bucket.chars().any(char::is_control) {
        return Err(SourceError::Other(format!("invalid GCS bucket '{bucket}'")));
    }
    if !bucket
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '-' | '_'))
    {
        return Err(SourceError::Other(format!("invalid GCS bucket '{bucket}'")));
    }
    let starts_ok = bucket
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit());
    let ends_ok = bucket
        .chars()
        .last()
        .is_some_and(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit());
    if !starts_ok || !ends_ok {
        return Err(SourceError::Other(format!("invalid GCS bucket '{bucket}'")));
    }
    Ok(bucket.to_string())
}

pub(crate) fn endpoint_is_google(endpoint: &str) -> bool {
    // LAW10: shared helper fails closed (non-Google) on a malformed/host-less
    // endpoint, so credential forwarding stays disabled.
    crate::cloud::endpoint_host_matches_domain(endpoint, "googleapis.com")
}

fn gcs_bearer_token(
    endpoint: &str,
    allow_token_forward: bool,
) -> Result<Option<String>, SourceError> {
    let Some((env_name, token)) = (match read_gcs_bearer_env("GOOGLE_OAUTH_ACCESS_TOKEN")? {
        Some(token) => Some(("GOOGLE_OAUTH_ACCESS_TOKEN", token)),
        None => read_gcs_bearer_env("GCS_BEARER_TOKEN")?.map(|token| ("GCS_BEARER_TOKEN", token)),
    }) else {
        return Ok(None);
    };
    if token.trim().is_empty() {
        return Err(SourceError::Other(format!(
            "{env_name} is set but empty; unset it for anonymous GCS access or provide a non-empty bearer token"
        )));
    }
    if token.chars().any(char::is_control) {
        return Err(SourceError::Other(format!(
            "{env_name} contains control characters; provide a single-line bearer token"
        )));
    }
    if endpoint_is_google(endpoint) {
        return Ok(Some(token));
    }
    if crate::cloud::credential_forward_allowed(allow_token_forward) {
        // Warn where the forwarding actually happens, not where the flag was
        // parsed. This is the single owner of the consent notice, so every entry
        // path into the GCS source (`--gcs-bucket ... --allow-gcs-token-forward`
        // and `--source gcs:BUCKET\nPREFIX\nENDPOINT\ntrue`) surfaces it
        // identically, and it fires only when an ambient token is genuinely
        // carried off-provider rather than whenever the flag is present.
        // Mirrors `s3::resolve_s3_auth`.
        tracing::warn!(
            endpoint = %endpoint,
            env = env_name,
            "explicit GCS token-forwarding override active: forwarding ambient GCS bearer token \
             to non-Google endpoint. Verify you trust this host."
        );
        return Ok(Some(token));
    }
    Err(SourceError::Other(format!(
        "{env_name} is present but endpoint {endpoint} is not googleapis.com; refusing to run anonymously after dropping credentials. Pass the explicit GCS token-forwarding flag only for endpoints you trust, or unset {env_name} for anonymous GCS-compatible scans."
    )))
}

fn read_gcs_bearer_env(name: &'static str) -> Result<Option<String>, SourceError> {
    match std::env::var(name) {
        Ok(token) => Ok(Some(token)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(SourceError::Other(format!(
            "{name} is not valid Unicode; provide a single-line bearer token"
        ))),
    }
}

#[cfg(test)]
mod builder_setter_tests {
    use super::GcsSource;

    #[test]
    fn with_prefix_and_max_objects_route_through_shared_set_optional() {
        // Defaults start unset.
        let source = GcsSource::new("example-bucket");
        assert_eq!(source.prefix, None);
        assert_eq!(source.max_objects, None);

        // Shared setter wraps the value in `Some`.
        let source = source.with_prefix("logs/2026/").with_max_objects(7);
        assert_eq!(source.prefix.as_deref(), Some("logs/2026/"));
        assert_eq!(source.max_objects, Some(7));

        // Overwrites the prior `Some`, it does not merge or ignore the update.
        let source = source.with_prefix("configs/").with_max_objects(42);
        assert_eq!(source.prefix.as_deref(), Some("configs/"));
        assert_eq!(source.max_objects, Some(42));
    }
}
