//! Google Cloud Storage bucket source: lists objects with the JSON API and
//! downloads text-like object bodies for scanning.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use reqwest::blocking::Client;
use serde::Deserialize;

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
        self.prefix = Some(prefix.into());
        self
    }

    pub(crate) fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    pub(crate) fn with_max_objects(mut self, max_objects: usize) -> Self {
        self.max_objects = Some(max_objects);
        self
    }
}

impl Source for GcsSource {
    fn name(&self) -> &str {
        "gcs"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        let result = crate::cloud::collect_on_blocking_thread("gcs", || {
            collect_gcs_chunks(
                &self.bucket,
                self.prefix.as_deref(),
                &self.endpoint,
                match self.max_objects {
                    Some(max_objects) => max_objects,
                    None => self.limits.cloud_max_objects, // LAW10: no explicit per-source object-count override => use resolved Tier-A SourceLimits default
                },
                self.limits,
                &self.http,
                self.allow_token_forward,
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

fn collect_gcs_chunks(
    bucket: &str,
    prefix: Option<&str>,
    endpoint: &str,
    max_objects: usize,
    limits: crate::SourceLimits,
    http: &crate::http::HttpClientConfig,
    allow_token_forward: bool,
) -> Result<Vec<Result<Chunk, SourceError>>, SourceError> {
    let bucket = validate_bucket_name(bucket)?;
    let endpoint = validate_endpoint(endpoint)?;
    let client = crate::cloud::blocking_client("GCS", http)?;
    let bearer = resolve_gcs_auth(&endpoint, allow_token_forward)?;
    let mut page_token = None::<String>;
    let mut chunks = Vec::new();
    let mut coverage = crate::cloud::CloudListingCoverage::new("gcs", "objects", max_objects);
    let fetch_pool = crate::cloud::object_fetch_pool("gcs")?;

    loop {
        if !coverage.has_capacity_or_record(&mut chunks) {
            break;
        }

        let listing = fetch_gcs_listing_page(
            &client,
            &endpoint,
            &bucket,
            prefix,
            page_token.as_deref(),
            bearer.as_deref(),
        )?;
        let (page, reached_limit) = coverage.take_page(listing.items);

        let page_chunks = download_gcs_listing_page(
            &fetch_pool,
            &page,
            &client,
            &endpoint,
            &bucket,
            bearer.as_deref(),
            limits.gcs_object_bytes,
        );
        crate::cloud::push_page_chunks(&mut chunks, page_chunks);

        if reached_limit {
            coverage.record_truncated(
                &mut chunks,
                "max_objects limit reached within the current GCS listing page",
            );
            break;
        }
        match listing.next_page_token {
            Some(token) => page_token = Some(token),
            None => break,
        }
    }

    Ok(chunks)
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
    let body = response.text().map_err(|error| {
        crate::cloud::record_unreadable_listing_skip(
            "GCS",
            "objects",
            format!("failed to read listing response body: {error}"),
        )
    })?;
    parse_gcs_listing(&body).map_err(|error| {
        crate::cloud::record_unreadable_listing_skip(
            "GCS",
            "objects",
            format!("failed to parse listing response: {error}"),
        )
    })
}

fn download_gcs_listing_page(
    fetch_pool: &rayon::ThreadPool,
    page: &[GcsObject],
    client: &Client,
    endpoint: &str,
    bucket: &str,
    bearer: Option<&str>,
    max_object_bytes: u64,
) -> Vec<Result<Option<Chunk>, SourceError>> {
    use rayon::prelude::*;

    fetch_pool.install(|| {
        page.par_iter()
            .map(|object| -> Result<Option<Chunk>, SourceError> {
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
                    client,
                    endpoint,
                    bucket,
                    &object.name,
                    listed_size,
                    bearer,
                    max_object_bytes,
                )
            })
            .collect()
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
            source_type: "gcs".into(),
            path: Some(format!("gs://{bucket}/{name}")),
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

fn validate_bucket_name(bucket: &str) -> Result<String, SourceError> {
    let bucket = bucket.trim();
    if bucket.len() < 3 || bucket.len() > 222 {
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

fn validate_endpoint(endpoint: &str) -> Result<String, SourceError> {
    let parsed = crate::cloud::parse_http_endpoint(endpoint, "GCS")?;
    if parsed.query().is_some() || !matches!(parsed.path(), "" | "/") {
        return Err(SourceError::Other("invalid GCS endpoint".into()));
    }
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

pub(crate) fn endpoint_is_google(endpoint: &str) -> bool {
    let parsed = match reqwest::Url::parse(endpoint) {
        Ok(parsed) => parsed,
        Err(_) => return false, // LAW10: malformed endpoint is fail-closed as non-Google, so credential forwarding stays disabled.
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    crate::cloud::host_matches_domain_ascii_ci(host, "googleapis.com")
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
    if endpoint_is_google(endpoint) || crate::cloud::credential_forward_allowed(allow_token_forward)
    {
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
