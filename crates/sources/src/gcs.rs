//! Google Cloud Storage bucket source: lists objects with the JSON API and
//! downloads text-like object bodies for scanning.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use reqwest::blocking::Client;
use serde::Deserialize;

const DEFAULT_GCS_ENDPOINT: &str = "https://storage.googleapis.com";

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
            endpoint: DEFAULT_GCS_ENDPOINT.to_string(),
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
    let bearer = gcs_bearer_token(&endpoint, allow_token_forward);
    let mut page_token = None::<String>;
    let mut chunks = Vec::new();
    let mut listed_objects = 0usize;
    let mut source_truncated_reported = false;
    use rayon::prelude::*;
    let fetch_pool = crate::cloud::object_fetch_pool("gcs")?;

    loop {
        if listed_objects >= max_objects {
            if let Some(error) = crate::cloud::record_source_truncated_once(
                "gcs",
                "max_objects limit reached before listing all objects",
                &mut source_truncated_reported,
            ) {
                chunks.push(Err(error));
            }
            break;
        }

        let list_url = gcs_list_url(&endpoint, &bucket);
        let mut request = client
            .get(&list_url)
            .query(&[("alt", "json"), ("maxResults", "1000")]);
        if let Some(prefix) = prefix {
            request = request.query(&[("prefix", prefix)]);
        }
        if let Some(token) = page_token.as_deref() {
            request = request.query(&[("pageToken", token)]);
        }
        if let Some(token) = bearer.as_deref() {
            request = request.bearer_auth(token);
        }

        let response = request
            .send()
            .map_err(|error| SourceError::Other(format!("failed to list GCS objects: {error}")))?;
        if !response.status().is_success() {
            return Err(SourceError::Other(format!(
                "failed to list GCS objects: bucket request returned {}",
                response.status()
            )));
        }
        let body = response
            .text()
            .map_err(|error| SourceError::Other(format!("failed to read GCS listing: {error}")))?;
        let listing = parse_gcs_listing(&body)?;
        let remaining = max_objects.saturating_sub(listed_objects);
        let reached_limit = listing.items.len() > remaining;
        let page: Vec<_> = listing.items.into_iter().take(remaining).collect();
        listed_objects += page.len();

        let page_chunks: Vec<Result<Option<Chunk>, SourceError>> = fetch_pool.install(|| {
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
                        let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
                        return Ok(None);
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

        if reached_limit {
            if let Some(error) = crate::cloud::record_source_truncated_once(
                "gcs",
                "max_objects limit reached within the current GCS listing page",
                &mut source_truncated_reported,
            ) {
                chunks.push(Err(error));
            }
            break;
        }
        match listing.next_page_token {
            Some(token) => page_token = Some(token),
            None => break,
        }
    }

    Ok(chunks)
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
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            return Ok(None);
        }
    }

    let url = gcs_media_url(endpoint, bucket, name);
    let mut request = client.get(&url);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    let response = request.send().map_err(|error| {
        SourceError::Other(format!("failed to download GCS object: {name}: {error}"))
    })?;
    let display_path = format!("gs://{bucket}/{name}");
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
    let host = host.to_ascii_lowercase();
    host == "googleapis.com" || host.ends_with(".googleapis.com")
}

fn gcs_bearer_token(endpoint: &str, allow_token_forward: bool) -> Option<String> {
    let token = std::env::var("GOOGLE_OAUTH_ACCESS_TOKEN")
        .or_else(|_| std::env::var("GCS_BEARER_TOKEN"))
        .ok()?; // LAW10: absent bearer env is an intended default for anonymous GCS; listing/fetch failures still surface normally.
    if endpoint_is_google(endpoint) || crate::cloud::credential_forward_allowed(allow_token_forward)
    {
        return Some(token);
    }
    tracing::warn!(
        endpoint,
        "GCS bearer token present but endpoint is not googleapis.com; refusing to forward. Pass the explicit GCS token-forwarding flag only for endpoints you trust."
    );
    None
}
