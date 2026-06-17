//! Google Cloud Storage bucket source: lists objects with the JSON API and
//! downloads text-like object bodies for scanning.

use std::io::Read;

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use reqwest::blocking::Client;
use serde::Deserialize;

const DEFAULT_GCS_ENDPOINT: &str = "https://storage.googleapis.com";
const DEFAULT_MAX_OBJECTS: usize = 100_000;
const MAX_GCS_OBJECT_BYTES: u64 = 10 * 1024 * 1024;

pub struct GcsSource {
    bucket: String,
    prefix: Option<String>,
    endpoint: String,
    max_objects: usize,
    http: crate::http::HttpClientConfig,
}

impl GcsSource {
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            prefix: None,
            endpoint: DEFAULT_GCS_ENDPOINT.to_string(),
            max_objects: DEFAULT_MAX_OBJECTS,
            http: crate::http::HttpClientConfig {
                ua_suffix: Some("gcs".into()),
                ..Default::default()
            },
        }
    }

    pub fn with_http_config(mut self, http: crate::http::HttpClientConfig) -> Self {
        self.http = http;
        self
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    pub fn with_max_objects(mut self, max_objects: usize) -> Self {
        self.max_objects = max_objects;
        self
    }
}

impl Source for GcsSource {
    fn name(&self) -> &str {
        "gcs"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        let result = std::thread::scope(|s| {
            match s
                .spawn(|| {
                    collect_gcs_chunks(
                        &self.bucket,
                        self.prefix.as_deref(),
                        &self.endpoint,
                        self.max_objects,
                        &self.http,
                    )
                })
                .join()
            {
                Ok(result) => result,
                Err(_panic) => Err(SourceError::Other("gcs fetch thread panicked".to_string())),
            }
        });
        match result {
            Ok(chunks) => Box::new(chunks.into_iter().map(Ok)),
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
    http: &crate::http::HttpClientConfig,
) -> Result<Vec<Chunk>, SourceError> {
    let bucket = validate_bucket_name(bucket)?;
    let endpoint = validate_endpoint(endpoint)?;
    let mut http = http.clone();
    if http.timeout.is_none() {
        http.timeout = Some(crate::timeouts::HTTP_REQUEST);
    }
    let client = crate::http::blocking_client_builder(&http)
        .map_err(SourceError::Other)?
        .build()
        .map_err(|error| SourceError::Other(format!("failed to build GCS client: {error}")))?;
    let bearer = gcs_bearer_token(&endpoint);
    let mut page_token = None::<String>;
    let mut chunks = Vec::new();
    let mut listed_objects = 0usize;
    let mut source_truncated_reported = false;

    loop {
        if listed_objects >= max_objects {
            crate::cloud::record_source_truncated_once(
                "gcs",
                "max_objects limit reached before listing all objects",
                &mut source_truncated_reported,
            );
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

        use rayon::prelude::*;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(16)
            .build()
            .map_err(|error| SourceError::Other(format!("rayon pool build: {error}")))?;
        let page_chunks: Vec<Result<Option<Chunk>, SourceError>> = pool.install(|| {
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
                    )
                })
                .collect()
        });
        for result in page_chunks {
            if let Some(chunk) = result? {
                chunks.push(chunk);
            }
        }

        if reached_limit {
            crate::cloud::record_source_truncated_once(
                "gcs",
                "max_objects limit reached within the current GCS listing page",
                &mut source_truncated_reported,
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

fn fetch_gcs_object_chunk(
    client: &Client,
    endpoint: &str,
    bucket: &str,
    name: &str,
    listed_size: Option<u64>,
    bearer: Option<&str>,
) -> Result<Option<Chunk>, SourceError> {
    if let Some(size) = listed_size {
        if size > MAX_GCS_OBJECT_BYTES {
            tracing::warn!(
                bucket,
                key = name,
                object_size = size,
                cap = MAX_GCS_OBJECT_BYTES,
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
    if !response.status().is_success() {
        let status = response.status();
        tracing::warn!(
            bucket,
            key = name,
            %status,
            "skipping GCS object: GET returned non-success status; NOT scanned",
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        return Ok(None);
    }
    if let Some(content_length) = response.content_length() {
        if content_length > MAX_GCS_OBJECT_BYTES {
            tracing::warn!(
                bucket,
                key = name,
                content_length,
                cap = MAX_GCS_OBJECT_BYTES,
                "skipping GCS object: Content-Length exceeds the per-object byte cap; NOT scanned",
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            return Ok(None);
        }
    }
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| match value.to_str() {
            Ok(value) => Some(value),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "GCS object content-type header is not valid text; scanning body as unknown content type"
                );
                None
            }
        });
    if let Some(content_type) = content_type {
        if crate::cloud::is_binary_content_type(content_type) {
            tracing::warn!(
                bucket,
                key = name,
                content_type,
                "skipping GCS object: binary content-type; NOT scanned as text",
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
            return Ok(None);
        }
    }

    let mut body = Vec::new();
    let mut reader = response.take(MAX_GCS_OBJECT_BYTES + 1);
    std::io::Read::read_to_end(&mut reader, &mut body).map_err(|error| {
        SourceError::Other(format!("failed to read GCS object body: {name}: {error}"))
    })?;
    if body.len() as u64 > MAX_GCS_OBJECT_BYTES {
        tracing::warn!(
            bucket,
            key = name,
            downloaded = body.len(),
            cap = MAX_GCS_OBJECT_BYTES,
            "skipping GCS object: streamed body exceeds the per-object byte cap; NOT scanned",
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        return Ok(None);
    }
    let object_text = match String::from_utf8(body) {
        Ok(text) => text,
        Err(error) => {
            tracing::warn!(
                bucket,
                key = name,
                valid_up_to = error.utf8_error().valid_up_to(),
                "skipping GCS object: body claimed text content-type but failed UTF-8 decode; NOT scanned"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return Ok(None);
        }
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
    let endpoint = endpoint.trim();
    let parsed = reqwest::Url::parse(endpoint)
        .map_err(|error| SourceError::Other(format!("invalid GCS endpoint: {error}")))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
    {
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

pub(crate) fn credential_forward_allowed() -> bool {
    matches!(
        std::env::var("KEYHOG_GCS_ALLOW_TOKEN_FORWARD")
            .ok() // LAW10: unset opt-in env is the intended default; credential forwarding remains fail-closed.
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

fn gcs_bearer_token(endpoint: &str) -> Option<String> {
    let token = std::env::var("GOOGLE_OAUTH_ACCESS_TOKEN")
        .or_else(|_| std::env::var("GCS_BEARER_TOKEN"))
        .ok()?; // LAW10: absent bearer env is an intended default for anonymous GCS; listing/fetch failures still surface normally.
    if endpoint_is_google(endpoint) || credential_forward_allowed() {
        return Some(token);
    }
    tracing::warn!(
        endpoint,
        "GCS bearer token present but endpoint is not googleapis.com; refusing to forward. Set KEYHOG_GCS_ALLOW_TOKEN_FORWARD=1 to opt in."
    );
    None
}
