//! Azure Blob Storage container source: lists blobs through the Blob service
//! REST API and downloads text-like blob bodies for scanning.

use std::io::Read;

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use quick_xml::de::{Deserializer, PredefinedEntityResolver};
use quick_xml::events::Event;
use quick_xml::Reader;
use reqwest::blocking::Client;
use serde::Deserialize;

const DEFAULT_MAX_OBJECTS: usize = 100_000;

pub struct AzureBlobSource {
    container_url: String,
    prefix: Option<String>,
    max_objects: usize,
    limits: crate::SourceLimits,
    http: crate::http::HttpClientConfig,
}

impl AzureBlobSource {
    pub fn new(container_url: impl Into<String>) -> Self {
        Self {
            container_url: container_url.into(),
            prefix: None,
            max_objects: DEFAULT_MAX_OBJECTS,
            limits: crate::SourceLimits::default(),
            http: crate::http::HttpClientConfig {
                ua_suffix: Some("azure-blob".into()),
                ..Default::default()
            },
        }
    }

    pub(crate) fn with_http_config(mut self, http: crate::http::HttpClientConfig) -> Self {
        self.http = http;
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

    pub(crate) fn with_max_objects(mut self, max_objects: usize) -> Self {
        self.max_objects = max_objects;
        self
    }
}

impl Source for AzureBlobSource {
    fn name(&self) -> &str {
        "azure_blob"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        let result = std::thread::scope(|s| {
            match s
                .spawn(|| {
                    collect_azure_blob_chunks(
                        &self.container_url,
                        self.prefix.as_deref(),
                        self.max_objects,
                        self.limits,
                        &self.http,
                    )
                })
                .join()
            {
                Ok(result) => result,
                Err(_panic) => Err(SourceError::Other(
                    "azure blob fetch thread panicked".to_string(),
                )),
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

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AzureListResponse {
    #[serde(default)]
    blobs: AzureBlobSet,
    #[serde(default, rename = "NextMarker")]
    next_marker: Option<String>,
}

impl AzureListResponse {
    fn next_marker(&self) -> Option<&str> {
        self.next_marker
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }
}

#[derive(Debug, Default, Deserialize)]
struct AzureBlobSet {
    #[serde(default, rename = "Blob")]
    blob: Vec<AzureListedBlob>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AzureListedBlob {
    name: String,
    #[serde(default)]
    properties: AzureBlobProperties,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AzureBlobProperties {
    #[serde(default, rename = "Content-Length")]
    content_length: Option<u64>,
    #[serde(default, rename = "Content-Type")]
    content_type: Option<String>,
}

fn collect_azure_blob_chunks(
    container_url: &str,
    prefix: Option<&str>,
    max_objects: usize,
    limits: crate::SourceLimits,
    http: &crate::http::HttpClientConfig,
) -> Result<Vec<Result<Chunk, SourceError>>, SourceError> {
    let container_url = validate_container_url(container_url)?;
    let mut http = http.clone();
    if http.timeout.is_none() {
        http.timeout = Some(crate::timeouts::HTTP_REQUEST);
    }
    let client = crate::http::blocking_client_builder(&http)
        .map_err(SourceError::Other)?
        .build()
        .map_err(|error| {
            SourceError::Other(format!("failed to build Azure Blob client: {error}"))
        })?;
    let mut marker = None::<String>;
    let mut chunks = Vec::new();
    let mut listed_objects = 0usize;
    let mut source_truncated_reported = false;
    use rayon::prelude::*;
    let fetch_pool = crate::cloud::object_fetch_pool("azure_blob")?;

    loop {
        if listed_objects >= max_objects {
            if let Some(error) = crate::cloud::record_source_truncated_once(
                "azure_blob",
                "max_objects limit reached before listing all blobs",
                &mut source_truncated_reported,
            ) {
                chunks.push(Err(error));
            }
            break;
        }

        let list_url = azure_list_url(&container_url, prefix, marker.as_deref());
        let response = client.get(list_url.clone()).send().map_err(|error| {
            SourceError::Other(format!("failed to list Azure blobs at {list_url}: {error}"))
        })?;
        if !response.status().is_success() {
            return Err(SourceError::Other(format!(
                "failed to list Azure blobs: container request returned {}",
                response.status()
            )));
        }
        let body = response.text().map_err(|error| {
            SourceError::Other(format!("failed to read Azure Blob listing: {error}"))
        })?;
        let listing = parse_azure_listing(&body)?;
        let next_marker = listing.next_marker().map(str::to_string);
        let remaining = max_objects.saturating_sub(listed_objects);
        let reached_limit = listing.blobs.blob.len() > remaining;
        let page: Vec<_> = listing.blobs.blob.into_iter().take(remaining).collect();
        listed_objects += page.len();

        let page_chunks: Vec<Result<Option<Chunk>, SourceError>> = fetch_pool.install(|| {
            page.par_iter()
                .map(|blob| -> Result<Option<Chunk>, SourceError> {
                    let listed_size = blob.properties.content_length;
                    if listed_size == Some(0) {
                        return Ok(None);
                    }
                    if !crate::cloud::is_probably_text_object_key(&blob.name) {
                        tracing::warn!(
                            key = %blob.name,
                            "skipping Azure blob: extension is treated as binary/container content; NOT scanned as text",
                        );
                        let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
                        return Ok(None);
                    }
                    if let Some(content_type) = blob.properties.content_type.as_deref() {
                        if crate::cloud::is_binary_content_type(content_type) {
                            tracing::warn!(
                                key = %blob.name,
                                content_type,
                                "skipping Azure blob: listing reports binary content-type; NOT scanned as text",
                            );
                            let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
                            return Ok(None);
                        }
                    }
                    fetch_azure_blob_chunk(
                        &client,
                        &container_url,
                        &blob.name,
                        listed_size,
                        limits.azure_blob_bytes,
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
                "azure_blob",
                "max_objects limit reached within the current Azure Blob listing page",
                &mut source_truncated_reported,
            ) {
                chunks.push(Err(error));
            }
            break;
        }
        match next_marker {
            Some(next) => marker = Some(next),
            None => break,
        }
    }

    Ok(chunks)
}

fn fetch_azure_blob_chunk(
    client: &Client,
    container_url: &reqwest::Url,
    name: &str,
    listed_size: Option<u64>,
    max_blob_bytes: u64,
) -> Result<Option<Chunk>, SourceError> {
    if let Some(size) = listed_size {
        if size > max_blob_bytes {
            tracing::warn!(
                key = name,
                object_size = size,
                cap = max_blob_bytes,
                "skipping Azure blob: listed size exceeds the per-blob byte cap; NOT scanned",
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            return Ok(None);
        }
    }

    let url = azure_blob_url(container_url, name);
    let response = client.get(url.clone()).send().map_err(|error| {
        SourceError::Other(format!("failed to download Azure blob: {name}: {error}"))
    })?;
    if !response.status().is_success() {
        let status = response.status();
        tracing::warn!(
            key = name,
            %status,
            "skipping Azure blob: GET returned non-success status; NOT scanned",
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        return Err(SourceError::Other(format!(
            "failed to scan Azure blob {name}: GET returned {status}; blob was not scanned"
        )));
    }
    if let Some(content_length) = response.content_length() {
        if content_length > max_blob_bytes {
            tracing::warn!(
                key = name,
                content_length,
                cap = max_blob_bytes,
                "skipping Azure blob: Content-Length exceeds the per-blob byte cap; NOT scanned",
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
                    "Azure blob content-type header is not valid text; scanning body as unknown content type"
                );
                None
            }
        });
    if let Some(content_type) = content_type {
        if crate::cloud::is_binary_content_type(content_type) {
            tracing::warn!(
                key = name,
                content_type,
                "skipping Azure blob: binary content-type; NOT scanned as text",
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
            return Ok(None);
        }
    }

    let mut body = Vec::new();
    let mut reader = response.take(max_blob_bytes + 1);
    std::io::Read::read_to_end(&mut reader, &mut body).map_err(|error| {
        SourceError::Other(format!("failed to read Azure blob body: {name}: {error}"))
    })?;
    if body.len() as u64 > max_blob_bytes {
        tracing::warn!(
            key = name,
            downloaded = body.len(),
            cap = max_blob_bytes,
            "skipping Azure blob: streamed body exceeds the per-blob byte cap; NOT scanned",
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        return Ok(None);
    }
    let object_text = match String::from_utf8(body) {
        Ok(text) => text,
        Err(error) => {
            tracing::warn!(
                key = name,
                valid_up_to = error.utf8_error().valid_up_to(),
                "skipping Azure blob: body claimed text content-type but failed UTF-8 decode; NOT scanned"
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
            source_type: "azure_blob".into(),
            path: Some(azure_blob_display_path(container_url, name)),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: listed_size,
            decoded_span: None,
        },
    }))
}

fn parse_azure_listing(body: &str) -> Result<AzureListResponse, SourceError> {
    if crate::cloud::contains_forbidden_xml_markup(body) {
        return Err(SourceError::Other(
            "Azure Blob XML response contains unsupported DTD/entity declarations".into(),
        ));
    }

    let mut reader = Reader::from_str(body);
    loop {
        match reader.read_event() {
            Ok(Event::DocType(_)) => {
                return Err(SourceError::Other(
                    "Azure Blob XML response contains unsupported DOCTYPE declarations".into(),
                ));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => {
                return Err(SourceError::Other(format!(
                    "failed to validate Azure Blob listing XML: {error}"
                )));
            }
        }
    }

    let mut deserializer = Deserializer::from_str_with_resolver(body, PredefinedEntityResolver);
    AzureListResponse::deserialize(&mut deserializer).map_err(|error| {
        SourceError::Other(format!("failed to parse Azure Blob listing XML: {error}"))
    })
}

fn azure_list_url(
    container_url: &reqwest::Url,
    prefix: Option<&str>,
    marker: Option<&str>,
) -> reqwest::Url {
    let mut url = container_url.clone();
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("restype", "container");
        query.append_pair("comp", "list");
        query.append_pair("maxresults", "5000");
        if let Some(prefix) = prefix {
            query.append_pair("prefix", prefix);
        }
        if let Some(marker) = marker {
            query.append_pair("marker", marker);
        }
    }
    url
}

fn azure_blob_url(container_url: &reqwest::Url, name: &str) -> reqwest::Url {
    let mut url = container_url.clone();
    let base_path = url.path().trim_end_matches('/');
    let encoded_name = crate::cloud::encode_object_key_path(name);
    url.set_path(&format!("{base_path}/{encoded_name}"));
    url
}

fn azure_blob_display_path(container_url: &reqwest::Url, name: &str) -> String {
    let host = match container_url.host_str() {
        Some(host) => host,
        None => "unknown-host",
    };
    let container_path = container_url.path().trim_matches('/');
    format!("azblob://{host}/{container_path}/{name}")
}

fn validate_container_url(raw: &str) -> Result<reqwest::Url, SourceError> {
    let raw = raw.trim();
    let parsed = reqwest::Url::parse(raw).map_err(|error| {
        SourceError::Other(format!("invalid Azure Blob container URL: {error}"))
    })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(SourceError::Other(
            "invalid Azure Blob container URL".into(),
        ));
    }
    if parsed.path().trim_matches('/').is_empty() {
        return Err(SourceError::Other(
            "invalid Azure Blob container URL: path must include the container".into(),
        ));
    }
    Ok(parsed)
}
