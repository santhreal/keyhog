//! Azure Blob Storage container source: lists blobs through the Blob service
//! REST API and downloads text-like blob bodies for scanning.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use quick_xml::de::{Deserializer, PredefinedEntityResolver};
use quick_xml::events::Event;
use quick_xml::Reader;
use reqwest::blocking::Client;
use serde::Deserialize;

pub struct AzureBlobSource {
    container_url: String,
    prefix: Option<String>,
    max_objects: Option<usize>,
    limits: crate::SourceLimits,
    http: crate::http::HttpClientConfig,
}

impl AzureBlobSource {
    pub fn new(container_url: impl Into<String>) -> Self {
        Self {
            container_url: container_url.into(),
            prefix: None,
            max_objects: None,
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
        self.max_objects = Some(max_objects);
        self
    }
}

impl Source for AzureBlobSource {
    fn name(&self) -> &str {
        "azure_blob"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        let result = crate::cloud::collect_on_blocking_thread("azure blob", || {
            collect_azure_blob_chunks(
                &self.container_url,
                self.prefix.as_deref(),
                match self.max_objects {
                    Some(max_objects) => max_objects,
                    None => self.limits.cloud_max_objects, // LAW10: no explicit per-source object-count override => use resolved Tier-A SourceLimits default
                },
                self.limits,
                &self.http,
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
    let client = crate::cloud::blocking_client("Azure Blob", http)?;
    let mut marker = None::<String>;
    let mut chunks = Vec::new();
    let mut coverage = crate::cloud::CloudListingCoverage::new("azure_blob", "blobs", max_objects);
    let fetch_pool = crate::cloud::object_fetch_pool("azure_blob")?;

    loop {
        if !coverage.has_capacity_or_record(&mut chunks) {
            break;
        }

        let listing =
            fetch_azure_blob_listing_page(&client, &container_url, prefix, marker.as_deref())?;
        let next_marker = listing.next_marker().map(str::to_string);
        let (page, reached_limit) = coverage.take_page(listing.blobs.blob);

        let page_chunks = download_azure_blob_listing_page(
            &fetch_pool,
            &page,
            &client,
            &container_url,
            limits.azure_blob_bytes,
        );
        crate::cloud::push_page_chunks(&mut chunks, page_chunks);

        if reached_limit {
            coverage.record_truncated(
                &mut chunks,
                "max_objects limit reached within the current Azure Blob listing page",
            );
            break;
        }
        match next_marker {
            Some(next) => marker = Some(next),
            None => break,
        }
    }

    Ok(chunks)
}

fn fetch_azure_blob_listing_page(
    client: &Client,
    container_url: &reqwest::Url,
    prefix: Option<&str>,
    marker: Option<&str>,
) -> Result<AzureListResponse, SourceError> {
    let list_url = azure_list_url(container_url, prefix, marker);
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
    parse_azure_listing(&body)
}

fn download_azure_blob_listing_page(
    fetch_pool: &rayon::ThreadPool,
    page: &[AzureListedBlob],
    client: &Client,
    container_url: &reqwest::Url,
    max_blob_bytes: u64,
) -> Vec<Result<Option<Chunk>, SourceError>> {
    use rayon::prelude::*;

    fetch_pool.install(|| {
        page.par_iter()
            .map(|blob| -> Result<Option<Chunk>, SourceError> {
                let listed_size = blob.properties.content_length;
                if listed_size == Some(0) {
                    return Ok(None);
                }
                let display_path = azure_blob_display_path(container_url, &blob.name)?;
                if !crate::cloud::is_probably_text_object_key(&blob.name) {
                    tracing::warn!(
                        key = %blob.name,
                        "skipping Azure blob: extension is treated as binary/container content; NOT scanned as text",
                    );
                    return Err(crate::cloud::record_unscanned_object_skip(
                        crate::SourceSkipEvent::Binary,
                        "Azure blob",
                        "blob",
                        &display_path,
                        "extension is treated as binary/container content",
                    ));
                }
                if let Some(content_type) = blob.properties.content_type.as_deref() {
                    if crate::cloud::is_binary_content_type(content_type) {
                        tracing::warn!(
                            key = %blob.name,
                            content_type,
                            "skipping Azure blob: listing reports binary content-type; NOT scanned as text",
                        );
                        return Err(crate::cloud::record_unscanned_object_skip(
                            crate::SourceSkipEvent::Binary,
                            "Azure blob",
                            "blob",
                            &display_path,
                            format!("listing reports binary content-type {content_type:?}"),
                        ));
                    }
                }
                fetch_azure_blob_chunk(client, container_url, &blob.name, listed_size, max_blob_bytes)
            })
            .collect()
    })
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
            let display_path = azure_blob_display_path(container_url, name)?;
            return Err(crate::cloud::record_unscanned_object_skip(
                crate::SourceSkipEvent::OverMaxSize,
                "Azure blob",
                "blob",
                &display_path,
                format!("listed size {size} exceeds the per-blob byte cap {max_blob_bytes}"),
            ));
        }
    }

    let display_path = azure_blob_display_path(container_url, name)?;
    let url = azure_blob_url(container_url, name);
    let response = client.get(url).send().map_err(|error| {
        crate::cloud::record_unreadable_object_skip(
            "Azure blob",
            "blob",
            &display_path,
            format!("download failed for {name}: {error}"),
        )
    })?;
    let Some(object_text) = crate::cloud::read_text_object_body(
        response,
        crate::cloud::TextObjectBodyContext {
            source: "Azure blob",
            item_kind: "blob",
            item_name: name,
            display_path: display_path.clone(),
            max_bytes: max_blob_bytes,
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
            source_type: "azure_blob".into(),
            path: Some(display_path),
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

fn azure_blob_display_path(
    container_url: &reqwest::Url,
    name: &str,
) -> Result<String, SourceError> {
    let Some(host) = container_url.host_str() else {
        return Err(SourceError::Other(
            "invalid Azure Blob container URL: missing host while building blob display path"
                .into(),
        ));
    };
    let container_path = container_url.path().trim_matches('/');
    Ok(format!("azblob://{host}/{container_path}/{name}"))
}

fn validate_container_url(raw: &str) -> Result<reqwest::Url, SourceError> {
    let parsed = crate::cloud::parse_http_endpoint(raw, "Azure Blob container URL")?;
    if parsed.path().trim_matches('/').is_empty() {
        return Err(SourceError::Other(
            "invalid Azure Blob container URL: path must include the container".into(),
        ));
    }
    Ok(parsed)
}
