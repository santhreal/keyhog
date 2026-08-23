//! Azure Blob Storage container source: lists blobs through the Blob service
//! REST API and downloads text-like blob bodies for scanning.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use quick_xml::de::{Deserializer, PredefinedEntityResolver};
use quick_xml::events::Event;
use quick_xml::Reader;
use reqwest::blocking::Client;
use serde::Deserialize;

#[derive(Clone)]
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
        crate::cloud::set_optional(&mut self.prefix, prefix.into());
        self
    }

    pub(crate) fn with_max_objects(mut self, max_objects: usize) -> Self {
        crate::cloud::set_optional(&mut self.max_objects, max_objects);
        self
    }
}

impl Source for AzureBlobSource {
    fn name(&self) -> &str {
        "azure_blob"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        let lease = crate::acquire_scan_read_lease();
        let source = self.clone();
        let worker_lease = lease.clone();
        let profile_runtime = crate::profile::current_runtime();
        let stream = crate::parallel_fetch::RemoteChunkStream::spawn(
            "keyhog-azure-blob",
            "azure blob",
            worker_lease,
            move |sender, worker_lease| {
                let _attributed = worker_lease.enter();
                let _profile_guard = profile_runtime.as_ref().map(|runtime| runtime.enter());
                let result = stream_azure_blob_chunks(
                    &source.container_url,
                    source.prefix.as_deref(),
                    source
                        .max_objects
                        .unwrap_or(source.limits.cloud_max_objects), // LAW10: absent per-source object cap uses the configured global cloud limit; enumeration remains bounded.
                    source.limits,
                    &source.http,
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
        // Azure returns an empty `<NextMarker/>` on the final page; the shared
        // normalizer treats that (and any whitespace cursor) as "exhausted".
        crate::cloud::meaningful_continuation_token(self.next_marker.as_deref())
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

fn stream_azure_blob_chunks(
    container_url: &str,
    prefix: Option<&str>,
    max_objects: usize,
    limits: crate::SourceLimits,
    http: &crate::http::HttpClientConfig,
    scan_lease: &crate::skip::ScanReadLease,
    mut emit: impl FnMut(Result<Chunk, SourceError>) -> bool,
) -> Result<(), SourceError> {
    let (container_url, screened) =
        validate_container_url(container_url, http.allow_private_endpoint)?;
    let _acquire = crate::profile::acquire_span();
    let client = crate::cloud::blocking_client("Azure Blob", http, screened.as_ref())?;
    drop(_acquire);
    let mut coverage = crate::cloud::CloudListingCoverage::new("azure_blob", "blobs", max_objects);
    let mut control_rows = Vec::new();
    let mut listing = {
        let _page = crate::profile::walk_span();
        fetch_azure_blob_listing_page(
            &client,
            &container_url,
            prefix,
            None,
            limits.web_response_bytes,
        )?
    };

    loop {
        if !coverage.has_capacity_or_record(&mut control_rows) {
            emit_azure_control_rows(&mut control_rows, &mut emit);
            break;
        }

        let next_marker = listing.next_marker().map(str::to_string);
        let (page, reached_limit) = coverage.take_page(listing.blobs.blob);
        let prefetch = match &next_marker {
            Some(marker) if !reached_limit && coverage.has_listed_capacity() => {
                let client = client.clone();
                let container_url = container_url.clone();
                let prefix = prefix.map(str::to_string);
                let marker = marker.clone();
                let max_response_bytes = limits.web_response_bytes;
                crate::cloud::ListingPrefetch::spawn(move || {
                    fetch_azure_blob_listing_page(
                        &client,
                        &container_url,
                        prefix.as_deref(),
                        Some(&marker),
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
                |blob| {
                    let listed_size = blob.properties.content_length;
                    if listed_size == Some(0) {
                        return Ok(None);
                    }
                    let display_path = azure_blob_display_path(&container_url, &blob.name)?;
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
                    fetch_azure_blob_chunk(
                        &client,
                        &container_url,
                        &blob.name,
                        listed_size,
                        limits.azure_blob_bytes,
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
                "max_objects limit reached within the current Azure Blob listing page",
            );
            emit_azure_control_rows(&mut control_rows, &mut emit);
            break;
        }
        if next_marker.is_none() {
            break;
        }
        match prefetch.join() {
            Some(next_listing) => listing = next_listing?,
            None => {
                coverage.has_capacity_or_record(&mut control_rows);
                emit_azure_control_rows(&mut control_rows, &mut emit);
                break;
            }
        }
    }

    Ok(())
}

fn emit_azure_control_rows(
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

fn fetch_azure_blob_listing_page(
    client: &Client,
    container_url: &reqwest::Url,
    prefix: Option<&str>,
    marker: Option<&str>,
    max_response_bytes: usize,
) -> Result<AzureListResponse, SourceError> {
    let list_url = azure_list_url(container_url, prefix, marker);
    let response = client.get(list_url.clone()).send().map_err(|error| {
        // The container URL is operator-supplied and, for a private container,
        // carries the SAS token whose `sig=` IS the credential. Both operands
        // leak it unredacted otherwise: `{list_url}` directly, and `{error}`
        // through `reqwest::Error`'s `" for url (<url>)"` suffix.
        let safe_url = crate::url_redaction::redact_url(list_url.as_str()).into_owned();
        crate::cloud::record_unreadable_listing_skip(
            "Azure Blob",
            "blobs",
            format!(
                "failed to list blobs at {safe_url}: {}",
                crate::url_redaction::redact_http_error(error)
            ),
        )
    })?;
    if !response.status().is_success() {
        let status = response.status();
        return Err(crate::cloud::record_unreadable_listing_skip(
            "Azure Blob",
            "blobs",
            format!("container request returned {status}"),
        ));
    }
    let body = crate::cloud::read_listing_response_body(
        response,
        "Azure Blob",
        "blobs",
        max_response_bytes,
    )?;
    parse_azure_listing(&body).map_err(|error| {
        crate::cloud::record_unreadable_listing_skip(
            "Azure Blob",
            "blobs",
            format!("failed to parse listing response: {error}"),
        )
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
        // `{error}` carries the blob URL, which inherits the container URL's
        // SAS `sig=`. `display_path` is the SAS-free `azblob://host/...` form,
        // so it stays as the operator-facing identity.
        crate::cloud::record_unreadable_object_skip(
            "Azure blob",
            "blob",
            &display_path,
            format!(
                "download failed for {name}: {}",
                crate::url_redaction::redact_http_error(error)
            ),
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
            source_type: keyhog_core::intern_source_type("azure_blob"),
            path: Some(display_path.into()),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            ctime_ns: None,
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

fn validate_container_url(
    raw: &str,
    allow_private: bool,
) -> Result<
    (
        reqwest::Url,
        Option<crate::endpoint_screen::ScreenedEndpoint>,
    ),
    SourceError,
> {
    let (parsed, screened) =
        crate::cloud::parse_http_endpoint(raw, "Azure Blob container URL", allow_private)?;
    if parsed.path().trim_matches('/').is_empty() {
        return Err(SourceError::Other(
            "invalid Azure Blob container URL: path must include the container".into(),
        ));
    }
    Ok((parsed, screened))
}

#[cfg(test)]
mod builder_setter_tests {
    use super::AzureBlobSource;

    #[test]
    fn with_prefix_and_max_objects_route_through_shared_set_optional() {
        // Defaults start unset.
        let source = AzureBlobSource::new("https://acct.blob.core.windows.net/container");
        assert_eq!(source.prefix, None);
        assert_eq!(source.max_objects, None);

        // Shared setter wraps the value in `Some`.
        let source = source.with_prefix("tenant-1/").with_max_objects(9);
        assert_eq!(source.prefix.as_deref(), Some("tenant-1/"));
        assert_eq!(source.max_objects, Some(9));

        // Overwrites the prior `Some`, it does not merge or ignore the update.
        let source = source.with_prefix("tenant-2/").with_max_objects(500);
        assert_eq!(source.prefix.as_deref(), Some("tenant-2/"));
        assert_eq!(source.max_objects, Some(500));
    }
}
