use keyhog_core::{Chunk, SourceError};
use reqwest::blocking::{Client, Response};
use std::io::Read;

#[cfg(feature = "azure")]
pub(crate) mod azure_blob;

pub(crate) use crate::blocking_thread::collect_on_blocking_thread;

pub(crate) const OBJECT_FETCH_THREADS: usize = crate::parallel_fetch::CLOUD_OBJECT_FETCH_THREADS;

pub(crate) fn object_fetch_pool(
    source: &str,
) -> Result<rayon::ThreadPool, keyhog_core::SourceError> {
    crate::parallel_fetch::bounded_fetch_pool(source, OBJECT_FETCH_THREADS)
}

pub(crate) fn blocking_client(
    source: &str,
    http: &crate::http::HttpClientConfig,
) -> Result<Client, SourceError> {
    let http = if http.timeout.is_none() {
        let mut http = http.clone();
        http.timeout = Some(crate::timeouts::HTTP_REQUEST);
        http
    } else {
        http.clone()
    };
    crate::http::blocking_client_builder(&http)
        .map_err(SourceError::Other)?
        .build()
        .map_err(|error| SourceError::Other(format!("failed to build {source} client: {error}")))
}

pub(crate) fn parse_http_endpoint(raw: &str, source: &str) -> Result<reqwest::Url, SourceError> {
    let raw = raw.trim();
    let parsed = reqwest::Url::parse(raw)
        .map_err(|error| SourceError::Other(format!("invalid {source} endpoint: {error}")))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(SourceError::Other(format!("invalid {source} endpoint")));
    }
    Ok(parsed)
}

pub(crate) fn credential_forward_allowed(allow_explicit: bool) -> bool {
    allow_explicit
}

pub(crate) fn host_matches_domain_ascii_ci(host: &str, domain: &str) -> bool {
    if host.eq_ignore_ascii_case(domain) {
        return true;
    }
    if host.len() <= domain.len() {
        return false;
    }
    let dot_index = host.len() - domain.len() - 1;
    host.as_bytes().get(dot_index) == Some(&b'.')
        && host
            .as_bytes()
            .get(dot_index + 1..)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(domain.as_bytes()))
}

pub(crate) fn take_listing_page<T>(items: Vec<T>, remaining: usize) -> (Vec<T>, bool) {
    let reached_limit = items.len() > remaining;
    let page = items.into_iter().take(remaining).collect();
    (page, reached_limit)
}

pub(crate) struct CloudListingCoverage {
    source: &'static str,
    item_plural: &'static str,
    max_objects: usize,
    listed_objects: usize,
    source_truncated_reported: bool,
}

impl CloudListingCoverage {
    pub(crate) fn new(source: &'static str, item_plural: &'static str, max_objects: usize) -> Self {
        Self {
            source,
            item_plural,
            max_objects,
            listed_objects: 0,
            source_truncated_reported: false,
        }
    }

    pub(crate) fn has_capacity_or_record(
        &mut self,
        chunks: &mut Vec<Result<Chunk, SourceError>>,
    ) -> bool {
        if self.listed_objects < self.max_objects {
            return true;
        }
        let reason = format!(
            "max_objects limit reached before listing all {}",
            self.item_plural
        );
        self.record_truncated(chunks, &reason);
        false
    }

    pub(crate) fn take_page<T>(&mut self, items: Vec<T>) -> (Vec<T>, bool) {
        let remaining = self.max_objects.saturating_sub(self.listed_objects);
        let (page, reached_limit) = take_listing_page(items, remaining);
        self.listed_objects += page.len();
        (page, reached_limit)
    }

    pub(crate) fn record_truncated(
        &mut self,
        chunks: &mut Vec<Result<Chunk, SourceError>>,
        reason: &str,
    ) {
        if let Some(error) =
            record_source_truncated_once(self.source, reason, &mut self.source_truncated_reported)
        {
            chunks.push(Err(error));
        }
    }
}

pub(crate) fn push_page_chunks(
    chunks: &mut Vec<Result<Chunk, SourceError>>,
    page_chunks: Vec<Result<Option<Chunk>, SourceError>>,
) {
    for result in page_chunks {
        match result {
            Ok(Some(chunk)) => chunks.push(Ok(chunk)),
            Ok(None) => {}
            Err(error) => chunks.push(Err(error)),
        }
    }
}

pub(crate) fn unscanned_object_error(
    source: &str,
    item_kind: &str,
    display_path: &str,
    reason: impl std::fmt::Display,
) -> SourceError {
    SourceError::Other(format!(
        "failed to scan {source} {display_path}: {reason}; {item_kind} was not scanned"
    ))
}

pub(crate) fn record_unscanned_object_skip(
    event: crate::SourceSkipEvent,
    source: &str,
    item_kind: &str,
    display_path: &str,
    reason: impl std::fmt::Display,
) -> SourceError {
    let _event = crate::record_skip_event(event);
    unscanned_object_error(source, item_kind, display_path, reason)
}

pub(crate) fn record_unreadable_object_skip(
    source: &str,
    item_kind: &str,
    display_path: &str,
    reason: impl std::fmt::Display,
) -> SourceError {
    record_unscanned_object_skip(
        crate::SourceSkipEvent::Unreadable,
        source,
        item_kind,
        display_path,
        reason,
    )
}

pub(crate) struct TextObjectBodyContext<'a> {
    pub(crate) source: &'static str,
    pub(crate) item_kind: &'static str,
    pub(crate) item_name: &'a str,
    pub(crate) display_path: String,
    pub(crate) max_bytes: u64,
}

pub(crate) fn read_text_object_body(
    response: Response,
    ctx: TextObjectBodyContext<'_>,
) -> Result<Option<String>, SourceError> {
    if !response.status().is_success() {
        let status = response.status();
        tracing::warn!(
            source = ctx.source,
            key = ctx.item_name,
            %status,
            "skipping cloud object: GET returned non-success status; NOT scanned",
        );
        return Err(record_unscanned_object_skip(
            crate::SourceSkipEvent::Unreadable,
            ctx.source,
            ctx.item_kind,
            &ctx.display_path,
            format!("GET returned {status}"),
        ));
    }

    if let Some(content_length) = response.content_length() {
        if content_length > ctx.max_bytes {
            tracing::warn!(
                source = ctx.source,
                key = ctx.item_name,
                content_length,
                cap = ctx.max_bytes,
                "skipping cloud object: Content-Length exceeds the per-object byte cap; NOT scanned",
            );
            return Err(record_unscanned_object_skip(
                crate::SourceSkipEvent::OverMaxSize,
                ctx.source,
                ctx.item_kind,
                &ctx.display_path,
                format!(
                    "Content-Length {content_length} exceeds the per-object byte cap {}",
                    ctx.max_bytes
                ),
            ));
        }
    }

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| match value.to_str() {
            Ok(value) => Some(value),
            Err(error) => {
                tracing::warn!(
                    source = ctx.source,
                    key = ctx.item_name,
                    %error,
                    "cloud object content-type header is not valid text; scanning body as unknown content type"
                );
                None
            }
        });
    if let Some(content_type) = content_type {
        if crate::cloud::is_binary_content_type(content_type) {
            tracing::warn!(
                source = ctx.source,
                key = ctx.item_name,
                content_type,
                "skipping cloud object: binary content-type; NOT scanned as text",
            );
            return Err(record_unscanned_object_skip(
                crate::SourceSkipEvent::Binary,
                ctx.source,
                ctx.item_kind,
                &ctx.display_path,
                format!("binary content-type {content_type:?}"),
            ));
        }
    }
    let content_type_is_unknown_binary = content_type.is_some_and(is_unknown_binary_content_type);

    let initial_capacity = match response.content_length() {
        Some(len) => len.min(ctx.max_bytes).min(64 * 1024) as usize,
        None => 0,
    };
    let mut body = Vec::with_capacity(initial_capacity);
    let mut reader = response.take(ctx.max_bytes + 1);
    Read::read_to_end(&mut reader, &mut body).map_err(|error| {
        record_unreadable_object_skip(
            ctx.source,
            ctx.item_kind,
            &ctx.display_path,
            format!("failed to read body for {}: {error}", ctx.item_name),
        )
    })?;
    if body.len() as u64 > ctx.max_bytes {
        tracing::warn!(
            source = ctx.source,
            key = ctx.item_name,
            downloaded = body.len(),
            cap = ctx.max_bytes,
            "skipping cloud object: streamed body exceeds the per-object byte cap; NOT scanned",
        );
        return Err(record_unscanned_object_skip(
            crate::SourceSkipEvent::OverMaxSize,
            ctx.source,
            ctx.item_kind,
            &ctx.display_path,
            format!(
                "streamed body exceeded the per-object byte cap {} after reading {} bytes",
                ctx.max_bytes,
                body.len()
            ),
        ));
    }

    if content_type_is_unknown_binary {
        return match crate::filesystem::decode_text_file(&body) {
            Some(text) => Ok(Some(text)),
            None => {
                tracing::warn!(
                    source = ctx.source,
                    key = ctx.item_name,
                    "skipping cloud object: octet-stream body is binary after capped decode; NOT scanned as text"
                );
                Err(record_unscanned_object_skip(
                    crate::SourceSkipEvent::Binary,
                    ctx.source,
                    ctx.item_kind,
                    &ctx.display_path,
                    "octet-stream body is binary after capped decode",
                ))
            }
        };
    }

    match String::from_utf8(body) {
        Ok(text) => Ok(Some(text)),
        Err(error) => {
            let valid_up_to = error.utf8_error().valid_up_to();
            tracing::warn!(
                source = ctx.source,
                key = ctx.item_name,
                valid_up_to,
                "skipping cloud object: body claimed text content-type but failed UTF-8 decode; NOT scanned"
            );
            Err(record_unscanned_object_skip(
                crate::SourceSkipEvent::Unreadable,
                ctx.source,
                ctx.item_kind,
                &ctx.display_path,
                format!("body failed UTF-8 decode at byte {valid_up_to}"),
            ))
        }
    }
}

pub(crate) fn is_probably_text_object_key(key: &str) -> bool {
    const BINARY_OBJECT_EXTS: &[&str] = &[
        "zip", "gz", "tgz", "tar", "7z", "rar", "pdf", "bz2", "xz", "zst", "lz4", "sz",
    ];
    let Some(ext) = cloud_key_extension(key) else {
        return true;
    };
    !crate::filesystem::is_default_skip_extension(ext)
        && !BINARY_OBJECT_EXTS
            .iter()
            .any(|candidate| ext.eq_ignore_ascii_case(candidate))
}

fn cloud_key_extension(key: &str) -> Option<&str> {
    let file_name = key.rsplit('/').next().unwrap_or(key); // LAW10: object key has no slash => whole key is the filename segment, recall-safe
    let (stem, ext) = file_name.rsplit_once('.')?;
    if stem.is_empty() || ext.is_empty() {
        return None;
    }
    Some(ext)
}

pub(crate) fn is_binary_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split_once(';')
        .map_or(content_type, |(media_type, _)| media_type)
        .trim();
    starts_with_ignore_ascii_case(media_type, "image/")
        || starts_with_ignore_ascii_case(media_type, "audio/")
        || starts_with_ignore_ascii_case(media_type, "video/")
        || media_type.eq_ignore_ascii_case("application/zip")
        || media_type.eq_ignore_ascii_case("application/gzip")
}

fn is_unknown_binary_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split_once(';')
        .map_or(content_type, |(media_type, _)| media_type)
        .trim();
    media_type.eq_ignore_ascii_case("application/octet-stream")
}

fn starts_with_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

pub(crate) fn encode_object_key_path(key: &str) -> String {
    let mut encoded = String::with_capacity(key.len());
    let mut segment = String::new();
    for ch in key.chars() {
        if ch == '/' {
            encoded.push_str(&urlencoding::encode(&segment));
            encoded.push('/');
            segment.clear();
        } else {
            segment.push(ch);
        }
    }
    encoded.push_str(&urlencoding::encode(&segment));
    encoded
}

pub(crate) fn contains_forbidden_xml_markup(body: &str) -> bool {
    let upper = body.to_ascii_uppercase();
    upper.contains("<!DOCTYPE") || upper.contains("<!ENTITY")
}

pub(crate) fn record_source_truncated_once(
    source: &str,
    reason: &str,
    reported: &mut bool,
) -> Option<keyhog_core::SourceError> {
    if *reported {
        return None;
    }
    *reported = true;
    tracing::warn!(
        source,
        reason,
        "cloud source listing ended before every matching object was covered; remaining objects were NOT scanned"
    );
    let _event = crate::record_skip_event(crate::SourceSkipEvent::SourceTruncated);
    Some(keyhog_core::SourceError::Other(format!(
        "{source} source scan was truncated: {reason}; remaining objects were not scanned"
    )))
}
