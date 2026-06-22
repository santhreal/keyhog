use std::path::Path;

use keyhog_core::SourceError;
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
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        return Err(SourceError::Other(format!(
            "failed to scan {} {}: GET returned {status}; {} was not scanned",
            ctx.source, ctx.display_path, ctx.item_kind
        )));
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
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
            return Ok(None);
        }
    }

    let initial_capacity = match response.content_length() {
        Some(len) => len.min(ctx.max_bytes).min(64 * 1024) as usize,
        None => 0,
    };
    let mut body = Vec::with_capacity(initial_capacity);
    let mut reader = response.take(ctx.max_bytes + 1);
    Read::read_to_end(&mut reader, &mut body).map_err(|error| {
        SourceError::Other(format!(
            "failed to read {} body: {}: {error}",
            ctx.source, ctx.item_name
        ))
    })?;
    if body.len() as u64 > ctx.max_bytes {
        tracing::warn!(
            source = ctx.source,
            key = ctx.item_name,
            downloaded = body.len(),
            cap = ctx.max_bytes,
            "skipping cloud object: streamed body exceeds the per-object byte cap; NOT scanned",
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        return Ok(None);
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
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            Err(SourceError::Other(format!(
                "failed to scan {} {}: body failed UTF-8 decode at byte {valid_up_to}; {} was not scanned",
                ctx.source, ctx.display_path, ctx.item_kind
            )))
        }
    }
}

pub(crate) fn is_probably_text_object_key(key: &str) -> bool {
    let ext = Path::new(key)
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());

    !matches!(
        ext.as_deref(),
        Some(
            "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "webp"
                | "zip"
                | "gz"
                | "tgz"
                | "tar"
                | "7z"
                | "pdf"
                | "woff"
                | "woff2"
                | "mp3"
                | "mp4"
                | "mov"
                | "dll"
                | "so"
                | "dylib"
        )
    )
}

pub(crate) fn is_binary_content_type(content_type: &str) -> bool {
    let lower = content_type.to_ascii_lowercase();
    lower.starts_with("image/")
        || lower.starts_with("audio/")
        || lower.starts_with("video/")
        || lower == "application/octet-stream"
        || lower == "application/zip"
        || lower == "application/gzip"
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
