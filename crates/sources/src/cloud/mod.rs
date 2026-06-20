use std::path::Path;

#[cfg(feature = "azure")]
pub(crate) mod azure_blob;

pub(crate) const OBJECT_FETCH_THREADS: usize = 16;

pub(crate) fn object_fetch_pool(
    source: &str,
) -> Result<rayon::ThreadPool, keyhog_core::SourceError> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(OBJECT_FETCH_THREADS)
        .build()
        .map_err(|error| {
            keyhog_core::SourceError::Other(format!("{source}: rayon pool build: {error}"))
        })
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
