use keyhog_core::{Chunk, SourceError};
use reqwest::blocking::{Client, Response};

#[cfg(feature = "azure")]
pub(crate) mod azure_blob;

pub(crate) use crate::blocking_thread::collect_on_blocking_thread;

pub(crate) const DEFAULT_GCS_ENDPOINT: &str = "https://storage.googleapis.com";
pub(crate) const DEFAULT_S3_HOST_SUFFIX: &str = "s3.amazonaws.com";
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

/// Normalize an object-listing continuation cursor: a token that is absent,
/// empty, or only whitespace means the listing is exhausted, so it returns
/// `None`.
///
/// Every cloud lister (S3 `NextContinuationToken`, GCS `nextPageToken`, Azure
/// `NextMarker`) paginates by re-requesting with the previous page's cursor and
/// stops when there is no cursor. An *empty* cursor is not a valid "next page"
/// pointer — re-requesting with it restarts the listing from the first page,
/// which re-downloads the same objects (duplicate chunks, wasted bandwidth, and,
/// with an unbounded `max_objects`, a non-terminating loop). Azure's protocol
/// deliberately returns an empty `<NextMarker/>` element on the final page; some
/// S3-compatible and self-hosted GCS/S3 endpoints likewise echo an empty cursor.
/// Routing every cursor through here makes "empty cursor == done" one rule
/// across all three backends, with the trimmed token borrowed from the input.
pub(crate) fn meaningful_continuation_token(token: Option<&str>) -> Option<&str> {
    token.map(str::trim).filter(|value| !value.is_empty())
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

pub(crate) fn record_unreadable_listing_skip(
    source: &str,
    item_plural: &str,
    reason: impl std::fmt::Display,
) -> SourceError {
    let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
    SourceError::Other(format!(
        "{source} source listing failed: {reason}; {item_plural} were not scanned"
    ))
}

pub(crate) fn record_oversized_listing_skip(
    source: &str,
    item_plural: &str,
    reason: impl std::fmt::Display,
) -> SourceError {
    let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
    SourceError::Other(format!(
        "{source} source listing failed: {reason}; {item_plural} were not scanned"
    ))
}

pub(crate) fn read_listing_response_body(
    response: Response,
    source: &str,
    item_plural: &str,
    max_response_bytes: usize,
) -> Result<String, SourceError> {
    let max_response_bytes_u64 = match u64::try_from(max_response_bytes) {
        Ok(value) => value,
        Err(_) => u64::MAX, // LAW10: unreachable on real platforms — only a usize wider than u64 takes this arm, where reqwest content lengths and Read::take caps are u64-bounded, so every representable HTTP body length is still capped.
    };
    if let Some(content_length) = response.content_length() {
        if content_length > max_response_bytes_u64 {
            return Err(record_oversized_listing_skip(
                source,
                item_plural,
                format!(
                    "listing response Content-Length {content_length} exceeds the web_response_bytes cap {max_response_bytes}"
                ),
            ));
        }
    }

    let capacity_hint = response
        .content_length()
        .map(|len| len.min(max_response_bytes_u64).min(64 * 1024));
    let read = crate::capped_read::read_to_cap(response, max_response_bytes_u64, capacity_hint)
        .map_err(|error| {
            record_unreadable_listing_skip(
                source,
                item_plural,
                format!("failed to read listing response body: {error}"),
            )
        })?;
    if read.truncated {
        return Err(record_oversized_listing_skip(
            source,
            item_plural,
            format!(
                "streamed listing response body exceeded the web_response_bytes cap {max_response_bytes}"
            ),
        ));
    }
    String::from_utf8(read.bytes).map_err(|error| {
        let valid_up_to = error.utf8_error().valid_up_to();
        record_unreadable_listing_skip(
            source,
            item_plural,
            format!("listing response body failed UTF-8 decode at byte {valid_up_to}"),
        )
    })
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

    let capacity_hint = match response.content_length() {
        Some(len) => len.min(ctx.max_bytes).min(64 * 1024) as usize,
        None => 0,
    };
    let read = crate::capped_read::read_to_cap(response, ctx.max_bytes, Some(capacity_hint as u64))
        .map_err(|error| {
            record_unreadable_object_skip(
                ctx.source,
                ctx.item_kind,
                &ctx.display_path,
                format!("failed to read body for {}: {error}", ctx.item_name),
            )
        })?;
    if read.truncated {
        let downloaded = ctx.max_bytes.saturating_add(1);
        tracing::warn!(
            source = ctx.source,
            key = ctx.item_name,
            downloaded,
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
                ctx.max_bytes, downloaded
            ),
        ));
    }
    let body = read.bytes;

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

/// Extract the bare media type from a `Content-Type` header value: the text
/// before the first `;` (dropping any `charset=`/`boundary=` parameters), with
/// surrounding whitespace trimmed. Single owner so every content-type
/// classifier (cloud binary/unknown checks here, the web-response router in
/// `crate::web`) splits the header the same way.
pub(crate) fn media_type(content_type: &str) -> &str {
    content_type
        .split_once(';')
        .map_or(content_type, |(media_type, _)| media_type)
        .trim()
}

pub(crate) fn is_binary_content_type(content_type: &str) -> bool {
    let media_type = media_type(content_type);
    starts_with_ignore_ascii_case(media_type, "image/")
        || starts_with_ignore_ascii_case(media_type, "audio/")
        || starts_with_ignore_ascii_case(media_type, "video/")
        || media_type.eq_ignore_ascii_case("application/zip")
        || media_type.eq_ignore_ascii_case("application/gzip")
}

fn is_unknown_binary_content_type(content_type: &str) -> bool {
    media_type(content_type).eq_ignore_ascii_case("application/octet-stream")
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

#[cfg(test)]
mod media_type_tests {
    use super::{is_binary_content_type, media_type};

    #[test]
    fn strips_parameters_and_trims() {
        assert_eq!(media_type("text/plain; charset=utf-8"), "text/plain");
        assert_eq!(media_type("  application/json  "), "application/json");
        assert_eq!(
            media_type("image/png ; boundary=abc ; q=1"),
            "image/png"
        );
    }

    #[test]
    fn bare_media_type_passes_through() {
        assert_eq!(media_type("application/octet-stream"), "application/octet-stream");
        assert_eq!(media_type(""), "");
    }

    #[test]
    fn binary_check_uses_the_shared_extractor() {
        // A parameterized image type must be recognized as binary via the same
        // single split rule the router uses.
        assert!(is_binary_content_type("image/jpeg; charset=binary"));
        assert!(!is_binary_content_type("text/plain; charset=utf-8"));
    }
}

#[cfg(test)]
mod continuation_token_tests {
    use super::meaningful_continuation_token;

    // --- meaningful tokens (carry to the next page; surrounding ws trimmed) ---

    #[test]
    fn plain_token_passes_through() {
        assert_eq!(
            meaningful_continuation_token(Some("token123")),
            Some("token123")
        );
    }

    #[test]
    fn realistic_s3_continuation_token_unchanged() {
        let token = "1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/2qGn8B3kE6w=";
        assert_eq!(meaningful_continuation_token(Some(token)), Some(token));
    }

    #[test]
    fn realistic_gcs_page_token_unchanged() {
        let token = "ChhvYmplY3QtMDAwMS5qc29uLWtleS1uZXh0";
        assert_eq!(meaningful_continuation_token(Some(token)), Some(token));
    }

    #[test]
    fn single_character_token_is_meaningful() {
        assert_eq!(meaningful_continuation_token(Some("a")), Some("a"));
    }

    #[test]
    fn zero_string_is_a_valid_token_not_empty() {
        assert_eq!(meaningful_continuation_token(Some("0")), Some("0"));
    }

    #[test]
    fn internal_space_is_preserved() {
        assert_eq!(meaningful_continuation_token(Some("a b")), Some("a b"));
    }

    #[test]
    fn base64_padding_equals_are_not_stripped() {
        assert_eq!(
            meaningful_continuation_token(Some("==abc==")),
            Some("==abc==")
        );
    }

    #[test]
    fn leading_whitespace_is_trimmed() {
        assert_eq!(
            meaningful_continuation_token(Some("  token")),
            Some("token")
        );
    }

    #[test]
    fn trailing_whitespace_is_trimmed() {
        assert_eq!(
            meaningful_continuation_token(Some("token  ")),
            Some("token")
        );
    }

    #[test]
    fn surrounding_whitespace_is_trimmed_internal_kept() {
        assert_eq!(
            meaningful_continuation_token(Some("  a\tb  ")),
            Some("a\tb")
        );
    }

    #[test]
    fn nbsp_padded_token_trims_to_value() {
        assert_eq!(
            meaningful_continuation_token(Some("\u{00A0}tok\u{00A0}")),
            Some("tok")
        );
    }

    // --- exhausted cursors (no next page) ---

    #[test]
    fn none_is_exhausted() {
        assert_eq!(meaningful_continuation_token(None), None);
    }

    #[test]
    fn empty_string_is_exhausted() {
        assert_eq!(meaningful_continuation_token(Some("")), None);
    }

    #[test]
    fn single_space_is_exhausted() {
        assert_eq!(meaningful_continuation_token(Some(" ")), None);
    }

    #[test]
    fn multiple_spaces_are_exhausted() {
        assert_eq!(meaningful_continuation_token(Some("     ")), None);
    }

    #[test]
    fn tab_only_is_exhausted() {
        assert_eq!(meaningful_continuation_token(Some("\t")), None);
    }

    #[test]
    fn newline_only_is_exhausted() {
        assert_eq!(meaningful_continuation_token(Some("\n")), None);
    }

    #[test]
    fn carriage_return_newline_is_exhausted() {
        assert_eq!(meaningful_continuation_token(Some("\r\n")), None);
    }

    #[test]
    fn mixed_ascii_whitespace_is_exhausted() {
        assert_eq!(meaningful_continuation_token(Some(" \t\n \r ")), None);
    }

    #[test]
    fn unicode_no_break_space_is_exhausted() {
        // Azure's empty <NextMarker/> can arrive as a stray NBSP through some
        // proxies; str::trim treats U+00A0 as whitespace, so it is exhausted.
        assert_eq!(meaningful_continuation_token(Some("\u{00A0}")), None);
    }

    #[test]
    fn unicode_ideographic_space_is_exhausted() {
        assert_eq!(meaningful_continuation_token(Some("\u{3000}")), None);
    }

    #[test]
    fn unicode_line_separator_is_exhausted() {
        assert_eq!(meaningful_continuation_token(Some("\u{2028}")), None);
    }
}
