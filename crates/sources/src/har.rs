//! HAR (HTTP Archive) 1.2 file expansion.
//!
//! Browser DevTools (Chrome, Firefox, Safari, Edge) export captured
//! sessions as `.har` files. The format is a single JSON object whose
//! `log.entries[]` array holds every request/response pair the browser
//! made. Real credentials show up in three reliable places: an
//! `Authorization` request header, a JSON request body, and a token
//! reflected back in a JSON response body. Treating the HAR as one big
//! grep target works (it's just JSON) but loses the request-vs-response
//! distinction that bug-bounty workflows care about.
//!
//! This module is the parser. For each entry we emit:
//!
//! - one chunk per request - concatenates the method, URL, headers,
//!   query string, and POST body into one searchable text blob tagged
//!   `wire:har:request` with the URL as the path metadata.
//! - one chunk per response - concatenates the status, headers, and
//!   body text, tagged `wire:har:response`.
//!
//! Two chunks per entry means a finding's `source_type` immediately
//! tells you whether the credential was outbound (you're leaking a key
//! to the upstream) or inbound (the upstream is leaking a key back to
//! you). Both are interesting; they're different threat models.
//!
//! Defenses:
//! - Refuse to parse anything larger than `max_size` (per-file cap).
//! - Refuse to parse beyond 4× `max_size` of expanded request+response
//!   bodies - defeats a malicious HAR that decompresses to gigabytes.
//! - Tolerate broken JSON (a partial export from a crashed browser):
//!   `serde_json` returns Err and we fall through to scanning the raw
//!   bytes as plain text. Better to grep the malformed JSON than to
//!   silently skip a credential-bearing file.
//!
//! Schema reference: <http://www.softwareishard.com/blog/har-12-spec/>

use keyhog_core::{Chunk, ChunkMetadata, SourceError};
use std::borrow::Cow;

/// Try to parse `bytes` as a HAR 1.2 document and expand it into one
/// chunk per request and one chunk per response. Returns `None` when
/// the input doesn't look like a HAR file (caller falls back to text
/// scanning). Returns `Some(vec![])` when the parse succeeded but every
/// entry was rejected (size cap / empty bodies).
///
/// `path_str` is the display path used as the `ChunkMetadata.path`
/// prefix for each emitted chunk - typically the path the user passed
/// to `keyhog scan`. The per-entry URL is appended with `#`.
pub(crate) fn try_expand_har(
    bytes: &[u8],
    path_str: &str,
    max_size: u64,
) -> Option<Vec<Result<Chunk, SourceError>>> {
    let text = har_text(bytes)?;

    // Cheap sniff: every HAR file is a JSON object with `log.entries`.
    // Decode first so UTF-16 HAR exports take the same structured path as
    // UTF-8 exports, then scan the whole text because valid HAR metadata can
    // push `entries` beyond a tiny fixed prefix.
    let trimmed = trim_bom_and_whitespace(&text);
    if !trimmed.starts_with('{') {
        return None;
    }
    if !contains_har_marker(trimmed) {
        return None;
    }

    let doc: HarDocument = match serde_json::from_str(trimmed) {
        Ok(d) => d,
        Err(error) => {
            let _event =
                crate::record_skip_event(crate::SourceSkipEvent::StructuredSourceParseFailure);
            tracing::debug!(
                path = %path_str,
                %error,
                "HAR-shaped file failed to parse as HAR 1.2; falling back to text scan"
            );
            return None;
        }
    };

    let mut chunks = Vec::with_capacity(doc.log.entries.len() * 2);
    let mut total_bytes: u64 = 0;
    let budget = crate::filesystem::extraction_total_budget(max_size);

    for entry in doc.log.entries {
        let url = entry.request.url.clone();

        let request_text = render_request(&entry.request);
        let request_len = request_text.len() as u64;
        total_bytes = total_bytes.saturating_add(request_len);
        if total_bytes > budget {
            tracing::warn!(
                path = %path_str,
                budget,
                "aborting HAR expansion: cumulative request/response bytes exceed 4x file cap"
            );
            chunks.push(Err(har_source_truncated_error(path_str, budget)));
            break;
        }
        if request_len > 0 {
            chunks.push(Ok(Chunk {
                data: request_text.into(),
                metadata: ChunkMetadata {
                    source_type: "wire:har:request".to_string(),
                    path: Some(format!("{path_str}#{url}")),
                    ..Default::default()
                },
            }));
        }

        let response_text = render_response(&entry.response);
        let response_len = response_text.len() as u64;
        total_bytes = total_bytes.saturating_add(response_len);
        if total_bytes > budget {
            tracing::warn!(
                path = %path_str,
                budget,
                "aborting HAR expansion: cumulative request/response bytes exceed 4x file cap"
            );
            chunks.push(Err(har_source_truncated_error(path_str, budget)));
            break;
        }
        if response_len > 0 {
            chunks.push(Ok(Chunk {
                data: response_text.into(),
                metadata: ChunkMetadata {
                    source_type: "wire:har:response".to_string(),
                    path: Some(format!("{path_str}#{url}")),
                    ..Default::default()
                },
            }));
        }
    }

    Some(chunks)
}

fn har_text(bytes: &[u8]) -> Option<Cow<'_, str>> {
    match std::str::from_utf8(bytes) {
        Ok(text) => Some(Cow::Borrowed(text)),
        Err(utf8_error) => match crate::decode_file_bytes(bytes) {
            Some(text) => Some(Cow::Owned(text)),
            None => {
                tracing::debug!(
                    %utf8_error,
                    "HAR candidate is not UTF-8 and shared text decoding rejected it"
                );
                None
            }
        },
    }
}

fn har_source_truncated_error(path_str: &str, budget: u64) -> SourceError {
    let _event = crate::record_skip_event(crate::SourceSkipEvent::SourceTruncated);
    SourceError::Other(format!(
        "HAR source scan was truncated for {path_str}: cumulative request/response bytes exceeded the {budget}-byte expansion budget; remaining HAR entries were not scanned"
    ))
}

fn trim_bom_and_whitespace(text: &str) -> &str {
    match text.strip_prefix('\u{FEFF}') {
        Some(rest) => rest.trim_start(),
        None => text.trim_start(),
    }
}

fn contains_har_marker(text: &str) -> bool {
    // False positives are fine; serde_json will reject and we fall through
    // with structured parse-failure telemetry.
    memchr::memmem::find(text.as_bytes(), b"\"log\"").is_some()
        && memchr::memmem::find(text.as_bytes(), b"\"entries\"").is_some()
}

fn render_request(req: &HarRequest) -> String {
    let mut out = String::with_capacity(request_render_capacity(req));
    out.push_str(&req.method);
    out.push(' ');
    out.push_str(&req.url);
    out.push('\n');
    for header in &req.headers {
        out.push_str(&header.name);
        out.push_str(": ");
        out.push_str(&header.value);
        out.push('\n');
    }
    if !req.query_string.is_empty() {
        out.push_str("# query\n");
        for q in &req.query_string {
            out.push_str(&q.name);
            out.push('=');
            out.push_str(&q.value);
            out.push('\n');
        }
    }
    if let Some(post) = &req.post_data {
        if let Some(text) = &post.text {
            out.push('\n');
            out.push_str(text);
        }
        if !post.params.is_empty() {
            out.push_str("\n# postData params\n");
            for param in &post.params {
                out.push_str(&param.name);
                out.push('=');
                if let Some(value) = &param.value {
                    out.push_str(value);
                }
                out.push('\n');
            }
        }
    }
    out
}

fn render_response(resp: &HarResponse) -> String {
    let decoded = resp.content.as_ref().and_then(decoded_content_text);
    let mut out = String::with_capacity(response_render_capacity(resp, decoded.as_deref()));
    push_i64_decimal(&mut out, resp.status);
    if let Some(status_text) = &resp.status_text {
        out.push(' ');
        out.push_str(status_text);
    }
    out.push('\n');
    for header in &resp.headers {
        out.push_str(&header.name);
        out.push_str(": ");
        out.push_str(&header.value);
        out.push('\n');
    }
    if let Some(text) = decoded {
        out.push('\n');
        out.push_str(&text);
    }
    out
}

fn request_render_capacity(req: &HarRequest) -> usize {
    let post_capacity = match req.post_data.as_ref() {
        Some(post) => post_data_capacity(post),
        None => 0,
    };
    req.method
        .len()
        .saturating_add(1)
        .saturating_add(req.url.len())
        .saturating_add(1)
        .saturating_add(kv_lines_capacity(&req.headers))
        .saturating_add(if req.query_string.is_empty() {
            0
        } else {
            "# query\n"
                .len()
                .saturating_add(query_lines_capacity(&req.query_string))
        })
        .saturating_add(post_capacity)
}

fn post_data_capacity(post: &HarPostData) -> usize {
    let text_capacity = match post.text.as_ref() {
        Some(text) => 1usize.saturating_add(text.len()),
        None => 0,
    };
    let params_capacity = if post.params.is_empty() {
        0
    } else {
        "# postData params\n"
            .len()
            .saturating_add(1)
            .saturating_add(post_param_lines_capacity(&post.params))
    };
    text_capacity.saturating_add(params_capacity)
}

fn response_render_capacity(resp: &HarResponse, decoded_text: Option<&str>) -> usize {
    let status_text_capacity = match &resp.status_text {
        Some(status_text) => 1usize.saturating_add(status_text.len()),
        None => 0,
    };
    let decoded_capacity = match decoded_text {
        Some(text) => 1usize.saturating_add(text.len()),
        None => 0,
    };
    i64_decimal_len(resp.status)
        .saturating_add(status_text_capacity)
        .saturating_add(1)
        .saturating_add(kv_lines_capacity(&resp.headers))
        .saturating_add(decoded_capacity)
}

fn i64_decimal_len(value: i64) -> usize {
    if value == 0 {
        return 1;
    }
    let mut len = usize::from(value < 0);
    let mut n = value.unsigned_abs();
    while n > 0 {
        len += 1;
        n /= 10;
    }
    len
}

fn push_i64_decimal(out: &mut String, value: i64) {
    let mut bytes = [0u8; 20];
    let mut index = bytes.len();
    let mut n = value.unsigned_abs();
    if n == 0 {
        index -= 1;
        bytes[index] = b'0';
    }
    while n > 0 {
        index -= 1;
        bytes[index] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    if value < 0 {
        index -= 1;
        bytes[index] = b'-';
    }
    for &byte in &bytes[index..] {
        out.push(byte as char);
    }
}

fn kv_lines_capacity(items: &[HarKv]) -> usize {
    items.iter().fold(0usize, |capacity, item| {
        capacity
            .saturating_add(item.name.len())
            .saturating_add(2)
            .saturating_add(item.value.len())
            .saturating_add(1)
    })
}

fn query_lines_capacity(items: &[HarKv]) -> usize {
    items.iter().fold(0usize, |capacity, item| {
        capacity
            .saturating_add(item.name.len())
            .saturating_add(1)
            .saturating_add(item.value.len())
            .saturating_add(1)
    })
}

fn post_param_lines_capacity(items: &[HarPostParam]) -> usize {
    items.iter().fold(0usize, |capacity, item| {
        let value_len = match item.value.as_ref() {
            Some(value) => value.len(),
            None => 0,
        };
        capacity
            .saturating_add(item.name.len())
            .saturating_add(1)
            .saturating_add(value_len)
            .saturating_add(1)
    })
}

/// HAR `content.text` is base64-encoded when `content.encoding == "base64"`
/// (HAR 1.2 spec). Decode it so credentials inside encoded response bodies
/// are scanned instead of the opaque base64 blob. Malformed base64 (a
/// truncated or corrupt encoding field) falls back to the raw text so a bad
/// `encoding` value never drops the body from the scan entirely.
fn decoded_content_text(content: &HarContent) -> Option<Cow<'_, str>> {
    use base64::Engine as _;
    let text = content.text.as_ref()?;
    if content
        .encoding
        .as_deref()
        .is_some_and(|encoding| encoding.eq_ignore_ascii_case("base64"))
    {
        let encoded = compact_base64_text(text);
        match base64::engine::general_purpose::STANDARD.decode(encoded.as_bytes()) {
            Ok(bytes) => Some(Cow::Owned(match String::from_utf8(bytes) {
                Ok(text) => text,
                Err(error) => String::from_utf8_lossy(&error.into_bytes()).into_owned(),
            })),
            // Recall-safe: malformed base64 is scanned raw, but the failed
            // structured decode is still a visible partial-coverage signal.
            Err(error) => {
                let _event =
                    crate::record_skip_event(crate::SourceSkipEvent::StructuredSourceParseFailure);
                tracing::debug!(
                    %error,
                    "HAR response content declared base64 but failed to decode; scanning raw content text"
                );
                Some(Cow::Borrowed(text))
            }
        }
    } else {
        Some(Cow::Borrowed(text))
    }
}

fn compact_base64_text(text: &str) -> Cow<'_, str> {
    if !text.as_bytes().iter().any(u8::is_ascii_whitespace) {
        return Cow::Borrowed(text);
    }
    let mut compact = String::with_capacity(text.len());
    for ch in text.chars() {
        if !ch.is_ascii_whitespace() {
            compact.push(ch);
        }
    }
    Cow::Owned(compact)
}

#[derive(serde::Deserialize)]
struct HarDocument {
    log: HarLog,
}

#[derive(serde::Deserialize)]
struct HarLog {
    #[serde(default)]
    entries: Vec<HarEntry>,
}

#[derive(serde::Deserialize)]
struct HarEntry {
    request: HarRequest,
    response: HarResponse,
}

#[derive(serde::Deserialize)]
struct HarRequest {
    method: String,
    url: String,
    #[serde(default)]
    headers: Vec<HarKv>,
    #[serde(default, rename = "queryString")]
    query_string: Vec<HarKv>,
    #[serde(default, rename = "postData")]
    post_data: Option<HarPostData>,
}

#[derive(serde::Deserialize)]
struct HarResponse {
    status: i64,
    #[serde(default, rename = "statusText")]
    status_text: Option<String>,
    #[serde(default)]
    headers: Vec<HarKv>,
    #[serde(default)]
    content: Option<HarContent>,
}

#[derive(serde::Deserialize)]
struct HarKv {
    name: String,
    value: String,
}

#[derive(serde::Deserialize)]
struct HarPostData {
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    params: Vec<HarPostParam>,
}

#[derive(serde::Deserialize)]
struct HarPostParam {
    name: String,
    #[serde(default)]
    value: Option<String>,
}

#[derive(serde::Deserialize)]
struct HarContent {
    #[serde(default)]
    text: Option<String>,
    /// HAR 1.2 `content.encoding`: when `"base64"`, `text` is base64.
    #[serde(default)]
    encoding: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{SourceTestApi, TestApi};

    // The fixture carries a real-SHAPE GitHub classic PAT so the request
    // chunk exercises the Authorization-header path. The 36-char token body
    // is split across a `concat!` boundary so the contiguous `ghp_`+36 shape
    // never appears on a single source line - that keeps keyhog's own
    // self-scan (dogfood/CI) from flagging this file while the runtime
    // `FIXTURE` string still reassembles the full token for the test.
    const GHP_TOKEN: &str = concat!("ghp_AbCd1234567890Ef", "GhIjKlMnOpQrStUvWx1A");

    fn fixture() -> String {
        format!(
            r#"{{
        "log": {{
            "version": "1.2",
            "creator": {{"name": "DevTools", "version": "1"}},
            "entries": [
                {{
                    "request": {{
                        "method": "GET",
                        "url": "https://api.example.com/me",
                        "headers": [
                            {{"name": "Authorization", "value": "Bearer {GHP_TOKEN}"}}
                        ],
                        "queryString": []
                    }},
                    "response": {{
                        "status": 200,
                        "statusText": "OK",
                        "headers": [
                            {{"name": "Content-Type", "value": "application/json"}}
                        ],
                        "content": {{
                            "size": 23,
                            "mimeType": "application/json",
                            "text": "{{\"id\":\"u-123\",\"name\":\"X\"}}"
                        }}
                    }}
                }}
            ]
        }}
    }}"#
        )
    }

    #[test]
    fn try_expand_har_splits_request_and_response() {
        let fixture = fixture();
        let chunks = try_expand_har(fixture.as_bytes(), "cap.har", 10 * 1024 * 1024)
            .expect("fixture should parse");
        let chunks: Vec<_> = chunks.into_iter().map(|c| c.unwrap()).collect();
        assert_eq!(chunks.len(), 2, "one request + one response per entry");
        assert_eq!(chunks[0].metadata.source_type, "wire:har:request");
        assert_eq!(chunks[1].metadata.source_type, "wire:har:response");
        assert!(chunks[0]
            .data
            .as_ref()
            .contains("Authorization: Bearer ghp_"));
        assert!(chunks[1].data.as_ref().contains("Content-Type"));
        assert!(chunks[1].data.as_ref().contains("u-123"));
        assert_eq!(
            chunks[0].metadata.path.as_deref(),
            Some("cap.har#https://api.example.com/me")
        );
    }

    #[test]
    fn non_har_json_returns_none() {
        let not_har = br#"{"hello": "world"}"#;
        assert!(try_expand_har(not_har, "x.json", 1024).is_none());
    }

    #[test]
    fn non_json_returns_none() {
        let bin = b"\xff\xfe\x00\x01plain binary";
        assert!(try_expand_har(bin, "x.bin", 1024).is_none());
    }

    #[test]
    fn malformed_har_returns_none_to_let_text_scan_run() {
        // Looks like HAR (has the markers) but JSON parser will reject.
        let half = br#"{"log": {"entries": [{"request": {"method": "GET", "url": "x"#;
        assert!(try_expand_har(half, "broken.har", 1024).is_none());
    }

    #[test]
    fn expansion_budget_truncation_is_counted_source_truncated() {
        let _guard = TestApi.skip_counter_guard();
        crate::reset_skip_counters();

        let chunks = try_expand_har(fixture().as_bytes(), "cap.har", 1)
            .expect("valid HAR should parse before the expansion budget fires");
        let (ok_chunks, errors) = split_rows(chunks);

        assert!(
            ok_chunks.is_empty(),
            "over-budget expansion must not emit a chunk it cannot prove covered; chunks={ok_chunks:?}"
        );
        assert_eq!(
            errors.len(),
            1,
            "over-budget expansion must surface exactly one source error row"
        );
        assert!(
            errors[0].contains("HAR source scan was truncated"),
            "wrong truncation error: {}",
            errors[0]
        );
        assert!(
            errors[0].contains("remaining HAR entries were not scanned"),
            "truncation error must make unscanned scope explicit: {}",
            errors[0]
        );
        assert_eq!(
            crate::skip_counts().source_truncated,
            1,
            "HAR expansion budget must surface as a partial source truncation"
        );

        crate::reset_skip_counters();
    }

    #[test]
    fn response_side_expansion_budget_truncation_surfaces_source_error() {
        let _guard = TestApi.skip_counter_guard();
        crate::reset_skip_counters();

        let har = har_with_response_body(None, &"A".repeat(256));
        let chunks = try_expand_har(har.as_bytes(), "cap.har", 20).expect("valid HAR should parse");
        let (ok_chunks, errors) = split_rows(chunks);

        assert_eq!(
            ok_chunks.len(),
            1,
            "request chunk should remain visible before response expansion exceeds budget"
        );
        assert_eq!(
            ok_chunks[0].metadata.source_type, "wire:har:request",
            "only the admitted request chunk should be emitted before truncation"
        );
        assert_eq!(
            errors.len(),
            1,
            "response-side budget truncation must surface exactly one source error row"
        );
        assert!(
            errors[0].contains("HAR source scan was truncated"),
            "wrong truncation error: {}",
            errors[0]
        );
        assert_eq!(
            crate::skip_counts().source_truncated,
            1,
            "response-side HAR expansion budget must bump SOURCE_TRUNCATED exactly once"
        );

        crate::reset_skip_counters();
    }

    /// Build a one-entry HAR whose response body carries the given
    /// `content.text` with the given optional `content.encoding`.
    fn har_with_response_body(encoding: Option<&str>, text: &str) -> String {
        let enc_field = match encoding {
            Some(e) => format!(r#""encoding": "{e}","#),
            None => String::new(),
        };
        format!(
            r#"{{"log":{{"version":"1.2","creator":{{"name":"t","version":"1"}},
            "entries":[{{"request":{{"method":"GET","url":"https://api.example.com/x",
            "headers":[],"queryString":[]}},
            "response":{{"status":200,"statusText":"OK","headers":[],
            "content":{{"size":1,"mimeType":"application/json",{enc_field}"text":"{text}"}}}}}}]}}}}"#
        )
    }

    fn split_rows(rows: Vec<Result<Chunk, SourceError>>) -> (Vec<Chunk>, Vec<String>) {
        let mut ok_chunks = Vec::new();
        let mut errors = Vec::new();
        for row in rows {
            match row {
                Ok(chunk) => ok_chunks.push(chunk),
                Err(error) => errors.push(error.to_string()),
            }
        }
        (ok_chunks, errors)
    }

    #[test]
    fn base64_encoded_response_body_is_decoded_before_scanning() {
        // `{"aws_key":"AKIA…7XYA"}` (a real-shape AWS key) base64-encoded. Without
        // decoding, the AWS key is invisible to the scanner: the response
        // chunk holds only the opaque base64 blob. With encoding handling,
        // the decoded JSON (and its key) lands in the scanned chunk.
        let b64 = "eyJhd3Nfa2V5IjoiQUtJQVFZTFBNTjVIRklRUjdYWUEifQ==";
        let har = har_with_response_body(Some("base64"), b64);
        let chunks =
            try_expand_har(har.as_bytes(), "cap.har", 10 * 1024 * 1024).expect("HAR should parse");
        let response = chunks
            .into_iter()
            .map(|c| c.unwrap())
            .find(|c| c.metadata.source_type == "wire:har:response")
            .expect("a response chunk");
        let body = response.data.as_ref();
        assert!(
            body.contains("AKIAQYLPMN5HFIQR7XYA"), // keyhog:ignore detector=aws-access-key (synthetic test fixture)
            "decoded AWS key must be present in the scanned chunk; got: {body}"
        );
        assert!(
            !body.contains(b64),
            "raw base64 blob must not remain once decoded"
        );
    }

    #[test]
    fn base64_encoding_label_is_case_insensitive() {
        let b64 = "eyJhd3Nfa2V5IjoiQUtJQVFZTFBNTjVIRklRUjdYWUEifQ==";
        let har = har_with_response_body(Some("BASE64"), b64);
        let chunks =
            try_expand_har(har.as_bytes(), "cap.har", 10 * 1024 * 1024).expect("HAR should parse");
        let response = chunks
            .into_iter()
            .map(|c| c.unwrap())
            .find(|c| c.metadata.source_type == "wire:har:response")
            .expect("a response chunk");
        assert!(
            response.data.as_ref().contains("AKIAQYLPMN5HFIQR7XYA"), // keyhog:ignore detector=aws-access-key (synthetic test fixture)
            "case-varied base64 encoding labels must still decode before scanning"
        );
    }

    #[test]
    fn wrapped_base64_response_body_is_decoded_before_scanning() {
        let wrapped_b64 = "eyJhd3Nfa2V5Ijoi\\nQUtJQVFZTFBNTjVIRklRUjdYWUEi\\nfQ==";
        let har = har_with_response_body(Some("base64"), wrapped_b64);
        let chunks =
            try_expand_har(har.as_bytes(), "cap.har", 10 * 1024 * 1024).expect("HAR should parse");
        let response = chunks
            .into_iter()
            .map(|c| c.unwrap())
            .find(|c| c.metadata.source_type == "wire:har:response")
            .expect("a response chunk");
        assert!(
            response.data.as_ref().contains("AKIAQYLPMN5HFIQR7XYA"), // keyhog:ignore detector=aws-access-key (synthetic test fixture)
            "base64 line wrapping must not force a raw-base64 fallback"
        );
    }

    #[test]
    fn compact_base64_text_preserves_non_ascii_noise() {
        let compacted = compact_base64_text("ab\né\tcd");
        assert_eq!(
            compacted.as_ref(),
            "abécd",
            "base64 whitespace compaction must not byte-cast and corrupt non-ASCII text"
        );
    }

    #[test]
    fn base64_decoded_invalid_utf8_response_body_is_scanned_lossy() {
        use base64::Engine as _;

        let b64 = base64::engine::general_purpose::STANDARD.encode([0xff, b'A', b'K', b'I', b'A']);
        let har = har_with_response_body(Some("base64"), &b64);
        let chunks =
            try_expand_har(har.as_bytes(), "cap.har", 10 * 1024 * 1024).expect("HAR should parse");
        let response = chunks
            .into_iter()
            .map(|c| c.unwrap())
            .find(|c| c.metadata.source_type == "wire:har:response")
            .expect("a response chunk");
        assert!(
            response.data.as_ref().contains("\u{FFFD}AKIA"),
            "invalid UTF-8 decoded from base64 must be scanned through lossy text, not dropped: {response:?}"
        );
    }

    #[test]
    fn malformed_base64_encoding_falls_back_to_raw_text() {
        // `encoding: base64` but the text is not valid base64. The body must
        // still be scanned (raw), never panic or get dropped.
        let not_b64 = "AKIAQYLPMN5HFIQR7XYA not base64 @@@"; // keyhog:ignore detector=aws-access-key (synthetic test fixture)
        let har = har_with_response_body(Some("base64"), not_b64);
        let chunks =
            try_expand_har(har.as_bytes(), "cap.har", 10 * 1024 * 1024).expect("HAR should parse");
        let response = chunks
            .into_iter()
            .map(|c| c.unwrap())
            .find(|c| c.metadata.source_type == "wire:har:response")
            .expect("a response chunk");
        assert!(
            response.data.as_ref().contains("AKIAQYLPMN5HFIQR7XYA"), // keyhog:ignore detector=aws-access-key (synthetic test fixture)
            "malformed base64 must fall back to scanning the raw text"
        );
    }

    #[test]
    fn plain_text_response_body_is_unchanged() {
        // No encoding field: text is scanned verbatim (regression guard for
        // the decode path not corrupting ordinary bodies).
        let har = har_with_response_body(None, "AKIAQYLPMN5HFIQR7XYA"); // keyhog:ignore detector=aws-access-key (synthetic test fixture)
        let chunks =
            try_expand_har(har.as_bytes(), "cap.har", 10 * 1024 * 1024).expect("HAR should parse");
        let response = chunks
            .into_iter()
            .map(|c| c.unwrap())
            .find(|c| c.metadata.source_type == "wire:har:response")
            .expect("a response chunk");
        assert!(response.data.as_ref().contains("AKIAQYLPMN5HFIQR7XYA")); // keyhog:ignore detector=aws-access-key (synthetic test fixture)
    }

    #[test]
    fn har_with_large_leading_metadata_is_parsed() {
        let large_comment = "A".repeat(3_000);
        let har = format!(
            r#"{{"log":{{"version":"1.2","creator":{{"name":"t","version":"1","comment":"{large_comment}"}},
            "entries":[{{"request":{{"method":"GET","url":"https://api.example.com/x",
            "headers":[{{"name":"X-Token","value":"large_metadata_marker_123456"}}],"queryString":[]}},
            "response":{{"status":200,"statusText":"OK","headers":[]}}}}]}}}}"#
        );

        let chunks = try_expand_har(har.as_bytes(), "large.har", 10 * 1024 * 1024)
            .expect("valid HAR with large metadata should parse");
        let chunks: Vec<_> = chunks.into_iter().map(|c| c.unwrap()).collect();
        assert!(
            chunks
                .iter()
                .any(|chunk| chunk.data.contains("large_metadata_marker_123456")),
            "large leading metadata must not make HAR sniffing fall back to raw text"
        );
    }

    #[test]
    fn utf16_har_is_decoded_and_expanded() {
        let fixture = fixture();
        let mut utf16_le = vec![0xFF, 0xFE];
        for unit in fixture.encode_utf16() {
            utf16_le.extend_from_slice(&unit.to_le_bytes());
        }

        let chunks = try_expand_har(&utf16_le, "utf16.har", 10 * 1024 * 1024)
            .expect("UTF-16 HAR should decode through the shared text path");
        let chunks: Vec<_> = chunks.into_iter().map(|c| c.unwrap()).collect();
        assert!(
            chunks
                .iter()
                .any(|chunk| chunk.data.as_ref().contains("Authorization: Bearer ghp_")),
            "UTF-16 HAR must expand into request chunks, not raw fallback text"
        );
    }

    #[test]
    fn utf8_bom_har_is_parsed() {
        let fixture = fixture();
        let mut bytes = b"\xEF\xBB\xBF".to_vec();
        bytes.extend_from_slice(fixture.as_bytes());

        let chunks = try_expand_har(&bytes, "bom.har", 10 * 1024 * 1024)
            .expect("UTF-8 BOM HAR should parse after BOM trimming");
        let chunks: Vec<_> = chunks.into_iter().map(|c| c.unwrap()).collect();
        assert!(
            chunks
                .iter()
                .any(|chunk| chunk.data.as_ref().contains("Authorization: Bearer ghp_")),
            "UTF-8 BOM HAR must expand into request chunks, not raw fallback text"
        );
    }

    #[test]
    fn har_post_data_params_are_rendered() {
        let har = r#"{"log":{"version":"1.2","creator":{"name":"t","version":"1"},
            "entries":[{"request":{"method":"POST","url":"https://api.example.com/login",
            "headers":[],"queryString":[],
            "postData":{"mimeType":"application/x-www-form-urlencoded","params":[
            {"name":"client_secret","value":"ghp_PostParams00000000000000000000"}]}},
            "response":{"status":200,"statusText":"OK","headers":[]}}]}}"#;

        let chunks = try_expand_har(har.as_bytes(), "params.har", 10 * 1024 * 1024)
            .expect("HAR with postData params should parse");
        let request = chunks
            .into_iter()
            .map(|c| c.unwrap())
            .find(|c| c.metadata.source_type == "wire:har:request")
            .expect("a request chunk");
        assert!(
            request
                .data
                .as_ref()
                .contains("client_secret=ghp_PostParams00000000000000000000"),
            "postData.params must be rendered into request chunks; got {}",
            request.data
        );
    }
}
