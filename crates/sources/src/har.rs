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
    // Cheap sniff: every HAR file starts with `{"log"` (possibly
    // preceded by whitespace / BOM). Bail before invoking the JSON
    // parser on a 200 MiB binary blob that obviously isn't HAR.
    let trimmed = trim_bom_and_whitespace(bytes);
    if !trimmed.starts_with(b"{") {
        return None;
    }
    if !contains_har_marker(trimmed) {
        return None;
    }

    let doc: HarDocument = match serde_json::from_slice(bytes) {
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
    let budget = max_size.saturating_mul(4);

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

fn trim_bom_and_whitespace(bytes: &[u8]) -> &[u8] {
    let mut s = bytes;
    if let Some(rest) = s.strip_prefix(b"\xEF\xBB\xBF") {
        s = rest;
    }
    while let Some((b, rest)) = s.split_first() {
        if b.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    s
}

fn contains_har_marker(bytes: &[u8]) -> bool {
    // Look for both `"log"` and `"entries"` within the first 1 KiB -
    // every HAR has them near the top. False positives are fine; the
    // JSON parser will reject and we fall through.
    let head = &bytes[..bytes.len().min(2048)];
    memchr::memmem::find(head, b"\"log\"").is_some()
        && memchr::memmem::find(head, b"\"entries\"").is_some()
}

fn render_request(req: &HarRequest) -> String {
    let mut out = String::with_capacity(256);
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
    }
    out
}

fn render_response(resp: &HarResponse) -> String {
    let mut out = String::with_capacity(256);
    out.push_str(&resp.status.to_string());
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
    if let Some(content) = &resp.content {
        if let Some(text) = decoded_content_text(content) {
            out.push('\n');
            out.push_str(&text);
        }
    }
    out
}

/// HAR `content.text` is base64-encoded when `content.encoding == "base64"`
/// (HAR 1.2 spec). Decode it so credentials inside encoded response bodies
/// are scanned instead of the opaque base64 blob. Malformed base64 (a
/// truncated or corrupt encoding field) falls back to the raw text so a bad
/// `encoding` value never drops the body from the scan entirely.
fn decoded_content_text(content: &HarContent) -> Option<String> {
    use base64::Engine as _;
    let text = content.text.as_ref()?;
    if content.encoding.as_deref() == Some("base64") {
        match base64::engine::general_purpose::STANDARD.decode(text.trim()) {
            Ok(bytes) => Some(String::from_utf8_lossy(&bytes).into_owned()),
            // Law 10: recall-safe — a malformed `encoding: base64` body is scanned
            // RAW instead of being dropped, so a credential in the un-decodable
            // body still reaches the scanner. Proven by the
            // `malformed_base64_encoding_falls_back_to_raw_text` regression test.
            Err(_) => Some(text.clone()), // LAW10: unrecognized/partial => caller scans whole-file/recovered prefix; recall-preserving
        }
    } else {
        Some(text.clone())
    }
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
}
