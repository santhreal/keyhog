use keyhog_core::{Chunk, SourceError};
use keyhog_sources::testing::{SourceTestApi, TestApi};

// The fixture carries a real-SHAPE GitHub classic PAT so the request chunk
// exercises the Authorization-header path. The 36-char token body is split
// across a `concat!` boundary so keyhog's own dogfood scan does not see the
// contiguous shape in source text.
const GHP_TOKEN: &str = concat!("ghp_AbCd1234567890Ef", "GhIjKlMnOpQrStUvWx1A");
const AWS_TEST_KEY: &str = concat!("AKIA", "QYLPMN5HFIQR7XYA");

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

fn expand_har(
    bytes: &[u8],
    path_str: &str,
    max_size: u64,
) -> Option<Vec<Result<Chunk, SourceError>>> {
    TestApi.expand_har(bytes, path_str, max_size)
}

#[test]
fn try_expand_har_splits_request_and_response() {
    let fixture = fixture();
    let chunks =
        expand_har(fixture.as_bytes(), "cap.har", 10 * 1024 * 1024).expect("fixture should parse");
    let chunks: Vec<_> = chunks.into_iter().map(|c| c.unwrap()).collect();
    assert_eq!(chunks.len(), 2, "one request + one response per entry");
    assert_eq!(chunks[0].metadata.source_type.as_ref(), "wire:har:request");
    assert_eq!(chunks[1].metadata.source_type.as_ref(), "wire:har:response");
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
    assert!(expand_har(not_har, "x.json", 1024).is_none());
}

#[test]
fn non_json_returns_none() {
    let bin = b"\xff\xfe\x00\x01plain binary";
    assert!(expand_har(bin, "x.bin", 1024).is_none());
}

#[test]
fn malformed_har_returns_none_to_let_text_scan_run() {
    let half = br#"{"log": {"entries": [{"request": {"method": "GET", "url": "x"#;
    assert!(expand_har(half, "broken.har", 1024).is_none());
}

#[test]
fn expansion_budget_truncation_is_counted_source_truncated() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    let chunks = expand_har(fixture().as_bytes(), "cap.har", 1)
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
        keyhog_sources::skip_counts().source_truncated,
        1,
        "HAR expansion budget must surface as a partial source truncation"
    );

    TestApi.reset_skip_counters();
}

#[test]
fn response_side_expansion_budget_truncation_surfaces_source_error() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    let har = har_with_response_body(None, &"A".repeat(256));
    let chunks = expand_har(har.as_bytes(), "cap.har", 20).expect("valid HAR should parse");
    let (ok_chunks, errors) = split_rows(chunks);

    assert_eq!(
        ok_chunks.len(),
        1,
        "request chunk should remain visible before response expansion exceeds budget"
    );
    assert_eq!(
        ok_chunks[0].metadata.source_type.as_ref(),
        "wire:har:request",
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
        keyhog_sources::skip_counts().source_truncated,
        1,
        "response-side HAR expansion budget must bump SOURCE_TRUNCATED exactly once"
    );

    TestApi.reset_skip_counters();
}

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
    let b64 = "eyJhd3Nfa2V5IjoiQUtJQVFZTFBNTjVIRklRUjdYWUEifQ==";
    let har = har_with_response_body(Some("base64"), b64);
    let chunks = expand_har(har.as_bytes(), "cap.har", 10 * 1024 * 1024).expect("HAR should parse");
    let response = chunks
        .into_iter()
        .map(|c| c.unwrap())
        .find(|c| c.metadata.source_type.as_ref() == "wire:har:response")
        .expect("a response chunk");
    let body = response.data.as_ref();
    assert!(
        body.contains(AWS_TEST_KEY),
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
    let chunks = expand_har(har.as_bytes(), "cap.har", 10 * 1024 * 1024).expect("HAR should parse");
    let response = chunks
        .into_iter()
        .map(|c| c.unwrap())
        .find(|c| c.metadata.source_type.as_ref() == "wire:har:response")
        .expect("a response chunk");
    assert!(
        response.data.as_ref().contains(AWS_TEST_KEY),
        "case-varied base64 encoding labels must still decode before scanning"
    );
}

#[test]
fn wrapped_base64_response_body_is_decoded_before_scanning() {
    let wrapped_b64 = "eyJhd3Nfa2V5Ijoi\\nQUtJQVFZTFBNTjVIRklRUjdYWUEi\\nfQ==";
    let har = har_with_response_body(Some("base64"), wrapped_b64);
    let chunks = expand_har(har.as_bytes(), "cap.har", 10 * 1024 * 1024).expect("HAR should parse");
    let response = chunks
        .into_iter()
        .map(|c| c.unwrap())
        .find(|c| c.metadata.source_type.as_ref() == "wire:har:response")
        .expect("a response chunk");
    assert!(
        response.data.as_ref().contains(AWS_TEST_KEY),
        "base64 line wrapping must not force a raw-base64 fallback"
    );
}

#[test]
fn compact_base64_text_preserves_non_ascii_noise() {
    let compacted = TestApi.compact_har_base64_text("ab\né\tcd");
    assert_eq!(
        compacted.as_str(),
        "abécd",
        "base64 whitespace compaction must not byte-cast and corrupt non-ASCII text"
    );
}

#[test]
fn base64_decoded_invalid_utf8_response_body_is_scanned_lossy() {
    use base64::Engine as _;

    let b64 = base64::engine::general_purpose::STANDARD.encode([0xff, b'A', b'K', b'I', b'A']);
    let har = har_with_response_body(Some("base64"), &b64);
    let chunks = expand_har(har.as_bytes(), "cap.har", 10 * 1024 * 1024).expect("HAR should parse");
    let response = chunks
        .into_iter()
        .map(|c| c.unwrap())
        .find(|c| c.metadata.source_type.as_ref() == "wire:har:response")
        .expect("a response chunk");
    assert!(
        response.data.as_ref().contains("\u{FFFD}AKIA"),
        "invalid UTF-8 decoded from base64 must be scanned through lossy text, not dropped: {response:?}"
    );
}

#[test]
fn malformed_base64_encoding_falls_back_to_raw_text() {
    let not_b64 = format!("{AWS_TEST_KEY} not base64 @@@");
    let har = har_with_response_body(Some("base64"), &not_b64);
    let chunks = expand_har(har.as_bytes(), "cap.har", 10 * 1024 * 1024).expect("HAR should parse");
    let response = chunks
        .into_iter()
        .map(|c| c.unwrap())
        .find(|c| c.metadata.source_type.as_ref() == "wire:har:response")
        .expect("a response chunk");
    assert!(
        response.data.as_ref().contains(AWS_TEST_KEY),
        "malformed base64 must fall back to scanning the raw text"
    );
}

#[test]
fn plain_text_response_body_is_unchanged() {
    let har = har_with_response_body(None, AWS_TEST_KEY);
    let chunks = expand_har(har.as_bytes(), "cap.har", 10 * 1024 * 1024).expect("HAR should parse");
    let response = chunks
        .into_iter()
        .map(|c| c.unwrap())
        .find(|c| c.metadata.source_type.as_ref() == "wire:har:response")
        .expect("a response chunk");
    assert!(response.data.as_ref().contains(AWS_TEST_KEY));
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

    let chunks = expand_har(har.as_bytes(), "large.har", 10 * 1024 * 1024)
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

    let chunks = expand_har(&utf16_le, "utf16.har", 10 * 1024 * 1024)
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

    let chunks = expand_har(&bytes, "bom.har", 10 * 1024 * 1024)
        .expect("UTF-8 BOM should parse after BOM trimming");
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

    let chunks = expand_har(har.as_bytes(), "params.har", 10 * 1024 * 1024)
        .expect("HAR with postData params should parse");
    let request = chunks
        .into_iter()
        .map(|c| c.unwrap())
        .find(|c| c.metadata.source_type.as_ref() == "wire:har:request")
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

#[test]
fn har_cookie_redirect_and_comments_are_rendered() {
    let har = r#"{"log":{"version":"1.2","creator":{"name":"t","version":"1"},
            "entries":[{"request":{"method":"GET","url":"https://api.example.com/login",
            "headers":[],"queryString":[],
            "cookies":[{"name":"session","value":"request_cookie_secret_123"}],
            "comment":"request_comment_secret_123"},
            "response":{"status":302,"statusText":"Found","headers":[],
            "cookies":[{"name":"refresh","value":"response_cookie_secret_123"}],
            "redirectURL":"https://api.example.com/callback?token=redirect_secret_123",
            "comment":"response_comment_secret_123"}}]}}"#;

    let chunks = expand_har(har.as_bytes(), "cookies.har", 10 * 1024 * 1024)
        .expect("HAR with cookies/comments should parse");
    let chunks: Vec<_> = chunks.into_iter().map(|c| c.unwrap()).collect();
    let request = chunks
        .iter()
        .find(|c| c.metadata.source_type.as_ref() == "wire:har:request")
        .expect("request chunk");
    let response = chunks
        .iter()
        .find(|c| c.metadata.source_type.as_ref() == "wire:har:response")
        .expect("response chunk");

    assert!(request.data.contains("session=request_cookie_secret_123"));
    assert!(request.data.contains("request_comment_secret_123"));
    assert!(response.data.contains("refresh=response_cookie_secret_123"));
    assert!(response.data.contains("redirect_secret_123"));
    assert!(response.data.contains("response_comment_secret_123"));
}
