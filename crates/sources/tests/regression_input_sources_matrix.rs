//! Regression matrix for the HAR / stdin / printable-strings input sources.
//!
//! Every assertion pins a CONCRETE expected value (exact rendered bytes, exact
//! chunk counts, exact decoded strings, exact error kind + message) so a
//! silent behavior drift in `har.rs`, `stdin.rs`, or `strings.rs` fails the
//! gate rather than passing a shape-only check.
//!
//! Exercised through the public source API:
//!   - `testing::TestApi::expand_har` / `compact_har_base64_text` (har.rs)
//!   - `testing::TestApi::read_stdin_test_input_with_limit` (stdin.rs)
//!   - `FilesystemSource` binary-strings path (strings.rs, MIN_PRINTABLE_STRING_LEN)

use keyhog_core::{Source, SourceError};
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::FilesystemSource;

const BIG_MAX_SIZE: u64 = 1_000_000;

/// One entry: Authorization request header + `api_key` query string + a
/// response header carrying a reflected token.
const HAR_HEADER_AND_QUERY: &str = r#"{"log":{"entries":[{"request":{"method":"GET","url":"https://api.example.test/v1","headers":[{"name":"Authorization","value":"Bearer secret_token_abc123"}],"queryString":[{"name":"api_key","value":"qsecret456"}]},"response":{"status":200,"statusText":"OK","headers":[{"name":"X-Api-Token","value":"resp_token_xyz789"}]}}]}}"#;

fn expand(doc: &str, path: &str) -> Vec<Result<keyhog_core::Chunk, SourceError>> {
    TestApi
        .expand_har(doc.as_bytes(), path, BIG_MAX_SIZE)
        .expect("HAR-shaped input must take the structured path")
}

// ---------------------------------------------------------------------------
// HAR request/response rendering (har.rs)
// ---------------------------------------------------------------------------

#[test]
fn har_request_chunk_renders_exact_bytes_with_header_and_query_secret() {
    let chunks = expand(HAR_HEADER_AND_QUERY, "capture.har");
    // Exactly one request + one response chunk for the single entry.
    assert_eq!(chunks.len(), 2, "one entry -> request + response chunk");

    let request = chunks[0].as_ref().expect("request chunk ok");
    assert_eq!(request.metadata.source_type, "wire:har:request");
    assert_eq!(
        request.metadata.path.as_deref(),
        Some("capture.har#https://api.example.test/v1")
    );
    assert_eq!(
        &*request.data,
        "GET https://api.example.test/v1\n\
         Authorization: Bearer secret_token_abc123\n\
         # query\n\
         api_key=qsecret456\n"
    );
}

#[test]
fn har_response_chunk_renders_exact_bytes_with_reflected_token() {
    let chunks = expand(HAR_HEADER_AND_QUERY, "capture.har");
    let response = chunks[1].as_ref().expect("response chunk ok");
    assert_eq!(response.metadata.source_type, "wire:har:response");
    assert_eq!(
        response.metadata.path.as_deref(),
        Some("capture.har#https://api.example.test/v1")
    );
    assert_eq!(&*response.data, "200 OK\nX-Api-Token: resp_token_xyz789\n");
}

#[test]
fn har_post_body_and_cookies_render_in_request_chunk() {
    let doc = r#"{"log":{"entries":[{"request":{"method":"POST","url":"https://api.example.test/login","headers":[],"cookies":[{"name":"session","value":"cookie_secret_1"}],"postData":{"text":"password=body_secret_2"}},"response":{"status":204}}]}}"#;
    let chunks = expand(doc, "login.har");
    let request = chunks[0].as_ref().expect("request chunk ok");
    // method+url, then "# cookies" kv section, then a blank line + raw post body.
    assert_eq!(
        &*request.data,
        "POST https://api.example.test/login\n\
         # cookies\n\
         session=cookie_secret_1\n\
         \npassword=body_secret_2"
    );
    // status 204, no statusText, no headers/body -> just the status line.
    let response = chunks[1].as_ref().expect("response chunk ok");
    assert_eq!(&*response.data, "204\n");
}

#[test]
fn har_base64_response_body_is_decoded_before_scanning() {
    // content.text is base64 of "decoded_secret_value" with encoding=="base64".
    let doc = r#"{"log":{"entries":[{"request":{"method":"GET","url":"https://api.example.test/blob","headers":[]},"response":{"status":200,"content":{"encoding":"base64","text":"ZGVjb2RlZF9zZWNyZXRfdmFsdWU="}}}]}}"#;
    let chunks = expand(doc, "blob.har");
    let response = chunks[1].as_ref().expect("response chunk ok");
    // "200" status line (no statusText/headers), blank separator, decoded body.
    assert_eq!(&*response.data, "200\n\ndecoded_secret_value");
}

#[test]
fn har_two_entries_emit_four_chunks_in_request_response_order() {
    let doc = r#"{"log":{"entries":[
        {"request":{"method":"GET","url":"https://a.test/1","headers":[]},"response":{"status":200}},
        {"request":{"method":"PUT","url":"https://b.test/2","headers":[]},"response":{"status":500}}
    ]}}"#;
    let chunks = expand(doc, "multi.har");
    assert_eq!(chunks.len(), 4, "two entries -> four chunks");
    let types: Vec<&str> = chunks
        .iter()
        .map(|c| c.as_ref().expect("ok").metadata.source_type.as_str())
        .collect();
    assert_eq!(
        types,
        vec![
            "wire:har:request",
            "wire:har:response",
            "wire:har:request",
            "wire:har:response",
        ]
    );
    assert_eq!(&*chunks[0].as_ref().unwrap().data, "GET https://a.test/1\n");
    assert_eq!(&*chunks[2].as_ref().unwrap().data, "PUT https://b.test/2\n");
}

#[test]
fn empty_har_entries_yield_exactly_zero_chunks() {
    let result = TestApi.expand_har(br#"{"log":{"entries":[]}}"#, "empty.har", BIG_MAX_SIZE);
    let chunks = result.expect("valid empty HAR parses via the structured path");
    assert_eq!(chunks.len(), 0, "empty HAR emits no chunks");
}

#[test]
fn json_without_har_markers_returns_none() {
    // A JSON object that is not a HAR (no "log"/"entries" markers) must not be
    // claimed by the HAR expander; the caller falls back to raw text scanning.
    let result = TestApi.expand_har(br#"{"foo":123,"bar":"baz"}"#, "x.json", BIG_MAX_SIZE);
    assert!(result.is_none(), "non-HAR JSON must return None");
}

#[test]
fn non_object_input_returns_none() {
    // Does not start with '{' after BOM/whitespace trimming -> not HAR.
    let result = TestApi.expand_har(b"[1,2,3]", "x.json", BIG_MAX_SIZE);
    assert!(result.is_none(), "non-object JSON must return None");
}

#[test]
fn har_shaped_but_invalid_json_returns_none() {
    // Contains the "log"/"entries" markers but the JSON is truncated: serde
    // rejects it and the expander declines (caller scans raw text instead).
    let result = TestApi.expand_har(
        br#"{"log":{"entries":[{"request":"#,
        "broken.har",
        BIG_MAX_SIZE,
    );
    assert!(result.is_none(), "unparseable HAR shape must return None");
}

#[test]
fn har_expansion_budget_abort_emits_single_truncation_error() {
    // max_size == 1 -> 4x budget == 4 bytes, smaller than the first request
    // render, so expansion aborts on the first entry with a truncation error.
    let chunks = TestApi
        .expand_har(HAR_HEADER_AND_QUERY.as_bytes(), "capped.har", 1)
        .expect("HAR still parses; budget abort happens during rendering");
    assert_eq!(chunks.len(), 1, "budget abort emits exactly one error row");
    match &chunks[0] {
        Err(SourceError::Other(msg)) => {
            assert!(
                msg.contains("expansion budget"),
                "truncation error must name the expansion budget; got: {msg}"
            );
        }
        other => panic!("expected SourceError::Other truncation, got {other:?}"),
    }
}

#[test]
fn compact_base64_text_strips_all_ascii_whitespace() {
    // Whitespace-wrapped base64 (HAR pretty-printers) is compacted before decode.
    assert_eq!(TestApi.compact_har_base64_text("ab cd\tef\n"), "abcdef");
    // No-whitespace input is returned unchanged.
    assert_eq!(TestApi.compact_har_base64_text("ZGVjb2Rl"), "ZGVjb2Rl");
}

// ---------------------------------------------------------------------------
// stdin passthrough + capping (stdin.rs)
// ---------------------------------------------------------------------------

#[test]
fn stdin_passes_utf8_bytes_through_verbatim() {
    let input = b"my_stdin_secret=shhh\nline2=value\n";
    let out = TestApi
        .read_stdin_test_input_with_limit(input, 1000)
        .expect("under-limit stdin succeeds");
    assert_eq!(out, "my_stdin_secret=shhh\nline2=value\n");
}

#[test]
fn stdin_lossy_decodes_invalid_utf8() {
    // A lone 0xFF is not valid UTF-8; it becomes the U+FFFD replacement char,
    // and the surrounding printable secret survives (matches filesystem lossy).
    let input = b"key=\xffval_secret";
    let out = TestApi
        .read_stdin_test_input_with_limit(input, 1000)
        .expect("binary stdin is lossy-decoded, not rejected");
    assert_eq!(out, "key=\u{FFFD}val_secret");
}

#[test]
fn stdin_exactly_at_limit_is_accepted() {
    // len == cap is NOT truncated (read_to_cap reads cap+1, truncates on >cap).
    let out = TestApi
        .read_stdin_test_input_with_limit(b"12345", 5)
        .expect("input exactly at the cap is accepted");
    assert_eq!(out, "12345");
}

#[test]
fn stdin_one_byte_over_limit_errors_with_exact_message() {
    let err = TestApi
        .read_stdin_test_input_with_limit(b"123456", 5)
        .expect_err("input exceeding the cap must error");
    assert_eq!(err.kind(), std::io::ErrorKind::Other);
    assert_eq!(err.to_string(), "stdin exceeds 5 byte limit");
}

// ---------------------------------------------------------------------------
// printable-string extraction via the filesystem binary-strings path (strings.rs)
// ---------------------------------------------------------------------------

fn filesystem_chunks_for(bytes: &[u8], file_name: &str) -> Vec<keyhog_core::Chunk> {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(file_name), bytes).expect("write blob");
    FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .map(|c| c.expect("filesystem chunk ok"))
        .collect()
}

#[test]
fn binary_blob_yields_exact_ascii_printable_runs() {
    // 4-NUL runs + invalid-UTF-8 bytes force the binary-strings path.
    let mut blob = Vec::new();
    blob.extend_from_slice(&[0, 0, 0, 0]);
    blob.extend_from_slice(b"first_printable_secret"); // len 22 >= 8 -> kept
    blob.push(0xFF);
    blob.extend_from_slice(b"AB"); // len 2 < 8 -> dropped
    blob.extend_from_slice(&[0, 0, 0, 0]);
    blob.extend_from_slice(b"second_run_secret"); // len 17 >= 8 -> kept
    blob.push(0x80);

    let chunks = filesystem_chunks_for(&blob, "blob.bin");
    let strings_chunk = chunks
        .iter()
        .find(|c| c.metadata.source_type == "filesystem:binary-strings")
        .expect("binary blob must yield a binary-strings chunk");
    assert_eq!(
        &*strings_chunk.data,
        "first_printable_secret\nsecond_run_secret"
    );
}

#[test]
fn binary_blob_with_only_short_runs_yields_no_chunk() {
    // Only printable run is 7 chars (< MIN_PRINTABLE_STRING_LEN == 8): dropped,
    // and with nothing else printable the file produces zero chunks.
    let mut blob = Vec::new();
    blob.extend_from_slice(&[0, 0, 0, 0]);
    blob.extend_from_slice(b"abcdefg"); // len 7 < 8
    blob.push(0xFF);
    blob.extend_from_slice(&[0, 0, 0, 0]);
    blob.push(0x80);

    let chunks = filesystem_chunks_for(&blob, "short.bin");
    assert_eq!(
        chunks.len(),
        0,
        "sub-threshold-only binary blob emits no chunks; got {chunks:?}"
    );
}

#[test]
fn binary_blob_recovers_utf16le_wide_string() {
    // "WideSecretValue" (15 chars) encoded as X 00 X 00 ...; the ASCII pass sees
    // only length-1 runs (all dropped) and the UTF-16LE pass recovers the whole
    // wide string. The dense NUL interleave classifies the file as binary.
    let mut blob = Vec::new();
    for &b in b"WideSecretValue" {
        blob.push(b);
        blob.push(0x00);
    }
    let chunks = filesystem_chunks_for(&blob, "wide.bin");
    let strings_chunk = chunks
        .iter()
        .find(|c| c.metadata.source_type == "filesystem:binary-strings")
        .expect("wide-encoded blob must yield a binary-strings chunk");
    assert_eq!(&*strings_chunk.data, "WideSecretValue");
}
