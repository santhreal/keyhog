//! Deep regression coverage for the HAR 1.2 expander
//! (`crates/sources/src/har.rs`), driven through the hidden
//! `testing::TestApi::expand_har` facade so every assertion checks the exact
//! rendered chunk text, source_type tag, and `path#url` metadata a finding
//! carries — not just "non-empty".
//!
//! Contract under test (see the module docs in `har.rs`):
//! - one `wire:har:request` chunk and one `wire:har:response` chunk per entry,
//!   each tagged with `"{path}#{url}"`;
//! - a secret in a request header / query / cookie / postData surfaces in the
//!   request chunk; a secret in a response body / redirectURL surfaces in the
//!   response chunk;
//! - `content.encoding == "base64"` bodies are decoded before scanning;
//! - a malformed (but HAR-shaped) document returns `None` (caller falls back to
//!   raw text) and records exactly one structured parse-failure gap — it never
//!   panics;
//! - a document whose expanded bodies blow the 4× file-size budget yields an
//!   exact `SourceError::Other` truncation row rather than unbounded growth;
//! - an empty `entries` array yields zero chunks;
//! - non-HAR / non-JSON input is declined (`None`) without a parse-failure count;
//! - UTF-16LE (BOM) exports take the same structured path as UTF-8.

use keyhog_core::{Chunk, SourceError};
use keyhog_sources::skip_counts;
use keyhog_sources::testing::{SourceTestApi, TestApi};

const BIG: u64 = 1_000_000;

fn expand(bytes: &[u8], path: &str, max: u64) -> Vec<Result<Chunk, SourceError>> {
    TestApi
        .expand_har(bytes, path, max)
        .unwrap_or_else(|| panic!("expected HAR to be recognized and expanded (got None)"))
}

fn expect_ok(row: &Result<Chunk, SourceError>) -> &Chunk {
    match row {
        Ok(chunk) => chunk,
        Err(error) => panic!("expected an Ok chunk, got error: {error:?}"),
    }
}

fn expect_truncation(row: &Result<Chunk, SourceError>) -> String {
    match row {
        Err(SourceError::Other(message)) => message.clone(),
        other => panic!("expected SourceError::Other truncation row, got {other:?}"),
    }
}

#[test]
fn request_authorization_header_secret_surfaces_with_exact_metadata() {
    let har = br#"{"log":{"entries":[{"request":{"method":"POST","url":"https://api.example.test/v1/login","headers":[{"name":"Authorization","value":"Bearer sk_live_ABCDEF123456"}]},"response":{"status":201,"statusText":"Created","headers":[{"name":"Content-Type","value":"application/json"}]}}]}}"#;

    let rows = expand(har, "capture.har", BIG);
    assert_eq!(rows.len(), 2, "one request + one response chunk per entry");

    let request = expect_ok(&rows[0]);
    assert_eq!(request.metadata.source_type.as_ref(), "wire:har:request");
    assert_eq!(
        request.metadata.path.as_deref(),
        Some("capture.har#https://api.example.test/v1/login"),
        "request chunk must carry the source path fused with the entry URL"
    );
    assert_eq!(
        &*request.data,
        "POST https://api.example.test/v1/login\nAuthorization: Bearer sk_live_ABCDEF123456\n",
        "request render is method+url line then each header on its own line"
    );

    let response = expect_ok(&rows[1]);
    assert_eq!(response.metadata.source_type.as_ref(), "wire:har:response");
    assert_eq!(
        response.metadata.path.as_deref(),
        Some("capture.har#https://api.example.test/v1/login"),
        "response chunk shares the same path#url anchor as its request"
    );
    assert_eq!(
        &*response.data, "201 Created\nContent-Type: application/json\n",
        "response render is status[+statusText] line then each header"
    );
}

#[test]
fn response_json_body_secret_surfaces_in_response_chunk() {
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://api.example.test/token"},"response":{"status":200,"content":{"text":"{\"access_token\":\"ghp_SECRETINBODY0123\"}"}}}]}}"#;

    let rows = expand(har, "capture.har", BIG);
    assert_eq!(rows.len(), 2);

    let request = expect_ok(&rows[0]);
    assert_eq!(&*request.data, "GET https://api.example.test/token\n");

    let response = expect_ok(&rows[1]);
    assert_eq!(response.metadata.source_type.as_ref(), "wire:har:response");
    assert_eq!(
        response.metadata.path.as_deref(),
        Some("capture.har#https://api.example.test/token")
    );
    assert_eq!(
        &*response.data, "200\n\n{\"access_token\":\"ghp_SECRETINBODY0123\"}",
        "response body is appended after a blank-line separator following the status line"
    );
}

#[test]
fn base64_declared_response_body_is_decoded_before_scanning() {
    // base64("client_secret=ghp_A1b2C3d4E5f6G7h8I9j0K")
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://b64.test/r"},"response":{"status":200,"content":{"encoding":"base64","text":"Y2xpZW50X3NlY3JldD1naHBfQTFiMkMzZDRFNWY2RzdoOEk5ajBL"}}}]}}"#;

    let rows = expand(har, "b64.har", BIG);
    assert_eq!(rows.len(), 2);

    let response = expect_ok(&rows[1]);
    assert_eq!(response.metadata.source_type.as_ref(), "wire:har:response");
    assert_eq!(
        &*response.data, "200\n\nclient_secret=ghp_A1b2C3d4E5f6G7h8I9j0K",
        "declared-base64 body must be decoded so the plaintext secret is what gets scanned"
    );
}

#[test]
fn request_query_string_and_cookies_render_in_order() {
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://q.test/s","headers":[{"name":"X-Api-Key","value":"key_abc123"}],"cookies":[{"name":"session","value":"sess_XYZ"}],"queryString":[{"name":"token","value":"qs_TOKEN99"}]},"response":{"status":204}}]}}"#;

    let rows = expand(har, "q.har", BIG);
    assert_eq!(rows.len(), 2);

    let request = expect_ok(&rows[0]);
    assert_eq!(
        &*request.data,
        "GET https://q.test/s\nX-Api-Key: key_abc123\n# cookies\nsession=sess_XYZ\n# query\ntoken=qs_TOKEN99\n",
        "render order is headers, then # cookies section, then # query section"
    );

    let response = expect_ok(&rows[1]);
    assert_eq!(
        &*response.data, "204\n",
        "a content-less response still renders its status line"
    );
}

#[test]
fn request_post_data_text_and_params_render() {
    let har = br#"{"log":{"entries":[{"request":{"method":"POST","url":"https://p.test/f","postData":{"text":"grant_type=password&secret=ps_SEKRIT","params":[{"name":"secret","value":"ps_PARAM_VAL"}]}},"response":{"status":200}}]}}"#;

    let rows = expand(har, "p.har", BIG);
    assert_eq!(rows.len(), 2);

    let request = expect_ok(&rows[0]);
    assert_eq!(
        &*request.data,
        "POST https://p.test/f\n\ngrant_type=password&secret=ps_SEKRIT\n# postData params\nsecret=ps_PARAM_VAL\n",
        "postData.text is appended after a blank line, then the # postData params section"
    );
}

#[test]
fn response_redirect_url_comment_and_negative_status_render() {
    // Adversarial: HAR `status` is an i64; a negative value must render via the
    // signed-decimal path, not panic.
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://r.test/x"},"response":{"status":-5,"redirectURL":"https://evil.test/cb?token=rt_LEAK","comment":"cached"}}]}}"#;

    let rows = expand(har, "r.har", BIG);
    assert_eq!(rows.len(), 2);

    let response = expect_ok(&rows[1]);
    assert_eq!(
        &*response.data,
        "-5\n# redirectURL\nhttps://evil.test/cb?token=rt_LEAK\n# response comment\ncached\n",
        "negative status renders as -5 and the redirectURL/comment sections follow"
    );
}

#[test]
fn multiple_entries_emit_request_response_pairs_in_order() {
    let har = br#"{"log":{"entries":[
        {"request":{"method":"GET","url":"https://one.test/a"},"response":{"status":200}},
        {"request":{"method":"GET","url":"https://two.test/b"},"response":{"status":200}}
    ]}}"#;

    let rows = expand(har, "multi.har", BIG);
    assert_eq!(rows.len(), 4, "two entries -> four chunks");

    let types: Vec<&str> = rows
        .iter()
        .map(|row| expect_ok(row).metadata.source_type.as_ref())
        .collect();
    assert_eq!(
        types,
        vec![
            "wire:har:request",
            "wire:har:response",
            "wire:har:request",
            "wire:har:response",
        ],
        "chunks are emitted request-then-response, entry by entry"
    );

    assert_eq!(
        expect_ok(&rows[0]).metadata.path.as_deref(),
        Some("multi.har#https://one.test/a")
    );
    assert_eq!(
        expect_ok(&rows[3]).metadata.path.as_deref(),
        Some("multi.har#https://two.test/b")
    );
}

#[test]
fn empty_entries_array_yields_zero_chunks() {
    let rows = expand(br#"{"log":{"entries":[]}}"#, "empty.har", BIG);
    assert_eq!(rows.len(), 0, "a HAR with no entries expands to nothing");
}

#[test]
fn malformed_har_returns_none_and_counts_exactly_one_parse_gap() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    // HAR-shaped (has `"log"` and `"entries"`, starts with `{`) but truncated
    // mid-object, so serde_json rejects it.
    let malformed = br#"{"log":{"entries":[{"request":{"method":"GET"#;
    let result = TestApi.expand_har(malformed, "broken.har", BIG);
    assert!(
        result.is_none(),
        "malformed HAR must decline structured expansion so the caller can raw-scan it (got Some)"
    );

    let counts = skip_counts();
    assert_eq!(
        counts.structured_source_parse_failures, 1,
        "a HAR-shaped parse failure surfaces exactly one partial-coverage gap"
    );

    TestApi.reset_skip_counters();
}

#[test]
fn non_har_json_is_declined_without_a_parse_failure_count() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    // Valid JSON, but lacks the `"log"`/`"entries"` markers -> declined at the
    // cheap sniff, BEFORE serde runs, so it is not a parse failure.
    let not_har = br#"{"config":{"items":[1,2,3]}}"#;
    let result = TestApi.expand_har(not_har, "config.json", BIG);
    assert!(result.is_none(), "non-HAR JSON must be declined");

    let counts = skip_counts();
    assert_eq!(
        counts.structured_source_parse_failures, 0,
        "declining at the marker sniff is NOT a structured parse failure"
    );

    TestApi.reset_skip_counters();
}

#[test]
fn non_json_input_is_declined_without_a_parse_failure_count() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    let plain = b"just plain text, not json at all, token=ghp_whatever";
    let result = TestApi.expand_har(plain, "notes.txt", BIG);
    assert!(
        result.is_none(),
        "input that does not start with '{{' is not HAR"
    );

    let counts = skip_counts();
    assert_eq!(
        counts.structured_source_parse_failures, 0,
        "non-JSON input never reaches the structured parser"
    );

    TestApi.reset_skip_counters();
}

#[test]
fn budget_overrun_on_first_request_yields_only_the_exact_truncation_error() {
    // max_size=10 -> expansion budget = 40 bytes. The single request renders to
    // 54 bytes ("GET " + 49-char url + "\n"), overrunning immediately, so the
    // only row is the truncation error and no request chunk is emitted.
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://example.test/aaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"response":{"status":200}}]}}"#;

    let rows = expand(har, "big.har", 10);
    assert_eq!(
        rows.len(),
        1,
        "over-budget first entry yields only the error row"
    );

    let message = expect_truncation(&rows[0]);
    assert_eq!(
        message,
        "HAR source scan was truncated for big.har: cumulative request/response bytes exceeded the 40-byte expansion budget; remaining HAR entries were not scanned",
        "truncation error must name the path and the exact 4x budget"
    );
}

#[test]
fn budget_overrun_after_request_emits_request_then_exact_truncation_error() {
    // request renders to 21 bytes (<= budget 52); a 100-byte response body then
    // pushes the cumulative total to 126 > 52, so the request chunk is kept and
    // a truncation error is appended before the loop breaks.
    let body = "z".repeat(100);
    let har = format!(
        r#"{{"log":{{"entries":[{{"request":{{"method":"GET","url":"https://a.test/x"}},"response":{{"status":200,"content":{{"text":"{body}"}}}}}}]}}}}"#
    );

    let rows = expand(har.as_bytes(), "cap.har", 13); // budget = 13*4 = 52
    assert_eq!(
        rows.len(),
        2,
        "the fitting request chunk plus the truncation error"
    );

    let request = expect_ok(&rows[0]);
    assert_eq!(request.metadata.source_type.as_ref(), "wire:har:request");
    assert_eq!(&*request.data, "GET https://a.test/x\n");

    let message = expect_truncation(&rows[1]);
    assert_eq!(
        message,
        "HAR source scan was truncated for cap.har: cumulative request/response bytes exceeded the 52-byte expansion budget; remaining HAR entries were not scanned"
    );
}

#[test]
fn utf16le_bom_har_takes_the_structured_path() {
    // Windows/PowerShell-style UTF-16LE export with a BOM must decode and expand
    // exactly like the UTF-8 form, not fall through to raw text.
    let json = r#"{"log":{"entries":[{"request":{"method":"GET","url":"https://u16.test/a","headers":[{"name":"Authorization","value":"Bearer u16_SECRET"}]},"response":{"status":200}}]}}"#;
    let mut bytes: Vec<u8> = vec![0xFF, 0xFE];
    for unit in json.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }

    let rows = expand(&bytes, "wide.har", BIG);
    assert_eq!(rows.len(), 2);

    let request = expect_ok(&rows[0]);
    assert_eq!(request.metadata.source_type.as_ref(), "wire:har:request");
    assert_eq!(
        request.metadata.path.as_deref(),
        Some("wide.har#https://u16.test/a")
    );
    assert_eq!(
        &*request.data, "GET https://u16.test/a\nAuthorization: Bearer u16_SECRET\n",
        "UTF-16 decoding must produce byte-identical structured output to UTF-8"
    );
}

#[test]
fn compact_har_base64_text_strips_all_ascii_whitespace() {
    // HAR exporters wrap base64 bodies at column boundaries; the compactor must
    // remove spaces/tabs/newlines so the decoder sees one continuous token.
    let compacted = TestApi.compact_har_base64_text("YWJj\nZGVm ghi\tjkl\r\n");
    assert_eq!(
        compacted, "YWJjZGVmghijkl",
        "every ASCII whitespace byte (\\n, space, \\t, \\r) is removed"
    );

    // No-whitespace input is returned unchanged (borrow fast path).
    let untouched = TestApi.compact_har_base64_text("YWJjZGVm");
    assert_eq!(untouched, "YWJjZGVm");
}
