//! HAR 1.2 parse/expansion regression coverage driven through the hidden
//! `testing::TestApi::expand_har` facade (the parser itself is `pub(crate)`).
//!
//! These assertions pin the EXACT rendered chunk bytes, `source_type` tag, and
//! `path#url` metadata for cases NOT already covered by `regression_har_deep.rs`:
//! render-order edge cases (response cookies, request comment, bare postData
//! params), the base64 body path (whitespace-wrapped decode + malformed-encoding
//! raw fallback with its structured-parse-failure count), the `push_i64_decimal`
//! zero boundary, the `max_size == 0` uncapped-budget path, serde `entries`
//! defaulting, and adversarial JSON shapes (top-level array, leading whitespace).
//!
//! Every entry always renders at least `"METHOD URL\n"` for the request and a
//! status line for the response, so a well-formed entry emits exactly two chunks.

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

#[test]
fn minimal_entry_emits_exactly_two_chunks_method_url_and_status() {
    // The smallest legal entry: a request with only method+url, and a response
    // with only a status. Both still render (request_len and response_len are
    // always > 0), so the entry yields exactly two chunks with fixed bytes.
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://min.test/a"},"response":{"status":200}}]}}"#;

    let rows = expand(har, "min.har", BIG);
    assert_eq!(
        rows.len(),
        2,
        "a minimal entry expands to exactly two chunks"
    );

    let request = expect_ok(&rows[0]);
    assert_eq!(request.metadata.source_type.as_ref(), "wire:har:request");
    assert_eq!(
        request.metadata.path.as_deref(),
        Some("min.har#https://min.test/a")
    );
    assert_eq!(&*request.data, "GET https://min.test/a\n");

    let response = expect_ok(&rows[1]);
    assert_eq!(response.metadata.source_type.as_ref(), "wire:har:response");
    assert_eq!(
        response.metadata.path.as_deref(),
        Some("min.har#https://min.test/a")
    );
    assert_eq!(
        &*response.data, "200\n",
        "status-only response is just the status line"
    );
}

#[test]
fn multiple_request_headers_render_in_document_order() {
    let har = br#"{"log":{"entries":[{"request":{"method":"POST","url":"https://h.test/x","headers":[{"name":"Authorization","value":"Bearer tok_AAA"},{"name":"X-Api-Key","value":"key_BBB"},{"name":"Content-Type","value":"application/json"}]},"response":{"status":200}}]}}"#;

    let rows = expand(har, "h.har", BIG);
    let request = expect_ok(&rows[0]);
    assert_eq!(
        &*request.data,
        "POST https://h.test/x\nAuthorization: Bearer tok_AAA\nX-Api-Key: key_BBB\nContent-Type: application/json\n",
        "headers render one per line in the order they appear in the HAR"
    );
}

#[test]
fn post_data_param_without_value_renders_bare_name_equals() {
    // Adversarial: HAR postData params[].value is optional; a param missing its
    // value must render `name=` with an empty value, not panic or skip the line.
    let har = br#"{"log":{"entries":[{"request":{"method":"POST","url":"https://p.test/f","postData":{"params":[{"name":"csrf"},{"name":"secret","value":"ps_VAL"}]}},"response":{"status":200}}]}}"#;

    let rows = expand(har, "p.har", BIG);
    let request = expect_ok(&rows[0]);
    assert_eq!(
        &*request.data, "POST https://p.test/f\n\n# postData params\ncsrf=\nsecret=ps_VAL\n",
        "a valueless param renders `name=` with nothing after the equals sign"
    );
}

#[test]
fn response_cookies_section_renders_after_headers() {
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://c.test/s"},"response":{"status":200,"headers":[{"name":"Content-Type","value":"text/html"}],"cookies":[{"name":"session","value":"sess_SECRET_1"}]}}]}}"#;

    let rows = expand(har, "c.har", BIG);
    let response = expect_ok(&rows[1]);
    assert_eq!(
        &*response.data, "200\nContent-Type: text/html\n# cookies\nsession=sess_SECRET_1\n",
        "response render is status, then headers, then the # cookies section"
    );
}

#[test]
fn request_comment_section_renders_last() {
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://cm.test/x","headers":[{"name":"X-Api-Key","value":"key_ZZZ"}],"comment":"captured by devtools"},"response":{"status":200}}]}}"#;

    let rows = expand(har, "cm.har", BIG);
    let request = expect_ok(&rows[0]);
    assert_eq!(
        &*request.data,
        "GET https://cm.test/x\nX-Api-Key: key_ZZZ\n# request comment\ncaptured by devtools\n",
        "the request comment section is appended after headers"
    );
}

#[test]
fn zero_status_renders_single_zero_digit() {
    // Boundary for push_i64_decimal: status 0 must render as the single byte "0".
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://z.test/x"},"response":{"status":0,"statusText":"Aborted"}}]}}"#;

    let rows = expand(har, "z.har", BIG);
    let response = expect_ok(&rows[1]);
    assert_eq!(
        &*response.data, "0 Aborted\n",
        "a zero status renders as \"0\" followed by its statusText"
    );
}

#[test]
fn base64_whitespace_wrapped_response_body_is_compacted_then_decoded() {
    // base64("api_key=AKIA_SECRET_007") wrapped with an interior newline the way
    // real exporters column-wrap encoded bodies. The compactor strips the
    // whitespace, then the decoder recovers the plaintext for scanning.
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://b64.test/r"},"response":{"status":200,"content":{"encoding":"base64","text":"YXBpX2tl\neT1BS0lBX1NFQ1JFVF8wMDc="}}}]}}"#;

    let rows = expand(har, "b64.har", BIG);
    let response = expect_ok(&rows[1]);
    assert_eq!(
        &*response.data, "200\n\napi_key=AKIA_SECRET_007",
        "a whitespace-wrapped declared-base64 body decodes to the plaintext secret"
    );
}

#[test]
fn base64_declared_but_malformed_body_falls_back_to_raw_and_counts_one_gap() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    // encoding says base64 but the text is not valid base64: the body must still
    // be scanned RAW (recall-safe) AND a single structured parse-failure gap must
    // be recorded so the partial-coverage decision is visible.
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://bad.test/r"},"response":{"status":200,"content":{"encoding":"base64","text":"!!!not-valid-base64!!!"}}}]}}"#;

    let rows = expand(har, "bad.har", BIG);
    let response = expect_ok(&rows[1]);
    assert_eq!(
        &*response.data, "200\n\n!!!not-valid-base64!!!",
        "an undecodable declared-base64 body is scanned as its raw text"
    );

    let counts = skip_counts();
    assert_eq!(
        counts.structured_source_parse_failures, 1,
        "a failed base64 decode records exactly one structured parse-failure gap"
    );

    TestApi.reset_skip_counters();
}

#[test]
fn max_size_zero_uses_uncapped_budget_and_expands_large_body() {
    // max_size == 0 selects the uncapped (1 GiB) archive budget, so a body far
    // larger than any tiny 4x cap still expands into a full response chunk rather
    // than a truncation error.
    let body = "q".repeat(200);
    let har = format!(
        r#"{{"log":{{"entries":[{{"request":{{"method":"GET","url":"https://u.test/x"}},"response":{{"status":200,"content":{{"text":"{body}"}}}}}}]}}}}"#
    );

    let rows = expand(har.as_bytes(), "unc.har", 0);
    assert_eq!(
        rows.len(),
        2,
        "with an uncapped budget both request and response chunks are emitted"
    );

    let response = expect_ok(&rows[1]);
    let expected = format!("200\n\n{body}");
    assert_eq!(
        &*response.data,
        expected.as_str(),
        "the full 200-byte body survives under the uncapped budget"
    );
}

#[test]
fn missing_entries_key_defaults_to_empty_and_yields_zero_chunks() {
    // The document carries the literal `"log"` and `"entries"` marker substrings
    // (the `"entries"` here is an unrelated field VALUE) so the cheap sniff
    // accepts it, but there is no real entries array; serde's #[serde(default)]
    // makes `log.entries` an empty Vec, so expansion produces zero chunks.
    let har = br#"{"log":{"comment":"no real array"},"unknown_field":"entries"}"#;

    let rows = expand(har, "noent.har", BIG);
    assert_eq!(
        rows.len(),
        0,
        "a HAR whose entries key is absent defaults to no chunks"
    );
}

#[test]
fn top_level_json_array_is_declined_without_a_parse_failure() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    // Valid JSON that even carries the `"log"`/`"entries"` marker substrings, but
    // starts with '[' not '{', so it is declined at the cheap structural sniff
    // BEFORE serde runs. Declining there is not a structured parse failure.
    let arr = br#"[{"log":1,"entries":2}]"#;
    let result = TestApi.expand_har(arr, "arr.json", BIG);
    assert!(
        result.is_none(),
        "a top-level JSON array is not a HAR object and must be declined"
    );

    let counts = skip_counts();
    assert_eq!(
        counts.structured_source_parse_failures, 0,
        "declining a non-object at the sniff is not a parse failure"
    );

    TestApi.reset_skip_counters();
}

#[test]
fn leading_whitespace_before_brace_still_takes_the_structured_path() {
    // trim_bom_and_whitespace trims leading whitespace, so an export with a stray
    // newline/spaces before the opening brace is still recognized and expanded.
    let har = b"  \n\t{\"log\":{\"entries\":[{\"request\":{\"method\":\"GET\",\"url\":\"https://w.test/a\",\"headers\":[{\"name\":\"Authorization\",\"value\":\"Bearer ws_SECRET\"}]},\"response\":{\"status\":200}}]}}";

    let rows = expand(har, "ws.har", BIG);
    assert_eq!(rows.len(), 2);
    let request = expect_ok(&rows[0]);
    assert_eq!(
        &*request.data, "GET https://w.test/a\nAuthorization: Bearer ws_SECRET\n",
        "leading whitespace before the brace does not block structured expansion"
    );
}

#[test]
fn post_data_params_only_without_text_renders_params_section_only() {
    // postData with params but no `text`: only the "# postData params" section is
    // appended (no leading blank-line text block).
    let har = br#"{"log":{"entries":[{"request":{"method":"POST","url":"https://po.test/f","postData":{"params":[{"name":"grant_type","value":"password"},{"name":"secret","value":"po_SEKRIT"}]}},"response":{"status":204}}]}}"#;

    let rows = expand(har, "po.har", BIG);
    let request = expect_ok(&rows[0]);
    assert_eq!(
        &*request.data,
        "POST https://po.test/f\n\n# postData params\ngrant_type=password\nsecret=po_SEKRIT\n",
        "params-only postData renders just the params section"
    );

    let response = expect_ok(&rows[1]);
    assert_eq!(&*response.data, "204\n");
}
