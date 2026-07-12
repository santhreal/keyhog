//! HAR 1.2 **header-axis** regression coverage, driven through the hidden
//! `testing::TestApi::expand_har` facade (the parser is `pub(crate)`).
//!
//! Distinct from `regression_har_parse.rs` / `regression_har_deep.rs`: this file
//! pins the behaviour of the request/response **header** render path in
//! `har.rs::render_request` / `render_response` — the `"{name}: {value}\n"`
//! line format, the request-vs-response chunk separation a leaked credential
//! lands in, the exact `wire:har:{request,response}` `source_type` tag, the
//! `{path}#{url}` metadata each header-bearing chunk carries, and the
//! multi-entry fan-out where every entry's header secret is tagged to its own
//! URL.
//!
//! "Surfaces" here means the credential's exact bytes appear in the rendered
//! chunk text a downstream scanner receives (the sources crate does not run the
//! detector engine); every assertion pins concrete bytes, not `!is_empty()`.

use keyhog_core::{Chunk, SourceError};
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

/// A request `Authorization` header secret lands in the REQUEST chunk, tagged
/// `wire:har:request` with the URL-suffixed path, rendered as one `name: value`
/// line after the request line.
#[test]
fn request_authorization_bearer_header_surfaces_in_request_chunk_with_metadata() {
    let har = br#"{"log":{"entries":[{"request":{"method":"POST","url":"https://api.example.test/v1/login","headers":[{"name":"Authorization","value":"Bearer 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"}]},"response":{"status":201,"statusText":"Created"}}]}}"#;

    let rows = expand(har, "capture.har", BIG);
    assert_eq!(rows.len(), 2, "one request + one response chunk per entry");

    let request = expect_ok(&rows[0]);
    assert_eq!(request.metadata.source_type.as_ref(), "wire:har:request");
    assert_eq!(
        request.metadata.path.as_deref(),
        Some("capture.har#https://api.example.test/v1/login")
    );
    assert_eq!(
        &*request.data,
        "POST https://api.example.test/v1/login\nAuthorization: Bearer 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\n",
        "the Authorization header renders as one `name: value` line after the request line"
    );
}

/// A response `Set-Cookie` header secret lands in the RESPONSE chunk, tagged
/// `wire:har:response`, rendered after the status line.
#[test]
fn response_set_cookie_header_secret_surfaces_in_response_chunk() {
    let har = br#"{"log":{"entries":[{"request":{"method":"POST","url":"https://s.test/login","headers":[{"name":"Content-Type","value":"application/json"}]},"response":{"status":200,"headers":[{"name":"Set-Cookie","value":"sessionid=sess_TOPSECRET_9f; Path=/; HttpOnly"}]}}]}}"#;

    let rows = expand(har, "sc.har", BIG);
    let response = expect_ok(&rows[1]);
    assert_eq!(response.metadata.source_type.as_ref(), "wire:har:response");
    assert_eq!(
        response.metadata.path.as_deref(),
        Some("sc.har#https://s.test/login")
    );
    assert_eq!(
        &*response.data,
        "200\nSet-Cookie: sessionid=sess_TOPSECRET_9f; Path=/; HttpOnly\n",
        "the Set-Cookie response header renders verbatim (semicolons/equals preserved) after the status line"
    );
}

/// Negative twin: a secret carried in a REQUEST header must NOT bleed into the
/// paired response chunk — the two chunks are separate threat models.
#[test]
fn request_header_secret_absent_from_response_chunk() {
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://n.test/x","headers":[{"name":"Authorization","value":"Bearer req_ONLY_SECRET_42"}]},"response":{"status":204}}]}}"#;

    let rows = expand(har, "n.har", BIG);
    let request = expect_ok(&rows[0]);
    let response = expect_ok(&rows[1]);

    assert!(
        request.data.contains("req_ONLY_SECRET_42"),
        "request header secret is present in the request chunk"
    );
    assert!(
        !response.data.contains("req_ONLY_SECRET_42"),
        "request header secret must NOT appear in the response chunk"
    );
    assert_eq!(
        &*response.data, "204\n",
        "the response chunk is just its status line"
    );
}

/// Negative twin (mirror): a RESPONSE header secret must NOT appear in the
/// request chunk.
#[test]
fn response_header_secret_absent_from_request_chunk() {
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://m.test/x"},"response":{"status":200,"headers":[{"name":"Set-Cookie","value":"tok=resp_ONLY_SECRET_77"}]}}]}}"#;

    let rows = expand(har, "m.har", BIG);
    let request = expect_ok(&rows[0]);
    let response = expect_ok(&rows[1]);

    assert_eq!(
        &*request.data, "GET https://m.test/x\n",
        "a header-less request renders only its request line"
    );
    assert!(
        !request.data.contains("resp_ONLY_SECRET_77"),
        "response header secret must NOT appear in the request chunk"
    );
    assert!(
        response.data.contains("resp_ONLY_SECRET_77"),
        "response header secret is present in the response chunk"
    );
}

/// Multiple entries: every entry's header secret is tagged to its OWN URL, and
/// the chunk count is exactly 2 per entry in document order.
#[test]
fn multiple_entries_each_header_secret_tagged_to_its_own_url() {
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://a.test/1","headers":[{"name":"Authorization","value":"Bearer tok_ENTRY_A"}]},"response":{"status":200}},{"request":{"method":"GET","url":"https://b.test/2","headers":[{"name":"Authorization","value":"Bearer tok_ENTRY_B"}]},"response":{"status":200}}]}}"#;

    let rows = expand(har, "multi.har", BIG);
    assert_eq!(rows.len(), 4, "two entries expand to exactly four chunks");

    let req_a = expect_ok(&rows[0]);
    assert_eq!(
        req_a.metadata.path.as_deref(),
        Some("multi.har#https://a.test/1")
    );
    assert_eq!(
        &*req_a.data,
        "GET https://a.test/1\nAuthorization: Bearer tok_ENTRY_A\n"
    );

    let req_b = expect_ok(&rows[2]);
    assert_eq!(
        req_b.metadata.path.as_deref(),
        Some("multi.har#https://b.test/2")
    );
    assert_eq!(
        &*req_b.data,
        "GET https://b.test/2\nAuthorization: Bearer tok_ENTRY_B\n"
    );

    // Cross-check: entry A's secret is not tagged to entry B's URL.
    assert!(!req_b.data.contains("tok_ENTRY_A"));
}

/// Many entries (3): all six chunks emit and every header secret surfaces in its
/// own request chunk.
#[test]
fn three_entries_all_header_secrets_surface_and_count_is_six() {
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://x.test/1","headers":[{"name":"X-Api-Key","value":"key_ONE"}]},"response":{"status":200}},{"request":{"method":"GET","url":"https://x.test/2","headers":[{"name":"X-Api-Key","value":"key_TWO"}]},"response":{"status":200}},{"request":{"method":"GET","url":"https://x.test/3","headers":[{"name":"X-Api-Key","value":"key_THREE"}]},"response":{"status":200}}]}}"#;

    let rows = expand(har, "three.har", BIG);
    assert_eq!(rows.len(), 6, "three entries expand to exactly six chunks");

    assert!(expect_ok(&rows[0]).data.contains("key_ONE"));
    assert!(expect_ok(&rows[2]).data.contains("key_TWO"));
    assert!(expect_ok(&rows[4]).data.contains("key_THREE"));

    // The response chunks (odd indices) carry only their status line.
    assert_eq!(&*expect_ok(&rows[1]).data, "200\n");
    assert_eq!(&*expect_ok(&rows[3]).data, "200\n");
    assert_eq!(&*expect_ok(&rows[5]).data, "200\n");
}

/// Header render order: multiple request headers render one per line in the
/// exact document order they appear.
#[test]
fn multiple_request_headers_preserve_document_order() {
    let har = br#"{"log":{"entries":[{"request":{"method":"POST","url":"https://o.test/x","headers":[{"name":"Authorization","value":"Bearer tok_FIRST"},{"name":"X-Api-Key","value":"key_SECOND"},{"name":"Content-Type","value":"application/json"}]},"response":{"status":200}}]}}"#;

    let rows = expand(har, "o.har", BIG);
    let request = expect_ok(&rows[0]);
    assert_eq!(
        &*request.data,
        "POST https://o.test/x\nAuthorization: Bearer tok_FIRST\nX-Api-Key: key_SECOND\nContent-Type: application/json\n",
        "request headers render one per line in document order"
    );
}

/// Boundary: a header with an empty value renders `name: ` (name, colon, space)
/// followed by the newline — the value slot is empty but the line is still
/// emitted.
#[test]
fn empty_header_value_renders_name_colon_space_then_newline() {
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://e.test/x","headers":[{"name":"X-Empty","value":""},{"name":"Authorization","value":"Bearer after_empty_SECRET"}]},"response":{"status":200}}]}}"#;

    let rows = expand(har, "e.har", BIG);
    let request = expect_ok(&rows[0]);
    assert_eq!(
        &*request.data,
        "GET https://e.test/x\nX-Empty: \nAuthorization: Bearer after_empty_SECRET\n",
        "an empty header value still emits the `name: ` line, and later headers still render"
    );
}

/// Adversarial: two headers with the SAME name (duplicate Authorization) both
/// render — neither is deduplicated or dropped.
#[test]
fn duplicate_header_name_renders_both_lines() {
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://d.test/x","headers":[{"name":"Authorization","value":"Bearer dup_ONE"},{"name":"Authorization","value":"Bearer dup_TWO"}]},"response":{"status":200}}]}}"#;

    let rows = expand(har, "d.har", BIG);
    let request = expect_ok(&rows[0]);
    assert_eq!(
        &*request.data,
        "GET https://d.test/x\nAuthorization: Bearer dup_ONE\nAuthorization: Bearer dup_TWO\n",
        "both same-named headers render in order; no dedup"
    );
}

/// The header name is rendered VERBATIM — casing is not normalized, so a
/// lowercased `authorization` header keeps its exact bytes.
#[test]
fn header_name_case_is_preserved_verbatim() {
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://k.test/x","headers":[{"name":"authorization","value":"Bearer lower_SECRET"}]},"response":{"status":200}}]}}"#;

    let rows = expand(har, "k.har", BIG);
    let request = expect_ok(&rows[0]);
    assert_eq!(
        &*request.data, "GET https://k.test/x\nauthorization: Bearer lower_SECRET\n",
        "the header name is emitted with its original casing, not normalized"
    );
}

/// Response render order: the status line precedes the response headers, which
/// precede the `# cookies` array section.
#[test]
fn response_status_line_precedes_headers_which_precede_cookies() {
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://r.test/x"},"response":{"status":200,"statusText":"OK","headers":[{"name":"Set-Cookie","value":"a=hdr_cookie_SECRET"}],"cookies":[{"name":"parsed","value":"arr_cookie_SECRET"}]}}]}}"#;

    let rows = expand(har, "r.har", BIG);
    let response = expect_ok(&rows[1]);
    assert_eq!(
        &*response.data,
        "200 OK\nSet-Cookie: a=hdr_cookie_SECRET\n# cookies\nparsed=arr_cookie_SECRET\n",
        "response order is status line, then header lines, then the # cookies array section"
    );
}

/// Request render order: headers precede the `# cookies` array section.
#[test]
fn request_headers_precede_cookies_section() {
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://q.test/x","headers":[{"name":"Authorization","value":"Bearer hdr_SECRET"}],"cookies":[{"name":"sid","value":"cookie_SECRET"}]},"response":{"status":200}}]}}"#;

    let rows = expand(har, "q.har", BIG);
    let request = expect_ok(&rows[0]);
    assert_eq!(
        &*request.data,
        "GET https://q.test/x\nAuthorization: Bearer hdr_SECRET\n# cookies\nsid=cookie_SECRET\n",
        "request order is request line, then header lines, then the # cookies section"
    );
}

/// A header value containing structural characters (colons, semicolons, equals,
/// spaces — as in a Basic auth or multi-attribute cookie) is preserved byte for
/// byte; only the FIRST `": "` (the separator this renderer inserts) delimits
/// name from value.
#[test]
fn header_value_with_colons_and_semicolons_preserved_byte_for_byte() {
    let har = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://v.test/x","headers":[{"name":"Authorization","value":"Basic dXNlcjpwYXNz=; realm=api; charset=utf-8"}]},"response":{"status":200}}]}}"#;

    let rows = expand(har, "v.har", BIG);
    let request = expect_ok(&rows[0]);
    assert_eq!(
        &*request.data,
        "GET https://v.test/x\nAuthorization: Basic dXNlcjpwYXNz=; realm=api; charset=utf-8\n",
        "the full header value including its internal colons/semicolons/equals is preserved"
    );
}

/// A header-only request (no query, no postData, no comment) emits exactly one
/// request line plus its header lines and nothing else — the header path does
/// not spuriously append body sections.
#[test]
fn header_only_request_emits_no_body_sections() {
    let har = br#"{"log":{"entries":[{"request":{"method":"PUT","url":"https://ho.test/x","headers":[{"name":"Authorization","value":"Bearer only_hdr_SECRET"},{"name":"Accept","value":"application/json"}]},"response":{"status":200}}]}}"#;

    let rows = expand(har, "ho.har", BIG);
    assert_eq!(rows.len(), 2);
    let request = expect_ok(&rows[0]);
    assert_eq!(
        &*request.data,
        "PUT https://ho.test/x\nAuthorization: Bearer only_hdr_SECRET\nAccept: application/json\n",
        "a header-only request has no query/postData/comment sections appended"
    );
    assert!(
        !request.data.contains("# query") && !request.data.contains("# postData"),
        "no body sections leak into a header-only request chunk"
    );
}
