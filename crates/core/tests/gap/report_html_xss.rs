//! Gap tests: HTML reporter stored-XSS escaping (`report_html_xss`).
//!
//! Target under test: `crates/core/src/report/html.rs`
//!   - `escape_for_script(serialized: &str) -> String` (private; exercised end
//!     to end through `HtmlReporter`).
//!   - `HtmlReporter::finish` inlines `serde_json::to_string(&findings)`
//!     verbatim into a `<script>` raw-text element, after:
//!       1. flattening `VerificationResult::Error(String)` from its object form
//!          `{"error":"…"}` to the bare discriminant string `"error"`, and
//!       2. `\u`-escaping `<`, `>`, `/`, U+2028 and U+2029.
//!
//! Every expected value below is derived from the real source:
//!   * `escape_for_script` maps (html.rs:23-31):
//!       '<' -> "\\u003c", '>' -> "\\u003e", '/' -> "\\u002f",
//!       U+2028 -> "\\u2028", U+2029 -> "\\u2029", everything else unchanged.
//!     It does NOT touch '"', '\'', '&', '\\', '\n', '\r', '\t'. Those are
//!     handled (or not) by `serde_json` at the JSON layer.
//!   * The HTML template emits EXACTLY ONE legitimate `</script>` close tag
//!     (html.rs:102). `html_script.js`, `html_body.html` and `html_styles.css`
//!     contain zero `</script>` sequences (verified). So any extra `</script>`
//!     in the output would be an attacker breakout.
//!   * `VerifiedFinding` uses serde default (snake_case) field names; no
//!     `rename_all`. Field names in the JSON: detector_id, detector_name,
//!     service, severity, credential_redacted, credential_hash, location,
//!     verification, metadata, additional_locations, confidence.
//!   * `Severity` serializes kebab-case (spec.rs:348): High -> "high",
//!     ClientSafe -> "client-safe", etc.
//!   * `VerificationResult` serializes snake_case (finding.rs:229): Live ->
//!     "live", RateLimited -> "rate_limited", Error(s) -> {"error":s} which
//!     `finish` rewrites to the bare string "error".
//!   * `confidence` is `skip_serializing_if = "Option::is_none"`.
//!   * `credential_hash` serializes as lowercase hex (finding.rs:319).

use crate::support::reporters::HtmlReporter;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use keyhog_core::{MatchLocation, Severity, VerificationResult, VerifiedFinding};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal finding with sane defaults; callers mutate fields.
fn base_finding() -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("aws-access-key"),
        detector_name: Arc::from("AWS Key"),
        service: Arc::from("aws"),
        severity: Severity::High,
        credential_redacted: Cow::Borrowed("AKIA...wxyz"),
        credential_hash: [0u8; 32],
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("src/main.rs")),
            line: Some(12),
            offset: 5,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Live,
        metadata: HashMap::new(),
        additional_locations: vec![],
        confidence: Some(0.5),
    }
}

/// Render one finding to a full HTML document string.
fn render(finding: &VerifiedFinding) -> String {
    render_all(std::slice::from_ref(finding))
}

/// Render a slice of findings to a full HTML document string.
fn render_all(findings: &[VerifiedFinding]) -> String {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut reporter = HtmlReporter::new(&mut buf);
        for f in findings {
            reporter.report(f).expect("report finding");
        }
        reporter.finish().expect("finish");
    }
    String::from_utf8(buf).expect("utf8 html output")
}

/// Extract the exact inlined JSON payload from the rendered document.
///
/// `finish` emits `    const rawFindings = {json};` on its own line
/// (html.rs:96-100). We return the substring between `const rawFindings = `
/// and the trailing `;`. This isolates only the attacker-influenced bytes so
/// our assertions never accidentally match the static template.
fn raw_findings_payload(html: &str) -> &str {
    let prefix = "const rawFindings = ";
    let start = html.find(prefix).expect("rawFindings assignment present") + prefix.len();
    let rest = &html[start..];
    let end = rest
        .find(";\n")
        .or_else(|| rest.find(';'))
        .expect("trailing semicolon");
    &rest[..end]
}

// ---------------------------------------------------------------------------
// `escape_for_script` character mapping (positive: each special char escaped)
// ---------------------------------------------------------------------------

#[test]
fn less_than_in_file_path_is_escaped_to_u003c() {
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("a<b"));
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    // serde_json would emit "a<b"; escape_for_script rewrites '<' -> <.
    assert!(payload.contains(r#""a\u003cb""#), "payload: {payload}");
    // The raw '<' must not survive inside the JSON payload region.
    assert!(!payload.contains('<'), "raw < survived: {payload}");
}

#[test]
fn greater_than_in_file_path_is_escaped_to_u003e() {
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("a>b"));
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    assert!(payload.contains(r#""a\u003eb""#), "payload: {payload}");
    assert!(!payload.contains('>'), "raw > survived: {payload}");
}

#[test]
fn forward_slash_in_file_path_is_escaped_to_u002f() {
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("a/b"));
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    assert!(payload.contains(r#""a\u002fb""#), "payload: {payload}");
    // The raw '/' must not appear within the JSON payload.
    assert!(
        !payload.contains('/'),
        "raw / survived in payload: {payload}"
    );
}

#[test]
fn u2028_line_separator_is_escaped() {
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("a\u{2028}b"));
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    assert!(payload.contains(r#""a\u2028b""#), "payload: {payload}");
    assert!(
        !payload.contains('\u{2028}'),
        "raw U+2028 survived in payload"
    );
}

#[test]
fn u2029_paragraph_separator_is_escaped() {
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("a\u{2029}b"));
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    assert!(payload.contains(r#""a\u2029b""#), "payload: {payload}");
    assert!(
        !payload.contains('\u{2029}'),
        "raw U+2029 survived in payload"
    );
}

#[test]
fn closing_script_tag_in_file_path_is_fully_neutralised() {
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("</script>"));
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    // '<' -> <, '/' -> /, '>' -> >, letters unchanged.
    assert!(
        payload.contains(r#""\u003c\u002fscript\u003e""#),
        "payload: {payload}"
    );
    // Exactly one legitimate </script> in the whole document.
    assert_eq!(
        html.matches("</script>").count(),
        1,
        "attacker </script> broke out"
    );
}

#[test]
fn open_script_tag_in_metadata_is_escaped() {
    let mut f = base_finding();
    f.metadata
        .insert("note".to_string(), "<script>alert(1)</script>".to_string());
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    // No raw "<script" anywhere in the inlined JSON.
    assert!(
        !payload.contains("<script"),
        "raw <script survived in payload: {payload}"
    );
    assert!(
        payload.contains(r#"\u003cscript\u003ealert(1)\u003c\u002fscript\u003e"#),
        "payload: {payload}"
    );
    assert_eq!(html.matches("</script>").count(), 1);
}

// ---------------------------------------------------------------------------
// Characters that `escape_for_script` deliberately leaves alone
// ---------------------------------------------------------------------------

#[test]
fn double_quote_is_json_escaped_not_unicode_escaped() {
    // escape_for_script does NOT touch '"'; serde_json emits it as \" already.
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("a\"b"));
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    // JSON string contains a backslash-quote, not ".
    assert!(payload.contains(r#""a\"b""#), "payload: {payload}");
    assert!(
        !payload.contains("\\u0022"),
        "double quote wrongly unicode-escaped: {payload}"
    );
}

#[test]
fn single_quote_is_left_verbatim() {
    // Single quote is safe in <script> raw text and in a double-quoted JSON
    // string; escape_for_script must not alter it.
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("it's"));
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    assert!(payload.contains("it's"), "payload: {payload}");
    assert!(
        !payload.contains("\\u0027") && !payload.contains("&#39;"),
        "single quote wrongly escaped: {payload}"
    );
}

#[test]
fn ampersand_is_not_escaped_by_escape_for_script() {
    // '&' is not in the escape_for_script match arms and serde_json does not
    // escape '&' either, so it appears verbatim. (HTML-entity escaping happens
    // client-side in escapeHtml, not in the inlined JSON.)
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("a&b"));
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    assert!(payload.contains("a&b"), "payload: {payload}");
    assert!(
        !payload.contains("&amp;"),
        "ampersand wrongly HTML-escaped in JSON: {payload}"
    );
}

#[test]
fn backslash_is_json_escaped_only() {
    // serde_json escapes '\' to '\\'; escape_for_script does not add to it.
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("a\\b"));
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    assert!(payload.contains(r#""a\\b""#), "payload: {payload}");
}

#[test]
fn newline_is_json_escaped_to_backslash_n() {
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("a\nb"));
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    assert!(payload.contains(r#""a\nb""#), "payload: {payload}");
    // The literal newline must not appear inside the single-line payload.
    assert!(!payload.contains("a\nb"), "raw newline survived: {payload}");
}

#[test]
fn carriage_return_is_json_escaped_to_backslash_r() {
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("a\rb"));
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    assert!(payload.contains(r#""a\rb""#), "payload: {payload}");
}

#[test]
fn tab_is_json_escaped_to_backslash_t() {
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("a\tb"));
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    assert!(payload.contains(r#""a\tb""#), "payload: {payload}");
}

#[test]
fn html_comment_open_in_field_does_not_break_out() {
    // `<!--` would open an HTML comment if '<' survived; '<' is escaped.
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("<!--"));
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    assert!(payload.contains(r#""\u003c!--""#), "payload: {payload}");
    assert!(!payload.contains('<'), "raw < survived: {payload}");
}

// ---------------------------------------------------------------------------
// Per-field coverage: every attacker-influenced string field is escaped
// ---------------------------------------------------------------------------

const BREAKOUT: &str = "</script><img src=x onerror=alert(1)>";
const BREAKOUT_ESC: &str = r#"\u003c\u002fscript\u003e\u003cimg src=x onerror=alert(1)\u003e"#;

fn assert_breakout_neutralised(html: &str) {
    // Exactly one legitimate </script> close in the whole document.
    assert_eq!(
        html.matches("</script>").count(),
        1,
        "attacker payload broke out of <script>"
    );
    // The raw breakout bytes must not survive inside the attacker-influenced
    // inlined JSON. (The whole document cannot be searched for the <img ...>
    // sentinel: html_script.js carries that exact string in a documentation
    // comment, concatenated verbatim, which would always false-positive.)
    let payload = raw_findings_payload(html);
    assert!(
        !payload.contains(BREAKOUT),
        "raw breakout payload appears verbatim in payload: {payload}"
    );
    assert!(
        !payload.contains("<img src=x onerror=alert(1)>"),
        "raw <img onerror> appears in payload: {payload}"
    );
    // The escaped form must be present in the inlined JSON.
    assert!(
        payload.contains(BREAKOUT_ESC),
        "escaped breakout payload missing; escaping did not run: {payload}"
    );
}

#[test]
fn breakout_in_file_path_is_neutralised() {
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from(BREAKOUT));
    assert_breakout_neutralised(&render(&f));
}

#[test]
fn breakout_in_commit_is_neutralised() {
    let mut f = base_finding();
    f.location.commit = Some(Arc::from(BREAKOUT));
    assert_breakout_neutralised(&render(&f));
}

#[test]
fn breakout_in_author_is_neutralised() {
    let mut f = base_finding();
    f.location.author = Some(Arc::from(BREAKOUT));
    assert_breakout_neutralised(&render(&f));
}

#[test]
fn breakout_in_date_is_neutralised() {
    let mut f = base_finding();
    f.location.date = Some(Arc::from(BREAKOUT));
    assert_breakout_neutralised(&render(&f));
}

#[test]
fn breakout_in_source_is_neutralised() {
    let mut f = base_finding();
    f.location.source = Arc::from(BREAKOUT);
    assert_breakout_neutralised(&render(&f));
}

#[test]
fn breakout_in_detector_id_is_neutralised() {
    let mut f = base_finding();
    f.detector_id = Arc::from(BREAKOUT);
    assert_breakout_neutralised(&render(&f));
}

#[test]
fn breakout_in_detector_name_is_neutralised() {
    let mut f = base_finding();
    f.detector_name = Arc::from(BREAKOUT);
    assert_breakout_neutralised(&render(&f));
}

#[test]
fn breakout_in_service_is_neutralised() {
    let mut f = base_finding();
    f.service = Arc::from(BREAKOUT);
    assert_breakout_neutralised(&render(&f));
}

#[test]
fn breakout_in_credential_redacted_is_neutralised() {
    let mut f = base_finding();
    f.credential_redacted = Cow::Owned(format!("AKIA...{BREAKOUT}"));
    assert_breakout_neutralised(&render(&f));
}

#[test]
fn breakout_in_metadata_value_is_neutralised() {
    let mut f = base_finding();
    f.metadata
        .insert("account_id".to_string(), BREAKOUT.to_string());
    assert_breakout_neutralised(&render(&f));
}

#[test]
fn breakout_in_metadata_key_is_neutralised() {
    let mut f = base_finding();
    f.metadata.insert(BREAKOUT.to_string(), "v".to_string());
    assert_breakout_neutralised(&render(&f));
}

#[test]
fn breakout_in_additional_location_file_path_is_neutralised() {
    let mut f = base_finding();
    let mut extra = f.location.clone();
    extra.file_path = Some(Arc::from(BREAKOUT));
    f.additional_locations.push(extra);
    assert_breakout_neutralised(&render(&f));
}

// ---------------------------------------------------------------------------
// VerificationResult::Error flattening (the "renders, not blank" guarantee)
// ---------------------------------------------------------------------------

#[test]
fn error_variant_is_flattened_to_bare_string_error() {
    let mut f = base_finding();
    f.verification = VerificationResult::Error("connection refused".to_string());
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    // The object form {"error":"…"} must NOT appear; the JS treats
    // verification as a string everywhere (f.verification.toLowerCase()).
    assert!(
        payload.contains(r#""verification":"error""#),
        "verification not flattened to bare string: {payload}"
    );
    assert!(
        !payload.contains(r#""verification":{"#),
        "verification still an object (would crash JS, blank page): {payload}"
    );
}

#[test]
fn error_variant_drops_inner_message_from_html() {
    // The flattening replaces the whole object with "error", so the inner
    // error text does not reach the HTML at all.
    let mut f = base_finding();
    f.verification = VerificationResult::Error("secret-bearing detail xyzzy".to_string());
    let html = render(&f);
    assert!(
        !html.contains("xyzzy"),
        "inner error message leaked into HTML"
    );
}

#[test]
fn error_variant_inner_breakout_cannot_xss_even_unflattened_path() {
    // Defense in depth: even if the inner string carried a breakout payload,
    // flattening drops it AND escaping would neutralise it. The bare "error"
    // string is what renders.
    let mut f = base_finding();
    f.verification = VerificationResult::Error(BREAKOUT.to_string());
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    assert!(
        payload.contains(r#""verification":"error""#),
        "payload: {payload}"
    );
    assert_eq!(html.matches("</script>").count(), 1);
    assert!(!html.contains(BREAKOUT));
}

#[test]
fn live_variant_serializes_as_live_string() {
    let mut f = base_finding();
    f.verification = VerificationResult::Live;
    let payload_owned = raw_findings_payload(&render(&f)).to_string();
    assert!(
        payload_owned.contains(r#""verification":"live""#),
        "payload: {payload_owned}"
    );
}

#[test]
fn revoked_variant_serializes_as_revoked_string() {
    let mut f = base_finding();
    f.verification = VerificationResult::Revoked;
    let payload_owned = raw_findings_payload(&render(&f)).to_string();
    assert!(payload_owned.contains(r#""verification":"revoked""#));
}

#[test]
fn dead_variant_serializes_as_dead_string() {
    let mut f = base_finding();
    f.verification = VerificationResult::Dead;
    let payload_owned = raw_findings_payload(&render(&f)).to_string();
    assert!(payload_owned.contains(r#""verification":"dead""#));
}

#[test]
fn rate_limited_variant_serializes_snake_case() {
    let mut f = base_finding();
    f.verification = VerificationResult::RateLimited;
    let payload_owned = raw_findings_payload(&render(&f)).to_string();
    assert!(
        payload_owned.contains(r#""verification":"rate_limited""#),
        "rate_limited not snake_case: {payload_owned}"
    );
}

#[test]
fn unverifiable_variant_serializes_as_unverifiable_string() {
    let mut f = base_finding();
    f.verification = VerificationResult::Unverifiable;
    let payload_owned = raw_findings_payload(&render(&f)).to_string();
    assert!(payload_owned.contains(r#""verification":"unverifiable""#));
}

#[test]
fn skipped_variant_serializes_as_skipped_string() {
    let mut f = base_finding();
    f.verification = VerificationResult::Skipped;
    let payload_owned = raw_findings_payload(&render(&f)).to_string();
    assert!(payload_owned.contains(r#""verification":"skipped""#));
}

#[test]
fn mixed_findings_each_render_with_string_verification() {
    // One Error finding adjacent to a Live finding: the Error must be flattened
    // so the whole array stays JS-safe.
    let mut err = base_finding();
    err.verification = VerificationResult::Error("boom".to_string());
    let live = base_finding();
    let html = render_all(&[err, live]);
    let payload = raw_findings_payload(&html);
    // Two findings: exactly two "verification" keys, none of them objects.
    assert_eq!(
        payload.matches(r#""verification""#).count(),
        2,
        "payload: {payload}"
    );
    assert!(!payload.contains(r#""verification":{"#));
    assert!(payload.contains(r#""verification":"error""#));
    assert!(payload.contains(r#""verification":"live""#));
}

// ---------------------------------------------------------------------------
// Severity serialization (kebab-case) reaching the JSON unaltered
// ---------------------------------------------------------------------------

#[test]
fn severity_high_serializes_kebab() {
    let mut f = base_finding();
    f.severity = Severity::High;
    let payload_owned = raw_findings_payload(&render(&f)).to_string();
    assert!(payload_owned.contains(r#""severity":"high""#));
}

#[test]
fn severity_client_safe_serializes_kebab_with_dash() {
    let mut f = base_finding();
    f.severity = Severity::ClientSafe;
    let payload_owned = raw_findings_payload(&render(&f)).to_string();
    assert!(
        payload_owned.contains(r#""severity":"client-safe""#),
        "ClientSafe not kebab-case: {payload_owned}"
    );
}

#[test]
fn severity_critical_serializes_kebab() {
    let mut f = base_finding();
    f.severity = Severity::Critical;
    let payload_owned = raw_findings_payload(&render(&f)).to_string();
    assert!(payload_owned.contains(r#""severity":"critical""#));
}

// ---------------------------------------------------------------------------
// Field-name and structural invariants of the inlined JSON
// ---------------------------------------------------------------------------

#[test]
fn json_uses_snake_case_field_names() {
    let f = base_finding();
    let payload = raw_findings_payload(&render(&f)).to_string();
    for key in [
        r#""detector_id""#,
        r#""detector_name""#,
        r#""service""#,
        r#""severity""#,
        r#""credential_redacted""#,
        r#""credential_hash""#,
        r#""location""#,
        r#""verification""#,
        r#""metadata""#,
        r#""additional_locations""#,
    ] {
        assert!(payload.contains(key), "missing field {key} in: {payload}");
    }
}

#[test]
fn credential_hash_serializes_as_lowercase_hex() {
    let mut f = base_finding();
    // 0xDE 0xAD 0xBE 0xEF then zeros.
    f.credential_hash = [0u8; 32];
    f.credential_hash[0] = 0xde;
    f.credential_hash[1] = 0xad;
    f.credential_hash[2] = 0xbe;
    f.credential_hash[3] = 0xef;
    let payload = raw_findings_payload(&render(&f)).to_string();
    // hex::encode -> lowercase, 64 hex chars total.
    let expected = "deadbeef".to_string() + &"00".repeat(28);
    assert!(
        payload.contains(&format!(r#""credential_hash":"{expected}""#)),
        "credential_hash hex mismatch: {payload}"
    );
}

#[test]
fn confidence_present_is_serialized() {
    let mut f = base_finding();
    f.confidence = Some(0.5);
    let payload = raw_findings_payload(&render(&f)).to_string();
    assert!(
        payload.contains(r#""confidence":0.5"#),
        "payload: {payload}"
    );
}

#[test]
fn confidence_none_is_omitted() {
    // skip_serializing_if = "Option::is_none" drops the key entirely.
    let mut f = base_finding();
    f.confidence = None;
    let payload = raw_findings_payload(&render(&f)).to_string();
    assert!(
        !payload.contains(r#""confidence""#),
        "confidence key present despite None: {payload}"
    );
}

#[test]
fn empty_findings_render_empty_json_array() {
    let html = render_all(&[]);
    let payload = raw_findings_payload(&html);
    assert_eq!(payload, "[]", "empty findings should inline []: {payload}");
    // Document still well-formed with exactly one script close.
    assert_eq!(html.matches("</script>").count(), 1);
}

// ---------------------------------------------------------------------------
// Whole-document structural invariants
// ---------------------------------------------------------------------------

#[test]
fn document_starts_with_doctype_and_html() {
    let html = render(&base_finding());
    assert!(
        html.starts_with("<!DOCTYPE html>\n"),
        "doc head: {:?}",
        &html[..32]
    );
    assert!(html.contains("<html lang=\"en\" data-theme=\"obsidian\">"));
}

#[test]
fn document_has_single_script_open_and_close_even_with_clean_finding() {
    let html = render(&base_finding());
    // Exactly one `<script>` open and one `</script>` close in the template.
    assert_eq!(html.matches("<script>").count(), 1, "script open count");
    assert_eq!(html.matches("</script>").count(), 1, "script close count");
}

#[test]
fn raw_findings_const_is_on_a_single_line() {
    // The payload is emitted via writeln! as a single line; a multi-line JSON
    // would mean serde produced pretty output or a stray newline survived.
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("a\nb")); // newline gets \n-escaped
    let html = render(&f);
    let line = html
        .lines()
        .find(|l| l.contains("const rawFindings ="))
        .expect("rawFindings line");
    assert!(line.trim_start().starts_with("const rawFindings = ["));
    assert!(line.trim_end().ends_with("];"), "line: {line}");
}

#[test]
fn null_byte_in_field_is_json_unicode_escaped_not_breakout() {
    // serde_json escapes NUL to  ; escape_for_script leaves it (not a
    // breakout char). Just assert no raw NUL in payload and document intact.
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("a\u{0}b"));
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    assert!(payload.contains(r#""a\u0000b""#), "payload: {payload}");
    assert!(!payload.contains('\u{0}'));
}

// ---------------------------------------------------------------------------
// Adversarial / evasion combinations
// ---------------------------------------------------------------------------

#[test]
fn uppercase_script_close_is_not_a_special_case_but_still_safe() {
    // The browser HTML parser is case-insensitive for </SCRIPT>. The '<' '/'
    // '>' are still escaped regardless of letter case, so it cannot break out.
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("</SCRIPT>"));
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    assert!(
        payload.contains(r#""\u003c\u002fSCRIPT\u003e""#),
        "payload: {payload}"
    );
    // No case-insensitive breakout: search raw lowercased close tag too.
    assert!(!html.to_lowercase().contains("</script><"));
    assert_eq!(html.matches("</script>").count(), 1);
}

#[test]
fn whitespace_inside_script_close_still_neutralised() {
    // `</script >` (parser tolerates trailing whitespace before '>'). The '<'
    // and '/' are escaped so it cannot terminate the element.
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("</script >"));
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    assert!(
        payload.contains(r#"\u003c\u002fscript \u003e"#),
        "payload: {payload}"
    );
    assert_eq!(html.matches("</script>").count(), 1);
}

#[test]
fn repeated_breakout_payloads_all_neutralised() {
    // Many separate fields each carrying the breakout payload: still exactly
    // one </script> and the escaped form appears many times.
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from(BREAKOUT));
    f.location.commit = Some(Arc::from(BREAKOUT));
    f.location.author = Some(Arc::from(BREAKOUT));
    f.detector_id = Arc::from(BREAKOUT);
    f.service = Arc::from(BREAKOUT);
    let html = render(&f);
    assert_eq!(
        html.matches("</script>").count(),
        1,
        "multiple poisoned fields broke out"
    );
    // The escaped breakout appears at least 5 times (one per poisoned field).
    assert!(
        html.matches(BREAKOUT_ESC).count() >= 5,
        "expected >=5 escaped copies, got {}",
        html.matches(BREAKOUT_ESC).count()
    );
}

#[test]
fn array_of_many_findings_keeps_one_script_close() {
    let mut findings = Vec::new();
    for i in 0..50 {
        let mut f = base_finding();
        f.location.file_path = Some(Arc::from(format!("</script>{i}").as_str()));
        findings.push(f);
    }
    let html = render_all(&findings);
    assert_eq!(html.matches("</script>").count(), 1);
    // 50 escaped script-closes in the payload.
    let payload = raw_findings_payload(&html);
    assert_eq!(
        payload.matches(r#"\u003c\u002fscript\u003e"#).count(),
        50,
        "expected 50 escaped closes"
    );
}

#[test]
fn nested_u2028_inside_breakout_double_escaped_form_absent() {
    // Combine a line separator with a tag close; both classes get escaped and
    // the raw bytes vanish.
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("</script>\u{2028}x"));
    let html = render(&f);
    let payload = raw_findings_payload(&html);
    assert!(
        payload.contains(r#""\u003c\u002fscript\u003e\u2028x""#),
        "payload: {payload}"
    );
    assert!(!payload.contains('\u{2028}'));
    assert_eq!(html.matches("</script>").count(), 1);
}

// ---------------------------------------------------------------------------
// Property-style loop: escape_for_script is exercised end-to-end over a corpus
// of strings; invariant = no raw <, >, /, U+2028, U+2029 ever survive in the
// inlined JSON payload, and the document keeps exactly one </script>.
// ---------------------------------------------------------------------------

#[test]
fn property_no_breakout_chars_survive_in_payload() {
    let corpus = [
        "",
        "/",
        "<",
        ">",
        "</script>",
        "//comment",
        "a/b/c/d",
        "<<<>>>",
        "path/to/</script>/file",
        "\u{2028}\u{2029}",
        "</ScRiPt\t>",
        "http://example.com/a?b=</script>",
        "unicode \u{1f600} and / slash",
        "\"quoted/<tag>\"",
        "tab\tand/newline\nand>gt",
    ];
    for s in corpus {
        let mut f = base_finding();
        f.location.file_path = Some(Arc::from(s));
        f.metadata.insert("m".to_string(), s.to_string());
        let html = render(&f);
        let payload = raw_findings_payload(&html);

        // No raw breakout characters anywhere in the attacker-influenced JSON.
        for bad in ['<', '>', '/', '\u{2028}', '\u{2029}'] {
            assert!(
                !payload.contains(bad),
                "raw {bad:?} survived for input {s:?} in payload {payload}"
            );
        }
        // Document integrity preserved.
        assert_eq!(
            html.matches("</script>").count(),
            1,
            "input {s:?} broke out of <script>"
        );
    }
}

#[test]
fn property_clean_ascii_passthrough_is_byte_for_byte() {
    // Strings with none of the five escape-trigger chars must appear verbatim
    // in the JSON payload (modulo serde's own quote/backslash handling, which
    // these inputs avoid).
    let clean = [
        "simple",
        "with spaces",
        "digits-12345",
        "under_score",
        "dot.dot.dot",
        "MiXeDcAsE",
        "unicode-é-ü-ñ",
        "emoji-\u{1f510}",
        "colon:semicolon;",
        "paren(s)[brackets]{braces}",
    ];
    for s in clean {
        let mut f = base_finding();
        f.service = Arc::from(s);
        let payload = raw_findings_payload(&render(&f)).to_string();
        assert!(
            payload.contains(&format!(r#""service":"{s}""#)),
            "clean input {s:?} not passed through verbatim: {payload}"
        );
    }
}
