//! Property/adversarial contract for the shared report sanitizers in
//! `core/src/report/escape.rs` — the single owner of output escaping for every
//! reporter (SARIF/JUnit/GitLab-SAST XML, CSV, terminal text). These functions
//! are the injection boundary: an attacker who controls a scanned file path, git
//! author, or redacted credential must not be able to break out of an XML
//! attribute, close a CDATA section early, inject a spreadsheet formula, or drive
//! the operator's terminal with ANSI escapes.
//!
//! Existing coverage exercises these only THROUGH the reporters with fixed
//! crafted inputs (regression_report_junit_xml, regression_csv_formula_injection,
//! gap/report_text_csv_injection). This pins the SECURITY INVARIANTS that must
//! hold for EVERY input, not just the sampled ones:
//!   * `escape_cdata`   — the output never contains the CDATA terminator `]]>`;
//!   * `escape_xml_attr`— no raw `< > " '` survives and every `&` begins a
//!                        known entity; XML-1.0-illegal controls are stripped;
//!   * `sanitize_xml`   — strips every XML-illegal C0 control but KEEPS tab/LF/CR,
//!                        is idempotent, borrows clean input, and replaces 1:1;
//!   * `sanitize_terminal` — strips the WHOLE terminal-control class (C0, DEL,
//!                        C1), is idempotent, borrows clean input, replaces 1:1;
//!   * `is_terminal_control` — exact boundary contract (differential vs oracle).

use keyhog_core::testing::{
    escape_cdata_for_test as escape_cdata, escape_csv_for_test as escape_csv,
    escape_xml_attr_for_test as escape_xml_attr,
    is_terminal_control_for_test as is_terminal_control,
    sanitize_terminal_borrows_for_test as sanitize_terminal_borrows,
    sanitize_terminal_for_test as sanitize_terminal,
    sanitize_xml_borrows_for_test as sanitize_xml_borrows, sanitize_xml_for_test as sanitize_xml,
};
use proptest::prelude::*;

const REPLACEMENT: char = '\u{FFFD}';

/// Oracle mirroring `report::escape::is_xml_illegal_control`: a C0 control other
/// than tab/LF/CR, which XML 1.0 forbids even entity-escaped.
fn is_xml_illegal(c: char) -> bool {
    let u = c as u32;
    u < 0x20 && !matches!(u, 0x09 | 0x0A | 0x0D)
}

/// Oracle mirroring `report::escape::is_terminal_control`: C0, DEL, or C1.
fn is_term_control_oracle(c: char) -> bool {
    let u = c as u32;
    u < 0x20 || c == '\u{7F}' || (0x80..=0x9F).contains(&u)
}

/// After `escape_xml_attr`, no raw XML metacharacter may survive and every `&`
/// must open a known entity.
fn only_valid_entities_and_no_raw_metachars(s: &str) -> bool {
    if s.contains('<') || s.contains('>') || s.contains('"') || s.contains('\'') {
        return false;
    }
    let mut rest = s;
    while let Some(idx) = rest.find('&') {
        let after = &rest[idx + 1..];
        let ok = ["amp;", "lt;", "gt;", "quot;", "apos;"]
            .iter()
            .any(|e| after.starts_with(e));
        if !ok {
            return false;
        }
        rest = after;
    }
    true
}

/// Arbitrary Unicode strings that deliberately include C0/C1/DEL controls and
/// the XML/CSV metacharacters — `any::<char>()` spans the whole scalar range.
fn arb_hostile_string() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<char>(), 0..80).prop_map(|v| v.into_iter().collect())
}

/// Decode a run of concatenated `<![CDATA[...]]>` sections back to raw text, the
/// way an XML parser would (section content is literal; adjacent sections
/// concatenate). Returns `None` if the input is not a clean run of sections —
/// which for an escaped body would itself be an escaping bug. This is the oracle
/// that proves `escape_cdata` round-trips: the correct invariant is NOT "output
/// has no `]]>`" (the canonical `]]]]><![CDATA[>` escape intentionally emits
/// `]]>` as the section boundary) but "wrapping + decoding recovers the body".
fn decode_cdata_sections(xml: &str) -> Option<String> {
    const OPEN: &str = "<![CDATA[";
    let mut out = String::new();
    let mut rest = xml;
    while !rest.is_empty() {
        rest = rest.strip_prefix(OPEN)?;
        let close = rest.find("]]>")?;
        out.push_str(&rest[..close]);
        rest = &rest[close + 3..];
    }
    Some(out)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    // ── escape_cdata: the CDATA round-trip / no-premature-close invariant ────
    #[test]
    fn escape_cdata_wrapped_roundtrips_to_the_sanitized_body(s in arb_hostile_string()) {
        // The real security property: no matter what the body is, embedding the
        // escaped form in a CDATA section and decoding it recovers the body
        // (after the control sanitization escape_cdata applies). A premature
        // section close would corrupt or truncate the decoded result.
        let escaped = escape_cdata(&s);
        let wrapped = format!("<![CDATA[{escaped}]]>");
        let decoded = decode_cdata_sections(&wrapped)
            .expect("escaped body must wrap into a clean run of CDATA sections");
        prop_assert_eq!(decoded, sanitize_xml(&s));
    }

    #[test]
    fn escape_cdata_strips_all_xml_illegal_controls(s in arb_hostile_string()) {
        // escape_cdata runs sanitize_xml first, so no XML-illegal control may
        // remain (they would make the whole XML document unparseable).
        let out = escape_cdata(&s);
        prop_assert!(
            !out.chars().any(is_xml_illegal),
            "escape_cdata left an XML-illegal control byte in {out:?}"
        );
    }

    // ── escape_xml_attr: the attribute-injection invariant ──────────────────
    #[test]
    fn escape_xml_attr_leaves_no_raw_metacharacter(s in arb_hostile_string()) {
        let out = escape_xml_attr(&s);
        prop_assert!(
            only_valid_entities_and_no_raw_metachars(&out),
            "escape_xml_attr left a raw metacharacter or bad entity in {out:?}"
        );
    }

    #[test]
    fn escape_xml_attr_strips_all_xml_illegal_controls(s in arb_hostile_string()) {
        let out = escape_xml_attr(&s);
        prop_assert!(
            !out.chars().any(is_xml_illegal),
            "escape_xml_attr left an XML-illegal control byte in {out:?}"
        );
    }

    // ── sanitize_xml: strips illegal C0, KEEPS tab/LF/CR, 1:1, idempotent ────
    #[test]
    fn sanitize_xml_removes_all_illegal_controls(s in arb_hostile_string()) {
        let out = sanitize_xml(&s);
        prop_assert!(!out.chars().any(is_xml_illegal), "illegal control survived in {out:?}");
    }

    #[test]
    fn sanitize_xml_preserves_tab_lf_cr(s in arb_hostile_string()) {
        // The three whitespace controls XML 1.0 permits must pass through
        // unchanged (count-preserving), or legitimate multi-line values break.
        let out = sanitize_xml(&s);
        for ws in ['\t', '\n', '\r'] {
            prop_assert_eq!(
                s.chars().filter(|&c| c == ws).count(),
                out.chars().filter(|&c| c == ws).count(),
                "sanitize_xml altered the count of a legal whitespace control"
            );
        }
    }

    #[test]
    fn sanitize_xml_is_a_one_to_one_replacement(s in arb_hostile_string()) {
        // Each illegal control becomes exactly one U+FFFD — never dropped — so
        // char offsets used for SARIF regions stay aligned.
        let out = sanitize_xml(&s);
        prop_assert_eq!(s.chars().count(), out.chars().count(), "length changed in {:?}", out);
    }

    #[test]
    fn sanitize_xml_is_idempotent(s in arb_hostile_string()) {
        let once = sanitize_xml(&s);
        let twice = sanitize_xml(&once);
        prop_assert_eq!(once, twice);
    }

    #[test]
    fn sanitize_xml_borrows_iff_already_clean(s in arb_hostile_string()) {
        let dirty = s.chars().any(is_xml_illegal);
        // Clean input must take the zero-copy borrowed path (Law 7: no needless
        // allocation on the common path) and come back byte-identical.
        prop_assert_eq!(sanitize_xml_borrows(&s), !dirty);
        if !dirty {
            prop_assert_eq!(sanitize_xml(&s), s);
        }
    }

    // ── sanitize_terminal: strips the WHOLE control class, 1:1, idempotent ──
    #[test]
    fn sanitize_terminal_removes_all_terminal_controls(s in arb_hostile_string()) {
        let out = sanitize_terminal(&s);
        prop_assert!(
            !out.chars().any(is_term_control_oracle),
            "a terminal-control byte survived sanitize_terminal in {out:?}"
        );
    }

    #[test]
    fn sanitize_terminal_replaces_controls_with_the_replacement_char(s in arb_hostile_string()) {
        // 1:1 replacement — every stripped control becomes U+FFFD, none dropped.
        let out = sanitize_terminal(&s);
        prop_assert_eq!(s.chars().count(), out.chars().count());
        let expected_controls = s.chars().filter(|&c| is_term_control_oracle(c)).count();
        let got_replacements = out.chars().filter(|&c| c == REPLACEMENT).count();
        // Every control maps to a U+FFFD; a pre-existing U+FFFD in the input is
        // not a control, so replacements >= controls, and any surplus is input
        // U+FFFDs carried through.
        prop_assert!(got_replacements >= expected_controls);
    }

    #[test]
    fn sanitize_terminal_is_idempotent(s in arb_hostile_string()) {
        let once = sanitize_terminal(&s);
        let twice = sanitize_terminal(&once);
        prop_assert_eq!(once, twice);
    }

    #[test]
    fn sanitize_terminal_borrows_iff_already_clean(s in arb_hostile_string()) {
        let dirty = s.chars().any(is_term_control_oracle);
        prop_assert_eq!(sanitize_terminal_borrows(&s), !dirty);
        if !dirty {
            prop_assert_eq!(sanitize_terminal(&s), s);
        }
    }

    // ── is_terminal_control: exact boundary (differential vs oracle) ────────
    #[test]
    fn is_terminal_control_matches_the_oracle(c in any::<char>()) {
        prop_assert_eq!(is_terminal_control(c), is_term_control_oracle(c));
    }

    // ── escape_csv: formula-injection prefixes are guarded ──────────────────
    #[test]
    fn escape_csv_guards_formula_prefixes(rest in "[a-zA-Z0-9 ]{0,20}") {
        // A value beginning with a spreadsheet formula trigger must be prefixed
        // with a single quote so the target app treats it as text, not a formula.
        for lead in ['=', '+', '-', '@'] {
            let value = format!("{lead}{rest}");
            let out = escape_csv(&value);
            // These leads don't force RFC-4180 quoting on their own, so the guard
            // quote is the first byte of the field.
            prop_assert!(
                out.starts_with('\''),
                "escape_csv failed to guard formula prefix {lead:?}: {out:?}"
            );
        }
    }
}

// ── Fixed adversarial vectors (documented, exact bytes) ────────────────────

#[test]
fn escape_cdata_splits_the_terminator_across_two_sections() {
    // The canonical escape emits `]]>` as the intentional close-and-reopen
    // boundary, so the invariant is the ROUND-TRIP, not the absence of `]]>`.
    assert_eq!(escape_cdata("]]>"), "]]]]><![CDATA[>");
    for body in ["]]>", "]]>]]>", "safe]]>evil", "just text", "a]]>b]]>c"] {
        let wrapped = format!("<![CDATA[{}]]>", escape_cdata(body));
        assert_eq!(
            decode_cdata_sections(&wrapped).as_deref(),
            Some(body),
            "round-trip through CDATA must recover {body:?} (wrapped: {wrapped:?})"
        );
    }
    // A clean value is untouched (borrowed fast path).
    assert_eq!(escape_cdata("just text"), "just text");
}

#[test]
fn escape_xml_attr_entity_encodes_every_metacharacter() {
    assert_eq!(escape_xml_attr("<"), "&lt;");
    assert_eq!(escape_xml_attr(">"), "&gt;");
    assert_eq!(escape_xml_attr("&"), "&amp;");
    assert_eq!(escape_xml_attr("\""), "&quot;");
    assert_eq!(escape_xml_attr("'"), "&apos;");
    assert_eq!(
        escape_xml_attr("\" onload=\"alert(1)"),
        "&quot; onload=&quot;alert(1)"
    );
    // Ampersand is escaped once, not double-escaped.
    assert_eq!(escape_xml_attr("a&amp;b"), "a&amp;amp;b");
}

#[test]
fn is_terminal_control_boundary_values() {
    for c in [
        '\u{00}', '\u{1F}', '\t', '\n', '\r', '\u{1B}', '\u{7F}', '\u{80}', '\u{9F}',
    ] {
        assert!(
            is_terminal_control(c),
            "{:#x} must be a terminal control",
            c as u32
        );
    }
    for c in [' ', '~', '\u{A0}', 'A', 'z', 'é', '🔥'] {
        assert!(
            !is_terminal_control(c),
            "{:#x} must NOT be a terminal control",
            c as u32
        );
    }
}

#[test]
fn sanitize_xml_keeps_newlines_but_drops_a_null_byte() {
    assert_eq!(sanitize_xml("a\nb\tc\rd"), "a\nb\tc\rd");
    assert_eq!(sanitize_xml("a\u{0}b"), format!("a{REPLACEMENT}b"));
    assert_eq!(
        sanitize_xml("bell\u{7}here"),
        format!("bell{REPLACEMENT}here")
    );
}

#[test]
fn sanitize_terminal_drops_escape_and_newline_alike() {
    // Unlike sanitize_xml, the terminal sanitizer strips tab/LF/CR/ESC too.
    assert_eq!(
        sanitize_terminal("a\u{1B}[31mred"),
        format!("a{REPLACEMENT}[31mred")
    );
    assert_eq!(
        sanitize_terminal("line\nfeed"),
        format!("line{REPLACEMENT}feed")
    );
    assert_eq!(
        sanitize_terminal("c1\u{85}here"),
        format!("c1{REPLACEMENT}here")
    );
}
