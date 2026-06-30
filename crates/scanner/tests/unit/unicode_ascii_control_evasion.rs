//! Contract for the unified ASCII-control evasion predicate
//! (`is_ascii_evasion_control_byte`): every C0 control (U+0000–001F) AND DEL
//! (U+007F), except the structural whitespace `\n`/`\r`/`\t`, is evasion and is
//! dropped on the normalization path so a spliced control cannot break a
//! credential body.
//!
//! Regression target: the fast-path gate and the `contains_evasion` detector
//! tested `b < 0x20`, which EXCLUDES DEL (0x7F), while the per-char Drop
//! classifier used `char::is_ascii_control()`, which INCLUDES it. A `ghp_…` with
//! a spliced DEL therefore gated to `CleanAscii`, returned `Cow::Borrowed`
//! unchanged, and the DEL broke the body regex — the secret evaded. All three
//! sites now delegate to one predicate, so DEL (and every other non-whitespace
//! control) is dropped uniformly, and legitimate `\n`/`\r`/`\t` are preserved.

use keyhog_scanner::testing::unicode_hardening::{contains_evasion, normalize_homoglyphs};
use std::borrow::Cow;

const DEL: char = '\u{7F}';

/// Splice `c` into a `ghp_` token; assert it is dropped so the token reassembles
/// AND the normalizer reports a change (`Cow::Owned`) — i.e. the fast-path gate
/// actually routed this input to the strip rather than passing it through.
fn assert_control_dropped(c: char, label: &str) {
    let text = format!("ghp_ab{c}cd");
    let normalized = normalize_homoglyphs(&text);
    assert!(
        matches!(normalized, Cow::Owned(_)),
        "{label} (U+{:04X}) must route off the clean fast path (Owned); got Borrowed",
        c as u32
    );
    assert!(
        normalized.contains("ghp_abcd") && !normalized.contains(c),
        "{label} (U+{:04X}) must be dropped so the token reassembles; got {normalized:?}",
        c as u32
    );
}

/// Assert a structural-whitespace char is preserved verbatim and not flagged.
fn assert_whitespace_preserved(c: char, label: &str) {
    let text = format!("key{c}= value");
    let normalized = normalize_homoglyphs(&text);
    assert!(
        normalized.contains(c),
        "{label} (U+{:04X}) is structural and must be preserved; got {normalized:?}",
        c as u32
    );
    assert!(
        !contains_evasion(&text),
        "{label} (U+{:04X}) is structural whitespace, not evasion",
        c as u32
    );
}

// ── DEL (0x7F): the specific desync that was a recall hole ───────────────────

#[test]
fn del_spliced_in_ghp_body_is_dropped_and_reassembles() {
    assert_control_dropped(DEL, "DELETE");
}

#[test]
fn del_makes_normalize_return_owned_not_borrowed() {
    // Before the fix this returned Borrowed (DEL gated as CleanAscii).
    let out = normalize_homoglyphs("ghp_abc\u{7F}def0123456789");
    assert!(
        matches!(out, Cow::Owned(_)),
        "DEL must no longer be treated as clean ASCII; got {out:?}"
    );
    assert_eq!(out.as_ref(), "ghp_abcdef0123456789", "got {out:?}");
}

#[test]
fn del_triggers_contains_evasion() {
    assert!(
        contains_evasion("ghp_a\u{7F}b"),
        "DEL must be reported by contains_evasion"
    );
}

#[test]
fn del_after_aws_prefix_reassembles_key() {
    let out = normalize_homoglyphs("AKIA\u{7F}QYLPMN5HFIQR7BBB");
    assert!(
        out.contains("AKIAQYLPMN5HFIQR7BBB"),
        "DEL after AKIA must be dropped; got {out:?}"
    );
}

#[test]
fn del_at_token_start_is_dropped() {
    let out = normalize_homoglyphs("\u{7F}ghp_secret");
    assert_eq!(out.as_ref(), "ghp_secret", "got {out:?}");
}

#[test]
fn del_at_token_end_is_dropped() {
    let out = normalize_homoglyphs("ghp_secret\u{7F}");
    assert_eq!(out.as_ref(), "ghp_secret", "got {out:?}");
}

#[test]
fn multiple_dels_all_dropped() {
    let out = normalize_homoglyphs("g\u{7F}h\u{7F}p\u{7F}_token");
    assert_eq!(out.as_ref(), "ghp_token", "got {out:?}");
}

#[test]
fn del_does_not_corrupt_a_following_kept_nonascii_char() {
    // DEL dropped, the (kept) é survives — proves the rebuild splices correctly
    // across an ASCII-control drop followed by a multibyte kept char.
    let out = normalize_homoglyphs("ab\u{7F}é");
    assert_eq!(out.as_ref(), "abé", "got {out:?}");
}

// ── representative C0 controls are dropped ───────────────────────────────────

#[test]
fn null_byte_0x00_dropped() {
    assert_control_dropped('\u{0}', "NULL");
}

#[test]
fn bell_0x07_dropped() {
    assert_control_dropped('\u{7}', "BELL");
}

#[test]
fn backspace_0x08_dropped() {
    assert_control_dropped('\u{8}', "BACKSPACE");
}

#[test]
fn vertical_tab_0x0b_dropped() {
    // VT is whitespace-ish but NOT in the {\n,\r,\t} structural set, so it IS
    // evasion (it can split a credential while rendering blank).
    assert_control_dropped('\u{B}', "VERTICAL TAB");
}

#[test]
fn form_feed_0x0c_dropped() {
    assert_control_dropped('\u{C}', "FORM FEED");
}

#[test]
fn escape_0x1b_dropped() {
    assert_control_dropped('\u{1B}', "ESCAPE");
}

#[test]
fn unit_separator_0x1f_dropped() {
    assert_control_dropped('\u{1F}', "UNIT SEPARATOR (top of C0)");
}

// ── completeness: every non-whitespace control in 0x00..=0x1F and DEL ─────────

#[test]
fn every_c0_control_except_whitespace_is_dropped() {
    for b in 0x00u8..=0x1F {
        if matches!(b, b'\n' | b'\r' | b'\t') {
            continue;
        }
        assert_control_dropped(b as char, "C0 control");
    }
}

#[test]
fn every_c0_control_except_whitespace_triggers_contains_evasion() {
    for b in 0x00u8..=0x1F {
        if matches!(b, b'\n' | b'\r' | b'\t') {
            continue;
        }
        let c = b as char;
        let s = format!("ghp_a{c}b");
        assert!(
            contains_evasion(&s),
            "U+{:04X} must trigger contains_evasion",
            b as u32
        );
    }
}

#[test]
fn c1_control_0x80_is_not_an_ascii_control_drop() {
    // DEL (0x7F) is the TOP of the ASCII-control set; U+0080 is a C1 control,
    // non-ASCII, and NOT covered by the ASCII-control predicate. It is kept
    // verbatim (it is in no homoglyph/zero-width/separator set either), proving
    // the predicate stops exactly at 0x7F and never bleeds into C1.
    let out = normalize_homoglyphs("a\u{80}b");
    assert!(
        out.contains('\u{80}'),
        "U+0080 (C1) must be kept, not ASCII-control-dropped; got {out:?}"
    );
    assert!(
        !contains_evasion("a\u{80}b"),
        "U+0080 is not an ASCII-control evasion"
    );
}

// ── structural whitespace is preserved (negative twins) ──────────────────────

#[test]
fn newline_preserved_not_evasion() {
    assert_whitespace_preserved('\n', "LINE FEED");
}

#[test]
fn carriage_return_preserved_not_evasion() {
    assert_whitespace_preserved('\r', "CARRIAGE RETURN");
}

#[test]
fn tab_preserved_not_evasion() {
    assert_whitespace_preserved('\t', "TAB");
}

#[test]
fn whitespace_trio_together_not_contains_evasion() {
    assert!(
        !contains_evasion("col1\tcol2\r\nrow"),
        "a TSV/CRLF row uses only structural whitespace, not evasion"
    );
}

#[test]
fn tsv_row_with_tabs_preserved_verbatim() {
    let row = "user\tpassword\tnotes";
    let out = normalize_homoglyphs(row);
    assert!(
        matches!(out, Cow::Borrowed(_)),
        "clean TSV must not allocate"
    );
    assert_eq!(out.as_ref(), row);
}

// ── clean ASCII safety ───────────────────────────────────────────────────────

#[test]
fn pure_printable_ascii_stays_borrowed() {
    let out = normalize_homoglyphs("ghp_abcdef0123456789");
    assert!(
        matches!(out, Cow::Borrowed(_)),
        "pure-ASCII must not allocate"
    );
    assert_eq!(out.as_ref(), "ghp_abcdef0123456789");
}

#[test]
fn printable_ascii_with_no_controls_not_evasion() {
    assert!(!contains_evasion("key = \"ghp_value123\""));
}

// ── mixed control + unicode evasion both stripped in one pass ─────────────────

#[test]
fn del_and_zero_width_both_removed_in_one_token() {
    // DEL (ASCII control) + ZWSP (U+200B) — different predicates, one rebuild.
    let out = normalize_homoglyphs("g\u{7F}h\u{200B}p_secret");
    assert_eq!(out.as_ref(), "ghp_secret", "got {out:?}");
}
