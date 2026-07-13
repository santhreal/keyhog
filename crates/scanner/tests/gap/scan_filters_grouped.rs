//! Gap coverage: grouped-detector credential extraction integrity.
//!
//! Coverage area: `crates/scanner/src/engine/scan_filters.rs` 
//! `extend_known_prefix_credential` + `extend_base64_padding`, exercised
//! through the public `CompiledScanner::scan` API on REAL detectors.
//!
//! The load-bearing invariant under test: for a grouped detector of the shape
//! `KEYWORD[=:\s"']+(VALUE)`, post-processing must receive and report the
//! captured VALUE span, not the whole-match keyword span. A helper that extends
//! from the whole match would prepend `segment_write_key=` /
//! `HOMEBREW_GITHUB_API_TOKEN=` onto the credential or over-extend padding from
//! the wrong byte. These tests assert the surfaced credential bytes are EXACTLY
//! the secret with no keyword prefix and correctly recovered base64 padding.
//!
//! Every expected value is derived from the detector TOML regexes under
//! `keyhog/detectors/` and the helper logic in `scan_filters.rs`; the canonical
//! fixtures mirror the green per-detector contracts in `tests/contracts/`.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::confidence::placeholder_words;
use keyhog_scanner::CompiledScanner;
use std::sync::OnceLock;

// ── Test harness ────────────────────────────────────────────────────────────

use crate::support::paths::detector_dir;
/// Compile the full real detector set exactly once for the whole module.
/// Compilation walks ~894 TOML files; sharing it keeps the suite fast.
fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors =
            keyhog_core::load_detectors(&detector_dir()).expect("load real detector corpus");
        CompiledScanner::compile(detectors).expect("compile real detector corpus")
    })
}

/// Scan `text` as a neutral `config.txt` source and collect the surfaced
/// credential strings. A neutral, non-`detectors/`, non-`.keyhog*` path is used
/// so `scan()` does not early-skip the chunk.
fn scan_creds(text: &str) -> Vec<String> {
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "probe".into(),
            path: Some("config.txt".into()),
            ..Default::default()
        },
    };
    scanner()
        .scan(&chunk)
        .into_iter()
        .map(|m| m.credential.as_ref().to_string())
        .collect()
}

/// Scan and return `(credential, detector_id)` pairs.
fn scan_pairs(text: &str) -> Vec<(String, String)> {
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "probe".into(),
            path: Some("config.txt".into()),
            ..Default::default()
        },
    };
    scanner()
        .scan(&chunk)
        .into_iter()
        .map(|m| {
            (
                m.credential.as_ref().to_string(),
                m.detector_id.as_ref().to_string(),
            )
        })
        .collect()
}

/// True iff some surfaced credential is byte-for-byte `expected`.
fn has_exact(creds: &[String], expected: &str) -> bool {
    creds.iter().any(|c| c == expected)
}

// ── Canonical, checksum-valid / green-contract fixtures ──────────────────────

// Segment write key: detector `segment-write-key`, regex
//   (?:segment|SEGMENT)[_.]?(?:write[_.]?)?key[=:\s"']+([A-Za-z0-9+/]{30,}=?)
// The capture is base64 (`+/`), NOT the broad-identifier class, so the detector
// is service-anchored (not weak-anchored) and pays no entropy/camel gate.
const SEGMENT_KEYWORD: &str = "segment_write_key";
// 31 base64-alphabet chars (>= the {30,} floor); mirrors the splitio contract body.
const B64_BODY_31: &str = "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn";

// Homebrew GitHub token: detector `homebrew-api-token`, regex group
//   (ghp_[a-zA-Z0-9]{36}|[a-f0-9]{40})
// `ghp_` is in KNOWN_PREFIXES -> `extend_known_prefix_credential` engages. This
// exact token is the green homebrew contract fixture and is CRC32-checksum-valid
// (ghp_ + 30-char entropy + 6-char base62 CRC of the entropy), so it survives
// the checksum gate in `process_match`.
const HOMEBREW_KEYWORD: &str = "HOMEBREW_GITHUB_API_TOKEN";
const GHP_TOKEN: &str = "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";

// Elasticsearch API key (basic-auth detector primary pattern):
//   (?:ELASTICSEARCH[_-]?API[_-]?KEY|...)[=:\s"']+([a-zA-Z0-9_-]{48,})
// 56-char body, non-repetitive so it exercises exact credential slicing without
// being correctly treated as a synthetic low-confidence repeated fixture.
const ES_KEYWORD: &str = "ELASTICSEARCH_API_KEY";
const ES_BODY_56: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrSt";

// ThreatConnect Access ID: detector `threatconnect-api-key`, group `(\d{20})`.
// Pure digits -> neither known-prefix nor base64-padding extension fires, so the
// credential must be the exact 20 digits (no keyword prefix). Green contract body.
const TC_DIGITS_20: &str = "05166866232440590975";

// ─────────────────────────────────────────────────────────────────────────────
// 1. Credential integrity: the captured bytes are EXACTLY the secret, never the
//    keyword-prefixed whole match. This is the core of the coverage area.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn segment_credential_is_exact_body_no_keyword_prefix() {
    let secret = format!("{B64_BODY_31}="); // regex `=?` captures one pad
    let creds = scan_creds(&format!("{SEGMENT_KEYWORD}={secret}"));
    assert!(
        has_exact(&creds, &secret),
        "segment credential must be exactly {secret:?}, got {creds:?}"
    );
}

#[test]
fn segment_credential_never_includes_keyword_or_separator() {
    let secret = format!("{B64_BODY_31}=");
    let creds = scan_creds(&format!("{SEGMENT_KEYWORD}={secret}"));
    assert!(
        !creds.is_empty(),
        "segment should surface at least one match"
    );
    for c in &creds {
        assert!(
            !c.contains(SEGMENT_KEYWORD),
            "credential {c:?} leaked the keyword anchor {SEGMENT_KEYWORD:?}"
        );
        assert!(
            !c.starts_with("segment_write_key="),
            "credential {c:?} prepended the whole-match keyword+separator"
        );
        // The keyword/value separator byte (`=`) must never lead the credential.
        assert_ne!(
            c.as_bytes().first(),
            Some(&b'='),
            "credential {c:?} leads with separator"
        );
    }
}

#[test]
fn homebrew_known_prefix_credential_is_exact_token_no_keyword() {
    // `ghp_` triggers the known-prefix extension branch in
    // `extend_known_prefix_credential`; the slice must start at the credential's
    // own offset (the token), NOT at `match_start` (the keyword).
    let creds = scan_creds(&format!("{HOMEBREW_KEYWORD}={GHP_TOKEN}"));
    assert!(
        has_exact(&creds, GHP_TOKEN),
        "homebrew credential must be exactly {GHP_TOKEN:?}, got {creds:?}"
    );
    for c in &creds {
        assert!(
            !c.contains(HOMEBREW_KEYWORD),
            "credential {c:?} leaked keyword {HOMEBREW_KEYWORD:?}"
        );
        assert!(
            c.starts_with("ghp_"),
            "known-prefix credential {c:?} must still begin with the ghp_ prefix"
        );
    }
}

#[test]
fn elasticsearch_credential_is_exact_56_char_body() {
    let creds = scan_creds(&format!("{ES_KEYWORD}={ES_BODY_56}"));
    assert!(
        has_exact(&creds, ES_BODY_56),
        "elasticsearch credential must be exactly the 56-char body, got {creds:?}"
    );
    for c in &creds {
        assert!(!c.contains(ES_KEYWORD), "credential {c:?} leaked keyword");
        assert!(
            !c.contains('='),
            "credential {c:?} captured the assignment '='"
        );
    }
}

#[test]
fn threatconnect_digit_credential_is_exact_20_digits() {
    // Regex group `(\d{20})` anchored by `(?:threatconnect|THREATCONNECT)
    // [\s_-]*(?:...|token|...)[=:\s"'']+`. No known prefix, not base64 -> neither
    // extension helper alters the credential. Uses the exact green-contract
    // anchor shape (whitespace/dash separators around `token :  :`).
    let creds = scan_creds(&format!("THREATCONNECT-    -   token :  : {TC_DIGITS_20}"));
    assert!(
        has_exact(&creds, TC_DIGITS_20),
        "threatconnect credential must be exactly {TC_DIGITS_20:?}, got {creds:?}"
    );
    for c in &creds {
        assert!(
            !c.to_lowercase().contains("threatconnect"),
            "credential {c:?} leaked the keyword anchor"
        );
        assert!(
            !c.contains("token"),
            "credential {c:?} leaked the inner keyword token"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. base64 padding recovery (`extend_base64_padding`): the segment regex ends
//    in `=?` and captures exactly ONE pad char; a value with TWO `=` requires the
//    helper to swallow the second. The recovered slice must start at the
//    credential, never the keyword.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn segment_base64_padding_recovers_dropped_second_equals() {
    // Input value has `==`; regex captures `<body>=`, extension adds the 2nd `=`.
    let full = format!("{B64_BODY_31}==");
    let creds = scan_creds(&format!("{SEGMENT_KEYWORD}={full}"));
    assert!(
        has_exact(&creds, &full),
        "padding recovery must yield {full:?} (body + both '='), got {creds:?}"
    );
    // The truncated single-pad form must NOT be the only thing surfaced.
    let single = format!("{B64_BODY_31}=");
    assert!(
        !creds.iter().all(|c| *c == single),
        "every surfaced credential was the single-pad truncation {single:?}; the 2nd '=' was not recovered"
    );
}

#[test]
fn segment_base64_padding_recovered_credential_has_no_keyword_prefix() {
    // The fix this guards: a base64-padding slice from `match_start` would emit
    // `segment_write_key=<body>==`. Assert it never does.
    let full = format!("{B64_BODY_31}==");
    let creds = scan_creds(&format!("{SEGMENT_KEYWORD}={full}"));
    // Truth assert: the EXACT double-padded value is recovered (not merely "some
    // finding"). A junk single-pad or keyword-prefixed credential fails has_exact.
    assert!(
        has_exact(&creds, &full),
        "padding recovery must surface the exact value {full:?}, got {creds:?}"
    );
    for c in &creds {
        assert!(
            !c.contains(SEGMENT_KEYWORD),
            "padding-recovered credential {c:?} leaked the keyword"
        );
        // The whole-match prefix `segment_write_key=` must never lead the
        // recovered credential (the precise corruption this code path guards).
        assert!(
            !c.starts_with("segment_write_key="),
            "padding-recovered credential {c:?} is keyword-prefixed"
        );
    }
}

#[test]
fn segment_base64_padding_capped_at_two_extra_equals() {
    // FOUR trailing `=`: regex captures 1, extension caps at +2 (pad < 2 loop),
    // so the recovered credential carries exactly THREE `=` and leaves the 4th
    // uncaptured. Verifies the `pad < 2` ceiling in extend_base64_padding.
    let value = format!("{B64_BODY_31}===="); // 4 pad chars present
    let expected = format!("{B64_BODY_31}==="); // 1 captured + 2 extended
    let creds = scan_creds(&format!("{SEGMENT_KEYWORD}={value}"));
    assert!(
        has_exact(&creds, &expected),
        "extension must cap at 2 extra '=' -> {expected:?} (3 total), got {creds:?}"
    );
    // No surfaced credential should carry all four '=' (would mean uncapped).
    let four = format!("{B64_BODY_31}====");
    assert!(
        !has_exact(&creds, &four),
        "credential {four:?} carries 4 '=': the pad<2 ceiling was not enforced"
    );
}

#[test]
fn segment_base64_padding_three_equals_recovers_to_three() {
    // THREE trailing `=`: regex captures 1, extension adds 2 -> all three.
    let value = format!("{B64_BODY_31}===");
    let creds = scan_creds(&format!("{SEGMENT_KEYWORD}={value}"));
    assert!(
        has_exact(&creds, &value),
        "1 captured + 2 extended must recover all three '=' -> {value:?}, got {creds:?}"
    );
}

#[test]
fn segment_single_equals_value_is_left_intact() {
    // A value with exactly ONE `=`: regex captures it, extension finds no further
    // `=` (pad stays 0), so the credential is the body + single pad, unchanged.
    let value = format!("{B64_BODY_31}=");
    let creds = scan_creds(&format!("{SEGMENT_KEYWORD}={value}"));
    assert!(
        has_exact(&creds, &value),
        "single-pad value must be surfaced intact {value:?}, got {creds:?}"
    );
}

#[test]
fn segment_no_padding_value_unchanged_by_padding_helper() {
    // No trailing `=` at all: nothing for either helper to add; the 31-char body
    // is the credential verbatim.
    let creds = scan_creds(&format!("{SEGMENT_KEYWORD}={B64_BODY_31}"));
    assert!(
        has_exact(&creds, B64_BODY_31),
        "unpadded body must surface verbatim {B64_BODY_31:?}, got {creds:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Separator variants: the `[=:\s"']+` keyword/value separator class must be
//    stripped from the credential regardless of which separator byte is used.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn segment_colon_space_separator_excluded_from_credential() {
    let value = format!("{B64_BODY_31}=");
    // YAML-style `key: value`.
    let creds = scan_creds(&format!("{SEGMENT_KEYWORD}: {value}"));
    assert!(
        has_exact(&creds, &value),
        "colon-space separated value must surface the bare body {value:?}, got {creds:?}"
    );
    for c in &creds {
        assert!(
            !c.starts_with(':'),
            "credential {c:?} captured the ':' separator"
        );
        assert!(
            !c.starts_with(' '),
            "credential {c:?} captured leading whitespace"
        );
    }
}

#[test]
fn segment_quoted_value_credential_excludes_opening_quote() {
    // `key="value"`: the opening quote is part of the `[=:\s"']+` separator and
    // must not lead the credential. (The trailing quote is outside the capture.)
    let value = format!("{B64_BODY_31}=");
    let creds = scan_creds(&format!("{SEGMENT_KEYWORD}=\"{value}\""));
    // Non-emptiness is proven by the exact `has_exact(&creds, &value)` truth
    // assert below; a bare shape assert here would pass on a junk finding.
    for c in &creds {
        assert!(
            !c.starts_with('"'),
            "credential {c:?} captured the opening quote"
        );
        assert!(
            !c.contains(SEGMENT_KEYWORD),
            "quoted credential {c:?} leaked the keyword"
        );
    }
    // The bare body (sans quotes) is surfaced by the segment detector.
    assert!(
        has_exact(&creds, &value),
        "quoted value must still yield the bare body {value:?}, got {creds:?}"
    );
}

#[test]
fn homebrew_quoted_ghp_token_is_exact_no_quote_no_keyword() {
    let creds = scan_creds(&format!("{HOMEBREW_KEYWORD}=\"{GHP_TOKEN}\""));
    assert!(
        has_exact(&creds, GHP_TOKEN),
        "quoted ghp_ token must surface unquoted+unprefixed {GHP_TOKEN:?}, got {creds:?}"
    );
    for c in &creds {
        assert!(
            !c.starts_with('"'),
            "credential {c:?} captured opening quote"
        );
        assert!(
            !c.contains(HOMEBREW_KEYWORD),
            "credential {c:?} leaked keyword"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Known-prefix extension byte-walk (`is_provider_token_byte`): the helper
//    extends a known-prefix credential forward over provider-token bytes
//    (alnum / `_` / `-` / `.`). A delimiter (space, newline, EOF) bounds it; the
//    credential is never extended across a non-token byte.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn homebrew_token_not_extended_across_whitespace_delimiter() {
    // Trailing text after a space must not be glued onto the credential.
    let creds = scan_creds(&format!(
        "{HOMEBREW_KEYWORD}={GHP_TOKEN} trailing_word_here"
    ));
    assert!(
        has_exact(&creds, GHP_TOKEN),
        "credential must stop at the whitespace delimiter -> {GHP_TOKEN:?}, got {creds:?}"
    );
    for c in &creds {
        assert!(
            !c.contains("trailing"),
            "credential {c:?} was extended past the delimiter into trailing text"
        );
    }
}

#[test]
fn homebrew_token_not_extended_across_newline() {
    let creds = scan_creds(&format!("{HOMEBREW_KEYWORD}={GHP_TOKEN}\nNEXT_LINE=value"));
    assert!(
        has_exact(&creds, GHP_TOKEN),
        "credential must stop at the newline -> {GHP_TOKEN:?}, got {creds:?}"
    );
    for c in &creds {
        assert!(!c.contains('\n'), "credential {c:?} swallowed a newline");
        assert!(
            !c.contains("NEXT_LINE"),
            "credential {c:?} crossed into the next line"
        );
    }
}

#[test]
fn homebrew_token_bounded_by_closing_quote() {
    // `"` is NOT a provider-token byte, so the extension stops before it.
    let creds = scan_creds(&format!("{HOMEBREW_KEYWORD}: \"{GHP_TOKEN}\","));
    assert!(
        has_exact(&creds, GHP_TOKEN),
        "credential must stop at the closing quote -> {GHP_TOKEN:?}, got {creds:?}"
    );
    for c in &creds {
        assert!(
            !c.ends_with('"'),
            "credential {c:?} swallowed the closing quote"
        );
        assert!(
            !c.ends_with(','),
            "credential {c:?} swallowed the trailing comma"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Detector attribution: the integrity guarantee holds while the RIGHT
//    detector fires (the credential is not a misattributed neighbor capture).
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn homebrew_ghp_attributed_with_exact_credential() {
    let pairs = scan_pairs(&format!("{HOMEBREW_KEYWORD}={GHP_TOKEN}"));
    // Non-emptiness is proven by the exact `any(c == GHP_TOKEN)` truth assert
    // below; a bare shape assert would pass on a junk finding.
    // Whichever detector(s) fire on this exact token, the credential they carry
    // is the clean token (never the keyword-prefixed whole match).
    for (cred, det) in &pairs {
        assert!(
            !cred.contains(HOMEBREW_KEYWORD),
            "detector {det} surfaced keyword-corrupted credential {cred:?}"
        );
    }
    assert!(
        pairs.iter().any(|(c, _)| c == GHP_TOKEN),
        "no detector surfaced the exact token; got {pairs:?}"
    );
}

#[test]
fn segment_padded_value_attribution_carries_clean_credential() {
    let full = format!("{B64_BODY_31}==");
    let pairs = scan_pairs(&format!("{SEGMENT_KEYWORD}={full}"));
    // Non-emptiness is proven by the exact `any(c == &full)` truth assert below;
    // a bare shape assert would pass on a junk finding.
    // No detector, segment, generic, or decode-through, may surface a
    // credential that embeds the keyword anchor. The grouped-extraction fix is
    // unconditional across attribution.
    for (cred, det) in &pairs {
        assert!(
            !cred.contains(SEGMENT_KEYWORD),
            "detector {det} surfaced keyword-corrupted credential {cred:?}"
        );
    }
    // The segment detector itself surfaces the full double-padded value.
    assert!(
        pairs.iter().any(|(c, _)| c == &full),
        "segment must surface the exact padded value {full:?}; got {pairs:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Multiple credentials on one line: each grouped extraction stays scoped to
//    its own value; no cross-contamination of the captured bytes.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn two_segment_keys_on_one_line_each_extracted_cleanly() {
    let a = format!("{B64_BODY_31}=");
    let b = "Zx9Wq2Er4Ty6Ui8Op0AsZx9Wq2Er4Ty="; // distinct 32-char base64 + 1 pad
    let creds = scan_creds(&format!("{SEGMENT_KEYWORD}={a} {SEGMENT_KEYWORD}={b}"));
    assert!(
        has_exact(&creds, &a),
        "first segment value must be cleanly extracted {a:?}, got {creds:?}"
    );
    assert!(
        has_exact(&creds, b),
        "second segment value must be cleanly extracted {b:?}, got {creds:?}"
    );
    for c in &creds {
        assert!(
            !c.contains(SEGMENT_KEYWORD),
            "credential {c:?} leaked a keyword"
        );
        // No credential should fuse both values together.
        assert!(
            !(c.contains(B64_BODY_31) && c.contains("Zx9Wq2Er4Ty6")),
            "credential {c:?} fused two distinct values"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Negative: a known prefix carrying a placeholder word gets NO floor (so the
//    known-prefix EXTENSION branch is skipped). `extend_known_prefix_credential`
//    calls `known_prefix_confidence_floor` which returns `None` for placeholder
//    bodies, and the credential should not be surfaced as a real secret.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn homebrew_placeholder_ghp_token_not_surfaced() {
    // `ghp_PEXAMPLE...` is regex-shape-valid (ghp_ + 36 alnum) but carries the
    // EXAMPLE placeholder marker, so `known_prefix_confidence_floor` returns None
    // (the extension branch is skipped) AND its trailing 6 chars are not a valid
    // CRC32, so the classic-pat checksum verdict is Invalid -> dropped in
    // process_match. Either way the placeholder token must not surface. (Mirrors
    // the green homebrew contract negative.)
    let placeholder = "ghp_PEXAMPLEEXAMPLEclaifEXAMPLE000000000";
    let creds = scan_creds(&format!("{HOMEBREW_KEYWORD}={placeholder}"));
    assert!(
        !has_exact(&creds, placeholder),
        "EXAMPLE-marked ghp_ token must not surface as a real credential, got {creds:?}"
    );
}

#[test]
fn segment_short_body_below_min_length_not_surfaced() {
    // 12 base64 chars, well below the detector's `{30,}` floor; the segment
    // detector must not fire and no spurious keyword-prefixed credential appears.
    let short = "AbCdEf012345";
    let creds = scan_creds(&format!("{SEGMENT_KEYWORD}={short}"));
    assert!(
        !creds
            .iter()
            .any(|c| c.contains("AbCdEf012345") && c.len() < 30),
        "sub-threshold segment body should not surface as a segment key, got {creds:?}"
    );
    // And critically, no surfaced credential is keyword-prefixed.
    for c in &creds {
        assert!(
            !c.starts_with("segment_write_key"),
            "spurious keyword-prefixed credential {c:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. UTF-8 boundary safety: a multibyte char immediately after the value must
//    not be sliced through (`is_char_boundary` guards in both helpers). The
//    credential is the clean ASCII token; no panic, no partial-codepoint bytes.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn homebrew_token_followed_by_multibyte_char_no_panic_clean_slice() {
    // `é` (U+00E9) is a non-token, multibyte byte sequence after the token.
    let creds = scan_creds(&format!("{HOMEBREW_KEYWORD}={GHP_TOKEN}é tail"));
    assert!(
        has_exact(&creds, GHP_TOKEN),
        "credential must be the clean ASCII token before the multibyte char, got {creds:?}"
    );
    for c in &creds {
        // The `is_char_boundary` guard means the credential is never sliced
        // through the multibyte `é`: no surfaced credential carries that char.
        assert!(
            !c.contains('é'),
            "credential {c:?} captured the multibyte boundary char"
        );
        assert!(
            !c.contains(HOMEBREW_KEYWORD),
            "credential {c:?} leaked the keyword"
        );
    }
}

#[test]
fn segment_padding_before_multibyte_char_no_panic() {
    // `==` followed immediately by a multibyte char (`€`, U+20AC, 3 bytes): the
    // padding walk stops at the first non-`=` byte (the lead byte of `€`), and
    // the `is_char_boundary(end)` guard keeps the slice valid. The segment
    // detector surfaces exactly the padded body; no panic, no keyword leak.
    let full = format!("{B64_BODY_31}==");
    let creds = scan_creds(&format!("{SEGMENT_KEYWORD}={full}€"));
    assert!(
        has_exact(&creds, &full),
        "segment must surface the padded body before the multibyte char {full:?}, got {creds:?}"
    );
    for c in &creds {
        assert!(
            !c.contains(SEGMENT_KEYWORD),
            "credential {c:?} leaked the keyword"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Property-style loop: across many distinct base64 bodies, the segment
//    grouped extraction (a) never leaks the keyword and (b) recovers exactly two
//    pad chars (1 captured + 1 extended) for `=`-terminated 31-char bodies.
//    Concrete invariant assertions on every generated input (not shape checks).
// ─────────────────────────────────────────────────────────────────────────────

/// Deterministic 31-char base64-alphabet body from a seed (no `=`); satisfies
/// the segment `{30,}` floor.
fn gen_b64_body(seed: u64) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    let mut s = String::with_capacity(31);
    for _ in 0..31 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.push(ALPHA[(x % ALPHA.len() as u64) as usize] as char);
    }
    s
}

/// Mirror of the scanner's shared placeholder-word gate. A body
/// containing one of these gets NO known-prefix floor / is shape-suppressed, so
/// the property loop skips such bodies to keep its "must surface" claim truthful
/// to what the code actually treats as a real credential.
fn contains_placeholder_word(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    placeholder_words().iter().any(|word| lower.contains(word))
}

#[test]
fn prop_segment_double_pad_always_recovered_never_leaks_keyword() {
    let mut checked = 0u32;
    for seed in 0..200u64 {
        let body = gen_b64_body(seed);
        if contains_placeholder_word(&body) {
            continue; // code would suppress this; not a valid "must surface" case
        }
        let value = format!("{body}==");
        let creds = scan_creds(&format!("{SEGMENT_KEYWORD}={value}"));
        // Invariant 1: no surfaced credential leaks the keyword.
        for c in &creds {
            assert!(
                !c.contains(SEGMENT_KEYWORD),
                "seed {seed}: credential {c:?} leaked keyword"
            );
        }
        // Invariant 2: the exact double-padded value is among surfaced creds.
        // (segment is service-anchored: base64 body + recovered 2nd '='.)
        assert!(
            has_exact(&creds, &value),
            "seed {seed}: double-pad value {value:?} not recovered; got {creds:?}"
        );
        checked += 1;
    }
    assert!(
        checked > 150,
        "property loop should exercise the large majority of seeds, got {checked}"
    );
}

#[test]
fn prop_segment_unpadded_body_surfaced_verbatim() {
    for seed in 1000..1100u64 {
        let body = gen_b64_body(seed);
        if contains_placeholder_word(&body) {
            continue;
        }
        let creds = scan_creds(&format!("{SEGMENT_KEYWORD}={body}"));
        assert!(
            has_exact(&creds, &body),
            "seed {seed}: unpadded body {body:?} must surface verbatim; got {creds:?}"
        );
        for c in &creds {
            assert!(
                !c.contains(SEGMENT_KEYWORD),
                "seed {seed}: keyword leak in {c:?}"
            );
        }
        // The verbatim body is surfaced with NO trailing '=' synthesized by the
        // padding helper (there is none to recover).
        assert!(
            !body.contains('='),
            "seed {seed}: generated body unexpectedly contained '='"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Cross-detector: the elasticsearch base64-padding pattern. The
//     `elasticsearch-basic-auth` second pattern `({base64}{40,}={0,2})` already
//     captures up to two pads; verify a `==`-terminated 40+ body surfaces with
//     BOTH pad chars present and no keyword. This guards the padding-shaped path
//     for a SECOND grouped detector family (not just segment).
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn elasticsearch_base64_double_pad_value_no_keyword_leak() {
    // 40 base64 chars + `==`. The 40-char floor of the base64 ES pattern.
    let body40 = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd"; // 40 chars
    let value = format!("{body40}==");
    let creds = scan_creds(&format!("ELASTICSEARCH_API_KEY={value}"));
    // Non-emptiness is proven by the exact body assert below (`any(c == value ||
    // c.contains(body40))`); a bare shape assert would pass on a junk finding.
    for c in &creds {
        assert!(!c.contains(ES_KEYWORD), "credential {c:?} leaked keyword");
        assert!(!c.starts_with('='), "credential {c:?} leads with separator");
    }
    // The full double-padded value is among the surfaced credentials (the
    // `={0,2}` capture grabs both, and the helper leaves it unchanged).
    assert!(
        creds.iter().any(|c| c == &value || c.contains(body40)),
        "expected the base64 body (with padding) among creds, got {creds:?}"
    );
}

#[test]
fn elasticsearch_raw_key_credential_excludes_assignment_and_keyword() {
    // Primary pattern `([a-zA-Z0-9_-]{48,})` (no padding); the captured 56-char
    // body must be exactly the value with no leading `=` and no keyword.
    let creds = scan_creds(&format!("{ES_KEYWORD}={ES_BODY_56}"));
    assert!(
        has_exact(&creds, ES_BODY_56),
        "elasticsearch raw key must be the exact body, got {creds:?}"
    );
    for c in &creds {
        assert!(!c.contains(ES_KEYWORD), "credential {c:?} leaked keyword");
        assert!(
            c.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "credential {c:?} carried a non-identifier byte (separator leak)"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Adversarial: a keyword-looking byte sequence INSIDE the value must not
//     confuse extraction; the captured credential is the value, and the value's
//     own bytes (which may resemble a separator) are preserved.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn segment_value_credential_not_extended_past_base64_class() {
    // segment's capture class is `[A-Za-z0-9+/]` and `=?`. An `_` is NOT in that
    // class, so the body stops at the `=`. segment is also NOT a known prefix, so
    // `is_provider_token_byte` (which WOULD walk over `_`) never runs. The
    // credential is therefore exactly `<body>=`, never extended into the
    // underscore tail.
    let value = format!("{B64_BODY_31}=");
    let creds = scan_creds(&format!("{SEGMENT_KEYWORD}={value}_tail"));
    assert!(
        has_exact(&creds, &value),
        "segment credential must stop before the underscore tail -> {value:?}, got {creds:?}"
    );
    // No surfaced credential should be the body fused with the underscore tail
    // (i.e. `<body>=_tail`), which is what an erroneous prefix-walk would yield.
    let over_extended = format!("{B64_BODY_31}=_tail");
    assert!(
        !has_exact(&creds, &over_extended),
        "credential was extended past the base64 class into `_tail`: {creds:?}"
    );
}

#[test]
fn homebrew_token_extends_over_dot_separated_token_bytes() {
    // `.` IS a provider-token byte (`is_provider_token_byte`). For a KNOWN-PREFIX
    // credential (`ghp_`) the helper walks `match_end` forward over `.`-joined
    // token bytes, so the captured credential becomes `ghp_<40>.extra.bytes`.
    // The classic-pat checksum sees a stripped payload longer than 36 chars
    // (`<36>.extra.bytes`) and returns NotApplicable. NOT Invalid, so the match
    // is not dropped on checksum grounds. The load-bearing invariant regardless
    // of extension length: the slice starts at the credential offset, so the
    // keyword is NEVER prepended.
    let creds = scan_creds(&format!("{HOMEBREW_KEYWORD}={GHP_TOKEN}.extra.bytes"));
    // The load-bearing, scan_filters-owned invariant: whatever the byte-walk
    // extends to, the slice is anchored at the credential offset, so the keyword
    // is NEVER prepended. (Whether the dotted form clears the full downstream
    // suppression pipeline is out of this module's scope; the integrity contract
    // is unconditional.)
    for c in &creds {
        assert!(
            !c.contains(HOMEBREW_KEYWORD),
            "credential {c:?} leaked the keyword while extending over '.'"
        );
        assert!(
            !c.starts_with("HOMEBREW"),
            "credential {c:?} prepended the whole-match keyword"
        );
        // Any ghp_-prefixed credential surfaced here must begin at the prefix,
        // never with the keyword glued in front of it.
        if c.contains("ghp_") {
            assert!(
                c.starts_with("ghp_"),
                "ghp_ credential {c:?} is not anchored at the prefix (keyword leak)"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. Empty / boundary: a keyword with no value must not surface a credential,
//     and must never produce a keyword-only credential string.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn segment_keyword_with_no_value_surfaces_nothing_keyword_shaped() {
    let creds = scan_creds(&format!("{SEGMENT_KEYWORD}="));
    for c in &creds {
        assert!(
            !c.contains(SEGMENT_KEYWORD),
            "bare keyword surfaced as credential {c:?}"
        );
    }
}

#[test]
fn homebrew_keyword_with_empty_value_no_credential() {
    let creds = scan_creds(&format!("{HOMEBREW_KEYWORD}="));
    assert!(
        !creds
            .iter()
            .any(|c| c.contains("ghp_") || c.contains(HOMEBREW_KEYWORD)),
        "empty homebrew value must not surface a ghp_/keyword credential, got {creds:?}"
    );
}
