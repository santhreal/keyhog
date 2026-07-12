//! Contract lock for the shared `support::vendorgen` vendor recall-lock harness.
//! Every per-vendor recall runner now depends on these generators and scan
//! predicates, so their guarantees are pinned here in one place: the LCG is
//! deterministic and seed-separated, each generator emits the exact requested
//! length drawn from exactly its alphabet, the UUID builder is canonical, and
//! the scan predicates round-trip a real (non-checksum) vendor token through the
//! on-disk detector set. A regression in any of these would silently weaken
//! every vendor lock that builds on it.

mod support;
use support::vendorgen::{
    alnum, detected, digits, fires, fires_any, gen, hex, lcnum, scan_ids, surfaces_under,
    surfaces_under_any, uppernum, uuid, ALNUM, DIGITS, HEX, LCNUM, UPPERNUM,
};

/// Non-checksum vendor tokens whose detectors are proven to fire; used to
/// exercise the scan predicates without a checksum-gated fixture.
const HF: &[&str] = &[
    "huggingface-api-key",
    "huggingface-org-token",
    "huggingface-user-token",
];

fn all_in(s: &str, charset: &[u8]) -> bool {
    s.bytes().all(|b| charset.contains(&b))
}

// ── generator: determinism + boundaries ─────────────────────────────────────

#[test]
fn gen_is_deterministic() {
    assert_eq!(gen(20, 42, HEX), gen(20, 42, HEX));
}

#[test]
fn gen_distinct_seeds_differ() {
    assert_ne!(gen(32, 1, HEX), gen(32, 2, HEX));
}

#[test]
fn gen_zero_length_is_empty() {
    assert_eq!(gen(0, 7, HEX), "");
}

#[test]
fn gen_single_char_charset_is_constant() {
    assert_eq!(gen(10, 5, b"x"), "xxxxxxxxxx");
}

#[test]
fn gen_respects_requested_length() {
    for n in [1usize, 7, 32, 64, 200] {
        assert_eq!(gen(n, 3, ALNUM).chars().count(), n, "length {n}");
    }
}

// ── generator: exact length + alphabet per helper ───────────────────────────

#[test]
fn hex_has_exact_length() {
    assert_eq!(hex(37, 1).len(), 37);
}

#[test]
fn hex_is_lowercase_hex() {
    assert!(all_in(&hex(64, 3), HEX), "hex must draw only from [0-9a-f]");
}

#[test]
fn alnum_has_exact_length() {
    assert_eq!(alnum(24, 1).len(), 24);
}

#[test]
fn alnum_is_alphanumeric() {
    assert!(all_in(&alnum(50, 2), ALNUM));
}

#[test]
fn lcnum_is_lowercase_alnum() {
    assert!(all_in(&lcnum(30, 4), LCNUM));
}

#[test]
fn uppernum_is_upper_alnum() {
    assert!(all_in(&uppernum(27, 6), UPPERNUM));
}

#[test]
fn digits_are_decimal() {
    assert!(all_in(&digits(10, 8), DIGITS));
}

#[test]
fn charsets_have_expected_sizes() {
    assert_eq!(HEX.len(), 16);
    assert_eq!(ALNUM.len(), 62);
    assert_eq!(LCNUM.len(), 36);
    assert_eq!(UPPERNUM.len(), 36);
    assert_eq!(DIGITS.len(), 10);
}

// ── uuid builder ────────────────────────────────────────────────────────────

#[test]
fn uuid_has_canonical_length_and_dashes() {
    let u = uuid(9);
    assert_eq!(u.len(), 36);
    let dashes: Vec<usize> = u.match_indices('-').map(|(i, _)| i).collect();
    assert_eq!(dashes, vec![8, 13, 18, 23]);
}

#[test]
fn uuid_segments_are_hex() {
    let u = uuid(11);
    assert!(u.bytes().filter(|&b| b != b'-').all(|b| HEX.contains(&b)));
}

#[test]
fn uuid_is_deterministic() {
    assert_eq!(uuid(13), uuid(13));
}

#[test]
fn uuid_distinct_seeds_differ() {
    assert_ne!(uuid(13), uuid(14));
}

// ── scan predicates: real detector round-trip ───────────────────────────────

#[test]
fn scan_ids_returns_id_and_credential_for_known_token() {
    let t = format!("pplx-{}", alnum(32, 1));
    let got = scan_ids(&t);
    assert!(
        got.iter()
            .any(|(id, cred)| !id.is_empty() && cred.contains(&t)),
        "scan_ids must return a labelled match for a real token: {got:?}"
    );
}

#[test]
fn surfaces_under_matches_specific_detector() {
    let t = format!("pplx-{}", alnum(32, 2));
    assert!(surfaces_under(&t, "perplexity-api-key", &t));
}

#[test]
fn surfaces_under_rejects_wrong_detector() {
    let t = format!("pplx-{}", alnum(32, 3));
    assert!(!surfaces_under(&t, "groq-api-key", &t));
}

#[test]
fn surfaces_under_any_matches_detector_set() {
    let t = format!("hf_{}", alnum(34, 4));
    assert!(surfaces_under_any(&t, HF, &t));
}

#[test]
fn fires_agrees_with_surfaces_for_known_token() {
    let t = format!("pplx-{}", alnum(32, 5));
    assert!(fires(&t, "perplexity-api-key"));
    assert!(!fires(&t, "groq-api-key"));
}

#[test]
fn fires_any_matches_detector_set() {
    let t = format!("hf_{}", alnum(34, 6));
    assert!(fires_any(&t, HF));
}

#[test]
fn detected_true_for_known_token_false_for_prose() {
    let t = format!("pplx-{}", alnum(32, 7));
    assert!(detected(&t, &t), "a real token must be detected somewhere");
    assert!(
        !detected("the quick brown fox jumps over the lazy dog", "pplx-"),
        "plain prose must not yield a pplx- credential"
    );
}
