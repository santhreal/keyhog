//! Boundary lock for detector-owned repeat-run precision heuristics.
//! `is_degenerate_repeat_at` applies each compiled detector's absolute run
//! threshold. The generic detector policy's `degenerate_run_min_length = 10`
//! boundary is a real detection contract (9 identical chars is a plausible key
//! body; 10 is not), so pin it exactly alongside custom thresholds and the
//! run-length and ratio primitives.
//! These `pub(crate)` and private items are unreachable from an external
//! `tests/` target, so the white-box tests live here.

use super::{
    apply_path_confidence_penalties, apply_post_ml_penalties_with_encoded_text_lift,
    is_degenerate_repeat_at, longest_repeat_run_len, max_repeat_run, FIXTURE_PATH_COMPONENTS,
};

fn post_match_policy() -> keyhog_core::DetectorPostMatchConfidenceSpec {
    keyhog_core::detector_spec_by_id("generic-secret")
        .and_then(|detector| detector.match_confidence)
        .map(|confidence| confidence.post_match)
        .expect("embedded generic-secret post-match policy")
}

fn is_degenerate_repeat(credential: &str) -> bool {
    is_degenerate_repeat_at(credential, post_match_policy().degenerate_run_min_length)
}

// ── Tier-B fixture-path component loader (rules/example-path-components.toml) ─
#[test]
fn fixture_path_components_load_the_union_superset() {
    // The consolidated Tier-B list must carry BOTH the components the
    // suppression owner had (`fixture`/`fixtures`) AND the ones this
    // confidence owner previously hardcoded (`sample`/`samples`), so the two
    // consumers can never disagree again.
    for expected in [
        "test", "tests", "example", "examples", "fixtures", "samples",
    ] {
        assert!(
            FIXTURE_PATH_COMPONENTS
                .iter()
                .any(|c| c.eq_ignore_ascii_case(expected)),
            "rules/example-path-components.toml missing `{expected}`"
        );
    }
}

#[test]
fn path_haircut_fires_for_fixture_dirs_and_halves_confidence() {
    // A `samples/` component (added by the union) must trigger the 0.5 haircut.
    let scored = apply_path_confidence_penalties(
        0.8,
        Some("src/samples/config.rs"),
        true,
        post_match_policy().fixture_path_multiplier,
    );
    assert!(
        (scored - 0.4).abs() < 1e-9,
        "expected 0.8 × 0.5 = 0.4 for a samples/ path, got {scored}"
    );
    // A `fixtures/` component (from the suppression side of the union) too.
    let scored = apply_path_confidence_penalties(
        0.8,
        Some("a/fixtures/b.rs"),
        true,
        post_match_policy().fixture_path_multiplier,
    );
    assert!((scored - 0.4).abs() < 1e-9, "fixtures/ path, got {scored}");
}

#[test]
fn path_haircut_does_not_fire_for_ordinary_source() {
    let scored = apply_path_confidence_penalties(
        0.8,
        Some("src/handlers/auth.rs"),
        true,
        post_match_policy().fixture_path_multiplier,
    );
    assert!(
        (scored - 0.8).abs() < 1e-9,
        "ordinary source path must not be haircut, got {scored}"
    );
}

#[test]
fn path_haircut_is_disabled_when_penalize_is_false() {
    // `--no-suppress-test-fixtures` clears the haircut even in a fixtures dir.
    let scored = apply_path_confidence_penalties(
        0.8,
        Some("a/fixtures/b.rs"),
        false,
        post_match_policy().fixture_path_multiplier,
    );
    assert!(
        (scored - 0.8).abs() < 1e-9,
        "penalize=false must keep full confidence, got {scored}"
    );
}

#[test]
fn path_haircut_sanitizes_nan_even_without_a_path() {
    assert_eq!(
        apply_path_confidence_penalties(
            f64::NAN,
            None,
            true,
            post_match_policy().fixture_path_multiplier,
        ),
        0.0
    );
}

// ── detector-owned post-ML policy values are pinned ─────────────────────
#[test]
fn generic_detector_penalty_policy_is_pinned() {
    let policy = post_match_policy();
    assert_eq!(policy.placeholder_multiplier, 0.05);
    assert_eq!(policy.low_diversity_multiplier, 0.1);
    assert_eq!(policy.degenerate_repeat_multiplier, 0.1);
    assert_eq!(policy.data_envelope_multiplier, Some(0.02));
}

#[test]
fn generic_degenerate_low_diversity_value_takes_both_shape_penalties() {
    // 16 identical non-base64 bytes fall below the detector-owned diversity
    // floor and exceed its detector-owned repeat-run ratio and length limits.
    // `!` is outside the base64 alphabet, so no data-envelope arm fires.
    let value = "!".repeat(16);
    let scored = apply_post_ml_penalties_with_encoded_text_lift(
        1.0,
        &value,
        false,
        false,
        false,
        post_match_policy(),
    );
    // The detector policy applies 0.1 low-diversity and repeat multipliers.
    assert!(
        (scored - 0.01).abs() < 1e-9,
        "expected 0.01 (0.1 × 0.1), got {scored}"
    );
}

// ── longest_repeat_run_len: the byte-run primitive ───────────────────────
#[test]
fn run_len_of_empty_is_zero() {
    assert_eq!(longest_repeat_run_len(""), 0);
}

#[test]
fn run_len_of_single_char_is_one() {
    assert_eq!(longest_repeat_run_len("a"), 1);
}

#[test]
fn run_len_with_no_repeats_is_one() {
    assert_eq!(longest_repeat_run_len("abcdefg"), 1);
}

#[test]
fn run_len_of_all_identical_is_the_length() {
    assert_eq!(longest_repeat_run_len("aaaa"), 4);
}

#[test]
fn run_len_finds_a_run_at_the_start() {
    assert_eq!(longest_repeat_run_len("XXXXabc"), 4);
}

#[test]
fn run_len_finds_a_run_in_the_middle() {
    assert_eq!(longest_repeat_run_len("abYYYYcd"), 4);
}

#[test]
fn run_len_finds_a_run_at_the_end() {
    assert_eq!(longest_repeat_run_len("abcZZZZ"), 4);
}

#[test]
fn run_len_returns_the_longest_of_several_runs() {
    assert_eq!(longest_repeat_run_len("aaXbbbbYcc"), 4);
}

#[test]
fn run_len_is_byte_based_not_char_based() {
    // 'é' is two bytes (0xC3 0xA9); a string of three 'é' has alternating bytes,
    // so its longest identical-BYTE run is 1, not 3. Degenerate-run detection is
    // deliberately byte-based, the placeholders it targets (XXXX, 0000) are
    // ASCII, where byte == char.
    assert_eq!(longest_repeat_run_len("\u{e9}\u{e9}\u{e9}"), 1);
}

// ── the generic detector's run threshold is exactly 10 ─────────────────
#[test]
fn generic_degenerate_run_min_length_is_ten() {
    assert_eq!(post_match_policy().degenerate_run_min_length, 10);
}

#[test]
fn custom_detector_repeat_limit_is_applied_exactly() {
    assert!(!is_degenerate_repeat_at("aaaa", 5));
    assert!(is_degenerate_repeat_at("aaaaa", 5));
}

#[test]
fn a_run_of_nine_is_not_degenerate() {
    assert!(!is_degenerate_repeat(&"a".repeat(9)));
}

#[test]
fn a_run_of_exactly_ten_is_degenerate() {
    assert!(is_degenerate_repeat(&"a".repeat(10)));
}

#[test]
fn a_run_of_eleven_is_degenerate() {
    assert!(is_degenerate_repeat(&"a".repeat(11)));
}

#[test]
fn an_empty_credential_is_not_degenerate() {
    assert!(!is_degenerate_repeat(""));
}

#[test]
fn a_high_entropy_body_is_not_degenerate() {
    assert!(!is_degenerate_repeat("aB3dE7gH1jK4mN6pQ8rS"));
}

#[test]
fn a_prefixed_placeholder_with_a_long_run_is_degenerate() {
    // The canonical case: a distinctive prefix dilutes the ratio, but the
    // absolute 16-char run still flags it (AKIA + 16 X's).
    assert!(is_degenerate_repeat("AKIAXXXXXXXXXXXXXXXX"));
}

#[test]
fn a_prefixed_value_with_only_a_nine_run_is_not_degenerate() {
    assert!(!is_degenerate_repeat("AKIAXXXXXXXXX")); // AKIA + 9 X's
}

#[test]
fn a_ten_zero_run_is_degenerate() {
    assert!(is_degenerate_repeat("key=0000000000"));
}

#[test]
fn a_long_value_whose_longest_run_is_short_is_not_degenerate() {
    // 40 chars but no run reaches 10.
    assert!(!is_degenerate_repeat(
        "abababababababababababababababababababab"
    ));
}

// ── max_repeat_run: the ratio primitive ──────────────────────────────────
#[test]
fn ratio_of_empty_is_zero() {
    assert_eq!(max_repeat_run(""), 0.0);
}

#[test]
fn ratio_of_all_identical_is_one() {
    assert_eq!(max_repeat_run("aaaa"), 1.0);
}

#[test]
fn ratio_is_longest_run_over_length() {
    assert_eq!(max_repeat_run("aaXX"), 0.5); // longest run 2 / len 4
    assert_eq!(max_repeat_run("abcd"), 0.25); // longest run 1 / len 4
}

#[test]
fn ratio_of_single_char_is_one() {
    assert_eq!(max_repeat_run("a"), 1.0);
}
