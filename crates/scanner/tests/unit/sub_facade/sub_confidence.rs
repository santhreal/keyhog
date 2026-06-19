//! Standalone unit coverage for `keyhog_scanner::confidence`.
//!
//! Asserts the exact weighted-sum scoring, the known-prefix floor (and its
//! placeholder/degenerate-run skips), the NaN-safety barrier, and the shape
//! penalty math — computed against the source weights, never `> 0.0`.

use keyhog_scanner::confidence::{
    compute_confidence, compute_confidence_with_threshold, is_sensitive_path,
    known_prefix_confidence_floor, ConfidenceSignals, KNOWN_PREFIXES,
};
use keyhog_scanner::testing::confidence::{
    apply_calibration_multiplier, apply_calibration_multiplier_with_store,
    apply_path_confidence_penalties, apply_post_ml_penalties, char_diversity,
    contains_placeholder_word, finalize_confidence, max_repeat_run, placeholder_words,
};

fn all_false_signals() -> ConfidenceSignals {
    ConfidenceSignals {
        has_literal_prefix: false,
        has_context_anchor: false,
        entropy: 0.0,
        keyword_nearby: false,
        sensitive_file: false,
        match_length: 0,
        has_companion: false,
    }
}

// ---------------------------------------------------------------------------
// compute_confidence — exact weighted normalization
// ---------------------------------------------------------------------------

#[test]
fn all_signals_present_high_entropy_scores_one() {
    let signals = ConfidenceSignals {
        has_literal_prefix: true,
        has_context_anchor: true,
        entropy: 7.5, // >= very-high tier (5.8) -> full ENTROPY_WEIGHT
        keyword_nearby: true,
        sensitive_file: true,
        match_length: 40,
        has_companion: true,
    };
    // Every weight earned, low-entropy penalty is 1.0 -> score == max_possible.
    assert_eq!(compute_confidence(&signals), 1.0);
}

#[test]
fn no_signals_scores_zero() {
    assert_eq!(compute_confidence(&all_false_signals()), 0.0);
}

#[test]
fn only_literal_prefix_scores_its_weight_fraction() {
    let mut signals = all_false_signals();
    signals.has_literal_prefix = true;
    // LITERAL_PREFIX_WEIGHT 0.35 over max_possible 1.0 (all weights sum to 1.0).
    // sum = 0.35+0.20+0.20+0.10+0.10+0.05 = 1.00.
    let out = compute_confidence(&signals);
    assert!((out - 0.35).abs() < 1e-9, "expected 0.35, got {out}");
}

#[test]
fn low_entropy_long_match_applies_penalty() {
    // entropy < 2.0 AND match_length > 10 -> low_entropy_penalty 0.6.
    let mut signals = all_false_signals();
    signals.has_literal_prefix = true; // score 0.35 before penalty
    signals.entropy = 1.0;
    signals.match_length = 20;
    let out = compute_confidence(&signals);
    // 0.35 * 0.6 = 0.21
    assert!((out - 0.21).abs() < 1e-9, "expected 0.21, got {out}");
}

#[test]
fn threshold_controls_entropy_tier() {
    // With a very high threshold, entropy 5.0 falls below the high tier and
    // earns nothing; with a low threshold it clears the very-high tier.
    let mut signals = all_false_signals();
    signals.entropy = 5.0;
    let low_thr = compute_confidence_with_threshold(&signals, 2.0);
    let high_thr = compute_confidence_with_threshold(&signals, 6.0);
    assert!(
        low_thr > high_thr,
        "lowering the entropy threshold must raise the score: {low_thr} vs {high_thr}"
    );
}

// ---------------------------------------------------------------------------
// known_prefix_confidence_floor
// ---------------------------------------------------------------------------

#[test]
fn known_prefix_lifts_to_floor() {
    assert_eq!(
        known_prefix_confidence_floor("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"),
        Some(0.8)
    );
    assert_eq!(
        known_prefix_confidence_floor("AKIAIOSFODNN7EXAMPLEXX"),
        // contains "EXAMPLE" placeholder -> no floor
        None
    );
}

#[test]
fn unknown_prefix_has_no_floor() {
    assert_eq!(
        known_prefix_confidence_floor("randomtokenwithnoprefix12345"),
        None
    );
}

#[test]
fn placeholder_word_blocks_floor() {
    // Known prefix but body is a placeholder doc sample.
    assert_eq!(
        known_prefix_confidence_floor("sk_live_PLACEHOLDER_value_here"),
        None
    );
}

#[test]
fn degenerate_repeat_blocks_floor() {
    // ghp_ prefix + a 16-char 'X' run is synthetic padding, not a key.
    assert_eq!(known_prefix_confidence_floor("ghp_XXXXXXXXXXXXXXXX"), None);
}

#[test]
fn known_prefixes_table_contains_core_providers() {
    for p in ["ghp_", "AKIA", "sk_live_", "xoxb-", "npm_", "glpat-"] {
        assert!(
            KNOWN_PREFIXES.contains(&p),
            "{p} missing from KNOWN_PREFIXES"
        );
    }
}

// ---------------------------------------------------------------------------
// char_diversity / max_repeat_run
// ---------------------------------------------------------------------------

#[test]
fn char_diversity_exact_ratios() {
    assert_eq!(char_diversity("aaaa"), 0.25); // 1 unique / 4
    assert_eq!(char_diversity("abcd"), 1.0); // 4 unique / 4
    assert_eq!(char_diversity(""), 1.0); // empty -> 1.0 by contract
}

#[test]
fn max_repeat_run_exact_ratios() {
    assert_eq!(max_repeat_run("aaaa"), 1.0); // run 4 / len 4
    assert_eq!(max_repeat_run("abcd"), 0.25); // run 1 / len 4
    assert_eq!(max_repeat_run("aabbb"), 0.6); // run 3 / len 5
    assert_eq!(max_repeat_run(""), 0.0);
}

// ---------------------------------------------------------------------------
// contains_placeholder_word
// ---------------------------------------------------------------------------

#[test]
fn placeholder_word_detected_case_insensitively() {
    assert_eq!(
        placeholder_words(),
        vec![
            "example".to_string(),
            "dummy".to_string(),
            "fake".to_string(),
            "mock".to_string(),
            "sample".to_string(),
            "placeholder".to_string(),
            "changeme".to_string(),
        ]
    );
    assert!(contains_placeholder_word("this_is_an_EXAMPLE_token"));
    assert!(contains_placeholder_word("placeholder_value"));
    assert!(contains_placeholder_word("mock_value"));
    assert!(contains_placeholder_word("changeme_value"));
    assert!(!contains_placeholder_word("ghp_realtokenbody0123456789"));
}

// ---------------------------------------------------------------------------
// finalize_confidence — NaN/Inf safety + clamp
// ---------------------------------------------------------------------------

#[test]
fn finalize_maps_nan_to_zero() {
    assert_eq!(finalize_confidence(f64::NAN), 0.0);
}

#[test]
fn finalize_clamps_out_of_range() {
    assert_eq!(finalize_confidence(2.0), 1.0);
    assert_eq!(finalize_confidence(-1.0), 0.0);
    assert_eq!(finalize_confidence(f64::INFINITY), 1.0);
    assert_eq!(finalize_confidence(f64::NEG_INFINITY), 0.0);
    assert_eq!(finalize_confidence(0.73), 0.73);
}

// ---------------------------------------------------------------------------
// apply_post_ml_penalties
// ---------------------------------------------------------------------------

#[test]
fn post_ml_placeholder_crushes_score() {
    // Surface placeholder -> *0.05.
    let out = apply_post_ml_penalties(1.0, "ghp_EXAMPLE_token_value", true);
    assert!((out - 0.05).abs() < 1e-9, "expected 0.05, got {out}");
}

#[test]
fn post_ml_named_keeps_small_alphabet_secret() {
    // 64-char hex (16 distinct symbols, diversity 0.25): a named detector keeps
    // it (>= 0.1 diversity, no degenerate run) -> score unchanged.
    let hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let out = apply_post_ml_penalties(0.9, hex64, true);
    assert!(
        (out - 0.9).abs() < 1e-9,
        "named hex should survive, got {out}"
    );
}

#[test]
fn post_ml_degenerate_run_penalized_even_for_named() {
    // 16-char 'X' run -> degenerate -> *0.1 (absolute-run arm).
    let out = apply_post_ml_penalties(1.0, "AKIAXXXXXXXXXXXXXXXX", true);
    assert!((out - 0.1).abs() < 1e-9, "expected 0.1, got {out}");
}

#[test]
fn post_ml_empty_credential_passthrough() {
    assert_eq!(apply_post_ml_penalties(0.5, "", false), 0.5);
}

#[test]
fn post_ml_nan_safe() {
    assert_eq!(apply_post_ml_penalties(f64::NAN, "ghp_token", true), 0.0);
}

// ---------------------------------------------------------------------------
// apply_path_confidence_penalties
// ---------------------------------------------------------------------------

#[test]
fn path_penalty_halves_test_directory_score() {
    let out = apply_path_confidence_penalties(0.8, Some("src/tests/fixtures.rs"), true);
    assert!((out - 0.4).abs() < 1e-9, "test dir -> *0.5, got {out}");
}

#[test]
fn path_penalty_uses_shared_placeholder_directory_words() {
    let out = apply_path_confidence_penalties(0.8, Some("fixtures/dummy/config.env"), true);
    assert!(
        (out - 0.4).abs() < 1e-9,
        "placeholder directory from shared Tier-B vocabulary -> *0.5, got {out}"
    );
}

#[test]
fn path_penalty_skipped_for_production_path() {
    let out = apply_path_confidence_penalties(0.8, Some("src/app/config.rs"), true);
    assert!(
        (out - 0.8).abs() < 1e-9,
        "non-test path unchanged, got {out}"
    );
}

#[test]
fn path_penalty_disabled_passes_through() {
    // penalize=false (the --no-suppress-test-fixtures side) keeps the score.
    let out = apply_path_confidence_penalties(0.8, Some("tests/x.rs"), false);
    assert!((out - 0.8).abs() < 1e-9);
}

#[test]
fn path_penalty_none_path_is_nan_safe() {
    assert_eq!(apply_path_confidence_penalties(f64::NAN, None, true), 0.0);
}

// ---------------------------------------------------------------------------
// apply_calibration_multiplier — universal NaN/clamp contract (cache-agnostic)
// ---------------------------------------------------------------------------

#[test]
fn calibration_is_nan_safe() {
    // Regardless of whether a calibration store is configured, NaN must finalize to 0.
    assert_eq!(
        apply_calibration_multiplier(f64::NAN, "some-unlikely-detector-id-xyz"),
        0.0
    );
}

#[test]
fn calibration_output_in_unit_range() {
    let out = apply_calibration_multiplier(0.7, "some-unlikely-detector-id-xyz");
    assert!(
        (0.0..=1.0).contains(&out),
        "calibrated score out of range: {out}"
    );
}

#[test]
fn calibration_only_applies_when_store_is_explicit() {
    let calibration = keyhog_core::Calibration::default();
    calibration.record_outcome("det-explicit-calibration", false);
    calibration.record_outcome("det-explicit-calibration", false);
    calibration.record_outcome("det-explicit-calibration", false);

    let unconfigured = apply_calibration_multiplier(0.9, "det-explicit-calibration");
    assert!(
        (unconfigured - 0.9).abs() < 1e-9,
        "absent explicit calibration store must leave score unchanged, got {unconfigured}"
    );

    let configured =
        apply_calibration_multiplier_with_store(0.9, "det-explicit-calibration", &calibration);
    assert!(
        configured < 0.5,
        "explicit false-positive history must damp the score, got {configured}"
    );
}

#[test]
fn calibration_multiplier_has_no_ambient_default_cache_probe() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/confidence/penalties.rs"
    ))
    .expect("read penalties source");
    for forbidden in [
        "calibration_default_cache_path",
        "OnceLock<Option<Calibration>>",
        "Calibration::load(&path)",
    ] {
        assert!(
            !source.contains(forbidden),
            "scanner confidence must not discover calibration from ambient disk state: {forbidden}"
        );
    }
}

// ---------------------------------------------------------------------------
// is_sensitive_path
// ---------------------------------------------------------------------------

#[test]
fn sensitive_paths_detected() {
    assert!(is_sensitive_path(".env"));
    assert!(is_sensitive_path("deploy/credentials.json"));
    assert!(is_sensitive_path("certs/server.pem"));
    assert!(is_sensitive_path("app/.npmrc"));
}

#[test]
fn non_sensitive_paths_rejected() {
    assert!(!is_sensitive_path("src/main.rs"));
    assert!(!is_sensitive_path("README.md"));
}
