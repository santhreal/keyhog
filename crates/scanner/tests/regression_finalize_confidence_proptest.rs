//! Property invariants for the report-confidence tail `finalize_report_confidence`
//! (`confidence::policy`), the pipeline every finding's confidence passes
//! through before emission (post-ML penalties → path → known-prefix floor →
//! calibration → checksum veto). The example-based contract lives in
//! `regression_finalize_report_confidence_pipeline`; this is the property
//! dimension (Testing Contract: proptest), sweeping thousands of random
//! (entry-confidence × credential × flag) tuples for invariants an example
//! suite can miss:
//!
//!   1. The finalized score, when present, is a FINITE unit-interval value, a
//!      confidence is a probability; it must never escape `[0, 1]`, go NaN, or
//!      go infinite no matter what upstream fed it.
//!   2. A credential with a proven-bad embedded checksum is ALWAYS dropped to
//!      `None`, for every entry confidence and flag combination, the terminal
//!      checksum veto can never be bypassed by any earlier signal.
//!   3. A NaN entry never leaks as `Some(non-finite)`: the NaN barrier holds
//!      across the whole flag space.
//!
//! `finalize_report_confidence` and the terminal checksum decision are the
//! STABLE part of `confidence::policy` (the in-flight edits to that file touch
//! neither), and the GitHub PAT verdict is a deterministic CRC32 check, so these
//! invariants are robust to the surrounding refactor.

use keyhog_scanner::testing::confidence::finalize_report_confidence;
use proptest::prelude::*;

// A representative credential per checksum branch, exercised under every flag
// tuple: a valid-CRC PAT (Valid), a forged-CRC PAT (Invalid → veto), and a
// plain non-checksum value (NotApplicable → passthrough).
const GHP_VALID: &str = "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";
const GHP_BAD_CHECKSUM: &str = "ghp_aBcD1234EFgh5678ijklMNop9012qrSTuvWX";
const PLAIN: &str = "just_some_plain_config_value_1234";

fn creds() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just(GHP_VALID), Just(GHP_BAD_CHECKSUM), Just(PLAIN)]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// Invariant 1 + 3: for any entry in [0,1] and any flags, a present score is
    /// a finite unit-interval value; and a NaN entry never leaks a non-finite
    /// score.
    #[test]
    fn finalized_score_is_finite_unit_interval(
        entry in 0.0f64..=1.0,
        cred in creds(),
        is_named in any::<bool>(),
        penalize in any::<bool>(),
        lift in any::<bool>(),
        has_path in any::<bool>(),
    ) {
        let path = has_path.then_some("src/config/settings.rs");
        let out = finalize_report_confidence(entry, cred, "generic-secret", path, is_named, penalize, lift);
        if let Some(score) = out {
            prop_assert!(score.is_finite(), "score must be finite, got {score} (cred={cred}, entry={entry})");
            prop_assert!(score >= 0.0, "score must be >= 0, got {score}");
            prop_assert!(score <= 1.0 + 1e-9, "confidence must not exceed 1.0, got {score} (cred={cred}, entry={entry})");
        }

        // Same flags but a NaN entry: the barrier must hold regardless.
        let nan_out = finalize_report_confidence(f64::NAN, cred, "generic-secret", path, is_named, penalize, lift);
        if let Some(score) = nan_out {
            prop_assert!(score.is_finite(), "NaN entry leaked a non-finite score {score}");
        }
    }

    /// Invariant 2: the terminal checksum veto is absolute, a forged-checksum
    /// PAT is dropped to None for EVERY entry confidence and flag tuple.
    #[test]
    fn bad_checksum_is_always_vetoed(
        entry in 0.0f64..=1.0,
        is_named in any::<bool>(),
        penalize in any::<bool>(),
        lift in any::<bool>(),
        has_path in any::<bool>(),
    ) {
        let path = has_path.then_some("src/lib.rs");
        let out = finalize_report_confidence(entry, GHP_BAD_CHECKSUM, "github-classic-pat", path, is_named, penalize, lift);
        prop_assert_eq!(out, None, "forged-checksum PAT must be vetoed to None at entry {}", entry);
    }
}
