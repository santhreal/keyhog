//! Behavioral lock for the report-confidence tail `finalize_report_confidence`
//! (`confidence::policy`), the pipeline every surfaced finding's confidence
//! passes through before it is emitted:
//!
//!   post-ML penalties (+ encoded-text lift) → path penalties → known-prefix
//!   floor → calibration multiplier → **checksum decision (LAST, can veto)**.
//!
//! Existing coverage (`engine_fallback_confidence_owner`) is a SOURCE-SHAPE
//! ownership gate — it asserts the tail *routes through* the owner, not what it
//! *computes*. The order is contractual and a reorder is a silent bug: if the
//! checksum decision did NOT run last, a token with a BAD embedded checksum that
//! a known-prefix floor already lifted would be emitted as a high-confidence
//! finding — a false positive on a provably-forged credential. These pin the
//! terminal behaviors with concrete values, never `> 0.0`.
//!
//! Scope note: `finalize_report_confidence` and the checksum decision it ends on
//! are the STABLE part of `confidence::policy` (the in-flight edits to that file
//! touch neither); the GitHub PAT verdicts used below are deterministic CRC32
//! checks, so these assertions are robust to the surrounding refactor.

use keyhog_scanner::testing::confidence::finalize_report_confidence;

// A GitHub classic PAT with a CORRECT trailing CRC32 checksum (the canonical
// `regression_github_pat_boundary::GHP_VALID`): `ghp_` + 30-char entropy + 6
// base62 CRC. The shipped `GithubClassicPatValidator` returns `Valid` for it.
const GHP_VALID: &str = "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";
// The SAME `ghp_` shape but a FABRICATED (wrong) checksum — structurally a PAT,
// but the CRC32 does not match the entropy body, so the validator returns
// `Invalid`. (This is the exact token `backend_parity_matrix` documents as
// "silently dropped once checksum wiring landed".)
const GHP_BAD_CHECKSUM: &str = "ghp_aBcD1234EFgh5678ijklMNop9012qrSTuvWX";

/// THE headline contract: the checksum decision runs LAST and VETOES. A token
/// with a proven-bad checksum must be dropped to `None` even when it entered the
/// tail at maximum confidence AND is a named detector whose `ghp_` known-prefix
/// floor would otherwise guarantee a high score. A forged credential is not a
/// finding, no matter how strong every earlier signal was.
#[test]
fn bad_checksum_vetoes_to_none_even_at_max_confidence() {
    let out = finalize_report_confidence(
        0.99,
        GHP_BAD_CHECKSUM,
        "github-classic-pat",
        None,  // no file path
        true,  // is_named_detector (would earn the anchor/known-prefix floor)
        false, // penalize_test_paths
        false, // allow_encoded_text_lift
    );
    assert_eq!(
        out, None,
        "a GitHub PAT with a forged checksum must be dropped to None by the terminal \
         checksum decision, even at confidence 0.99 on a named detector"
    );
}

/// The mirror of the veto: a token whose checksum VALIDATES is floored UP to the
/// checksum-valid floor (0.9) even if it entered the tail low. A matching CRC is
/// cryptographic proof of a well-formed token, so it must clear the high bar.
#[test]
fn valid_checksum_floors_a_low_entry_up_to_the_valid_floor() {
    let out = finalize_report_confidence(
        0.30,
        GHP_VALID,
        "github-classic-pat",
        None,
        true,
        false,
        false,
    );
    let score = out.expect("a checksum-valid PAT must survive the tail, not be dropped");
    assert!(
        score >= 0.9 - 1e-9,
        "a checksum-VALID PAT entering at 0.30 must be floored up to the \
         checksum-valid floor (>= 0.9); got {score}"
    );
    assert!(
        score <= 1.0 + 1e-9,
        "confidence must stay within the unit interval; got {score}"
    );
}

/// A credential with NO checksum-bearing prefix takes the `NotApplicable`
/// checksum branch: the tail must PASS IT THROUGH (never veto to None) and never
/// spuriously LIFT it (no known prefix, no valid checksum), so the finalized
/// score stays at or below the entry confidence. Proves the checksum stage is a
/// gate for checksum-bearing tokens only, not a blanket floor/veto.
#[test]
fn no_checksum_prefix_credential_passes_through_without_veto_or_lift() {
    let entry = 0.60;
    let out = finalize_report_confidence(
        entry,
        "just_some_plain_config_value_1234",
        "generic-secret",
        None,
        false, // not a named detector
        false,
        false,
    );
    let score = out.expect(
        "a non-checksum, non-placeholder credential must survive the tail (NotApplicable \
         checksum branch), not be dropped to None",
    );
    assert!(
        (0.0..=entry + 1e-9).contains(&score),
        "with no known prefix and no valid checksum the tail must not lift above the \
         entry confidence {entry}; got {score}"
    );
}

/// End-to-end NaN barrier: a broken upstream score must never be laundered into
/// a finite mid-tier confidence NOR leak as `Some(NaN)` out of the tail. The
/// result must be either a drop (`None`) or a finite score — never a NaN that
/// would poison every downstream `>=` gate (all comparisons against NaN are
/// false).
#[test]
fn nan_entry_never_leaks_as_some_nan() {
    let out = finalize_report_confidence(
        f64::NAN,
        "just_some_plain_config_value_1234",
        "generic-secret",
        None,
        false,
        false,
        false,
    );
    if let Some(score) = out {
        assert!(
            score.is_finite(),
            "the tail must never emit Some(NaN)/Some(inf) for a NaN entry; got {score}"
        );
    }
}

/// The `allow_encoded_text_lift` flag is WIRED THROUGH the tail (Review Vector 9:
/// a parsed flag must reach behavior). It feeds
/// `apply_post_ml_penalties_with_encoded_text_lift`, which only ever RELAXES the
/// encoded-text penalty — a "lift" adds, never subtracts — so for identical
/// inputs the lift-enabled finalize must land at or above the lift-disabled one.
/// A monotonicity contract (`>=`) that holds whether or not the lift fires for
/// this input, so it locks the DIRECTION of the wiring without pinning the exact
/// (possibly-tuned) lift magnitude.
#[test]
fn encoded_text_lift_flag_never_lowers_confidence_vs_disabled() {
    // A base64-shaped value (the encoded-text lift's target class).
    let cred = "dGhpc19pc19hX3Rlc3Rfc2VjcmV0X3ZhbHVlXzEyMzQ1Ng";
    let lifted = finalize_report_confidence(
        0.50,
        cred,
        "generic-secret",
        None,
        false,
        false,
        true, // allow_encoded_text_lift
    );
    let unlifted = finalize_report_confidence(
        0.50,
        cred,
        "generic-secret",
        None,
        false,
        false,
        false, // no lift
    );
    let (l, u) = (
        lifted.expect("lift-enabled result present"),
        unlifted.expect("lift-disabled result present"),
    );
    assert!(
        l >= u - 1e-9,
        "the encoded-text lift must never LOWER confidence: lifted {l} < unlifted {u}"
    );
}

/// The path penalty is APPLIED before the terminal stages (not skipped): the
/// same non-checksum credential scored on a test path with `penalize_test_paths`
/// must land no higher than the same credential with penalization off. Locks
/// that the test/docs haircut is inside the finalized tail, not bypassed.
#[test]
fn test_path_penalty_does_not_raise_confidence_vs_unpenalized() {
    let cred = "just_some_plain_config_value_1234";
    let penalized = finalize_report_confidence(
        0.60,
        cred,
        "generic-secret",
        Some("tests/fixtures/config_test.rs"),
        false,
        true, // penalize_test_paths
        false,
    );
    let unpenalized = finalize_report_confidence(
        0.60,
        cred,
        "generic-secret",
        Some("src/config.rs"),
        false,
        false, // no penalty
        false,
    );
    let (p, u) = (
        penalized.expect("penalized path result present"),
        unpenalized.expect("unpenalized path result present"),
    );
    assert!(
        p <= u + 1e-9,
        "the test-path haircut must not INCREASE confidence: penalized {p} > unpenalized {u}"
    );
}

/// CPU and GPU MoE evaluation use different floating-point widths internally.
/// Their public report score is a policy input and serialized API field, so a
/// few accumulator ULPs must not create backend-specific findings or JSON.
#[test]
fn report_confidence_canonicalizes_equivalent_cpu_gpu_scores() {
    let credential = "W/\"e1dc589b7165f7ab3b9a5ec1f1992257";
    let cpu = finalize_report_confidence(
        0.831_729_471_683_502_2,
        credential,
        "entropy-api-key",
        None,
        false,
        false,
        false,
    );
    let gpu = finalize_report_confidence(
        0.831_729_531_288_147,
        credential,
        "entropy-api-key",
        None,
        false,
        false,
        false,
    );
    assert_eq!(cpu, gpu, "backend-equivalent scores need one public value");
    assert_eq!(cpu, Some(0.832));
}
