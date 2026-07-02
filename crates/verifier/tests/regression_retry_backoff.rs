//! Regression lock for the verifier's retry / backoff POLICY (pure, network-free).
//!
//! The production credential-verification loop (`retry_loop` in
//! `verifier/src/verify/credential.rs`) re-probes a transient failure up to
//! `MAX_VERIFY_ATTEMPTS = 3` times, sleeping `retry_delay_bounds_for_attempt`
//! milliseconds between attempts with `RETRY_DELAY_MS = 500` as the base. The
//! delay schedule is exponential (base * 2^(attempt-1)) with a bounded 25%
//! upper jitter, a hard exponent cap at 10, and saturating arithmetic so a
//! hostile/large base can never panic. Whether an attempt is retried at all is
//! keyed on the attempt's `transient` bool, which for the AWS STS live probe is
//! produced by the pure `classify_aws_sts_failure` status classifier.
//!
//! Every assertion below pins an EXACT duration bound, bool, count, or message
//! byte — the whole schedule is computed with no clock and no socket, so these
//! are deterministic. Distinct from `regression_status_verdict_map.rs` (which
//! pins the status→verdict variant matrix): this file pins the *timing schedule*
//! and the *exhaustion contract*, not the verdict vocabulary.

use keyhog_core::VerificationResult;
use keyhog_verifier::testing::{TestApi, VerifierTestApi, MAX_RETRIES_ERROR};

/// Production base delay (`RETRY_DELAY_MS` in credential.rs). Kept local so a
/// drift in the source constant surfaces as a schedule-value mismatch here.
const PROD_BASE_MS: u64 = 500;

// ── attempt 0: the first try is immediate, never delayed ─────────────────────

#[test]
fn backoff_attempt_zero_is_always_immediate_regardless_of_base() {
    // The 0th attempt fires with no sleep; `retry_loop` only sleeps when
    // `attempt > 0`, and the bounds function returns (0, 0) for attempt 0 so the
    // fast path (`min == max`) skips the RNG entirely.
    assert_eq!(
        TestApi.retry_delay_bounds_for_attempt(0, PROD_BASE_MS),
        (0, 0)
    );
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(0, 1), (0, 0));
    assert_eq!(
        TestApi.retry_delay_bounds_for_attempt(0, u64::MAX),
        (0, 0),
        "attempt 0 is immediate even for a pathological base"
    );
}

// ── base 0: retries with no backoff (used by the pure test loops) ────────────

#[test]
fn backoff_zero_base_disables_delay_on_every_attempt() {
    // A zero base short-circuits to (0, 0) for ALL attempts — this is what the
    // metadata-preservation and rate-limit-feedback test loops rely on to run
    // without a real sleep (proving the schedule math is pure/no-network).
    for attempt in [0usize, 1, 2, 3, 5, 11, 1000] {
        assert_eq!(
            TestApi.retry_delay_bounds_for_attempt(attempt, 0),
            (0, 0),
            "base 0 must disable backoff at attempt {attempt}"
        );
    }
}

// ── the exact production schedule (base 500 ms, exponential + 25% jitter) ─────

#[test]
fn backoff_production_schedule_500ms_is_exact_exponential_with_quarter_jitter() {
    // attempt n (n>=1): lower = 500 * 2^(n-1); upper = lower + lower/4.
    assert_eq!(
        TestApi.retry_delay_bounds_for_attempt(1, PROD_BASE_MS),
        (500, 625)
    );
    assert_eq!(
        TestApi.retry_delay_bounds_for_attempt(2, PROD_BASE_MS),
        (1000, 1250)
    );
    assert_eq!(
        TestApi.retry_delay_bounds_for_attempt(3, PROD_BASE_MS),
        (2000, 2500)
    );
    assert_eq!(
        TestApi.retry_delay_bounds_for_attempt(4, PROD_BASE_MS),
        (4000, 5000)
    );
    assert_eq!(
        TestApi.retry_delay_bounds_for_attempt(5, PROD_BASE_MS),
        (8000, 10000)
    );
}

#[test]
fn backoff_lower_bound_doubles_every_attempt_below_the_cap() {
    // Exponential growth: each attempt's lower bound is exactly twice the prior
    // attempt's, for attempts 1..=6 (all below the exponent cap).
    let mut prev = TestApi.retry_delay_bounds_for_attempt(1, PROD_BASE_MS).0;
    assert_eq!(prev, 500);
    for attempt in 2..=6usize {
        let lower = TestApi
            .retry_delay_bounds_for_attempt(attempt, PROD_BASE_MS)
            .0;
        assert_eq!(
            lower,
            prev * 2,
            "attempt {attempt} lower bound must be double attempt {}'s",
            attempt - 1
        );
        prev = lower;
    }
    // Concretely: attempt 6 = 500 * 2^5 = 16000.
    assert_eq!(
        TestApi.retry_delay_bounds_for_attempt(6, PROD_BASE_MS),
        (16000, 20000)
    );
}

#[test]
fn backoff_upper_jitter_is_exactly_one_quarter_of_the_lower_bound() {
    // The jitter ceiling adds base/4 (25%). For a base divisible by 4 the whole
    // schedule keeps upper - lower == lower/4 with no rounding slop.
    for attempt in 1..=5usize {
        let (lower, upper) = TestApi.retry_delay_bounds_for_attempt(attempt, PROD_BASE_MS);
        assert_eq!(
            upper - lower,
            lower / 4,
            "attempt {attempt} jitter span must be a quarter of the base delay"
        );
    }
    // A base of 400 → attempt 1 span 100 (= 400/4).
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(1, 400), (400, 500));
}

// ── boundary: the jitter floor is 1 ms when base/4 rounds down to 0 ──────────

#[test]
fn backoff_jitter_floor_is_one_ms_when_quarter_rounds_to_zero() {
    // For a sub-4 ms effective base, integer base/4 is 0, but the schedule
    // guarantees a >=1 ms jitter window so the RNG range is never empty.
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(1, 1), (1, 2));
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(1, 2), (2, 3));
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(1, 3), (3, 4));
    // At base 4, base/4 == 1, so the floor and the computed jitter coincide.
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(1, 4), (4, 5));
    // Base 7: 7/4 == 1 (floor still 1); base 8: 8/4 == 2 (computed wins).
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(1, 7), (7, 8));
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(1, 8), (8, 10));
}

// ── adversarial: the exponent is hard-capped at 10, not unbounded ────────────

#[test]
fn backoff_exponent_caps_at_ten_so_deep_attempts_plateau() {
    // 2^10 = 1024 is the ceiling multiplier; attempt 11 hits it and every
    // deeper attempt returns the IDENTICAL bounds — the delay can't grow without
    // limit and blow past any sane timeout.
    let capped = TestApi.retry_delay_bounds_for_attempt(11, 1);
    assert_eq!(capped, (1024, 1280)); // 1 * 2^10 = 1024; jitter 1024/4 = 256.
    for attempt in [12usize, 13, 50, 1000, usize::MAX] {
        assert_eq!(
            TestApi.retry_delay_bounds_for_attempt(attempt, 1),
            capped,
            "attempt {attempt} must be pinned to the 2^10 plateau"
        );
    }
    // With base 3 the plateau scales: 3 * 1024 = 3072, jitter 768.
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(11, 3), (3072, 3840));
    assert_eq!(TestApi.retry_delay_bounds_for_attempt(999, 3), (3072, 3840));
}

// ── adversarial: a huge base saturates instead of overflowing/panicking ──────

#[test]
fn backoff_saturates_to_u64_max_without_panicking_on_overflow() {
    // saturating_mul + saturating_add mean a pathological base can never wrap or
    // panic; it clamps to u64::MAX. Purity contract: no clock, no socket, no UB.
    assert_eq!(
        TestApi.retry_delay_bounds_for_attempt(11, u64::MAX),
        (u64::MAX, u64::MAX),
        "MAX base at the exponent cap must clamp, not wrap"
    );
    // Even attempt 1 (multiplier 1) saturates the upper jitter add: MAX + MAX/4.
    assert_eq!(
        TestApi.retry_delay_bounds_for_attempt(1, u64::MAX),
        (u64::MAX, u64::MAX)
    );
    // A base just past half of u64::MAX overflows the *2 at attempt 2 → clamps.
    let half_plus = (u64::MAX / 2) + 1;
    assert_eq!(
        TestApi.retry_delay_bounds_for_attempt(2, half_plus),
        (u64::MAX, u64::MAX),
        "doubling past u64::MAX must saturate the lower bound too"
    );
}

// ── purity: same inputs → same outputs, and bounds never invert ──────────────

#[test]
fn backoff_bounds_are_deterministic_and_lower_never_exceeds_upper() {
    // The bounds computation is pure: repeated calls with identical arguments
    // return byte-identical tuples (only `retry_loop`'s RNG pick inside the
    // [lower, upper] window is nondeterministic — never the schedule itself).
    for attempt in 0..=15usize {
        let first = TestApi.retry_delay_bounds_for_attempt(attempt, PROD_BASE_MS);
        let second = TestApi.retry_delay_bounds_for_attempt(attempt, PROD_BASE_MS);
        assert_eq!(
            first, second,
            "attempt {attempt} bounds must be deterministic"
        );
        assert!(
            first.0 <= first.1,
            "attempt {attempt} lower bound {} must not exceed upper {}",
            first.0,
            first.1
        );
    }
    // Non-decreasing lower bound across the whole ramp (monotonic backoff).
    let mut prev_lower = 0u64;
    for attempt in 1..=15usize {
        let lower = TestApi
            .retry_delay_bounds_for_attempt(attempt, PROD_BASE_MS)
            .0;
        assert!(
            lower >= prev_lower,
            "attempt {attempt} lower {lower} regressed below prior {prev_lower}"
        );
        prev_lower = lower;
    }
}

// ── exhaustion: the retry loop keeps the LAST transient attempt's payload ─────

#[tokio::test]
async fn exhaustion_returns_last_transient_error_with_its_metadata_intact() {
    // Regression for the bug where an exhausted loop dropped the final transient
    // attempt's metadata (OOB observation ids, partial fields). With every
    // attempt transient, the loop returns the LAST attempt's Error verdict AND
    // its metadata verbatim — asserted to the exact message and value, not just
    // a matches!(Error(_)) shape.
    let (result, metadata) = TestApi.retry_loop_preserves_metadata_on_exhaustion().await;
    match result {
        VerificationResult::Error(message) => {
            assert_eq!(
                message, "transient verifier failure",
                "exhausted loop must surface the last transient error verbatim"
            );
        }
        other => panic!("exhaustion must yield an Error verdict, got {other:?}"),
    }
    assert_eq!(
        metadata.get("oob_id").map(String::as_str),
        Some("abc"),
        "the last transient attempt's OOB metadata must survive exhaustion"
    );
    assert_eq!(
        metadata.len(),
        1,
        "no metadata keys are invented or dropped"
    );
}

// ── the operator-facing exhaustion message is a stable, actionable contract ──

#[test]
fn max_retries_error_message_is_backcompat_and_actionable() {
    // Downstream code does `.contains("max retries exceeded")`, so the legacy
    // phrase must lead; the message must also name the cause class and a fix.
    assert!(
        MAX_RETRIES_ERROR.starts_with("max retries exceeded"),
        "back-compat phrase must lead: {MAX_RETRIES_ERROR}"
    );
    assert!(
        MAX_RETRIES_ERROR.contains("rate-limit, 5xx, or transport failure"),
        "message must name the retryable cause class"
    );
    assert!(
        MAX_RETRIES_ERROR.contains("Fix:") && MAX_RETRIES_ERROR.contains("lower"),
        "message must give the operator a concrete remediation"
    );
    assert!(
        MAX_RETRIES_ERROR.contains("verification concurrency"),
        "the fix must point at verification concurrency"
    );
}

// ── retry decision input: which STS statuses are transient (→ retried) ────────

#[test]
fn all_retryable_statuses_report_transient_true_so_the_loop_reprobes() {
    // The `transient` bool is exactly what `retry_loop` keys on: a true value
    // means "keep the last result and try again". 429 (rate-limit), the full 5xx
    // band, and an unexpected 401 are all transient. 500/503 are checked in the
    // status-verdict lock; 429/401/502/504 are pinned here as the retry inputs.
    for status in [401u16, 429, 502, 504] {
        let (result, transient) = TestApi.classify_aws_sts_failure(status, "server said no");
        assert_eq!(
            result,
            VerificationResult::RateLimited,
            "status {status} must classify as RateLimited"
        );
        assert!(transient, "status {status} must be retried by the loop");
    }
}

#[test]
fn conclusive_invalid_credential_is_not_transient_so_the_loop_stops() {
    // Negative twin: a plain STS 403 (invalid credential) is conclusive — the
    // loop must NOT re-probe it. `transient == false` short-circuits `retry_loop`
    // on the first attempt, returning the verdict immediately with no backoff.
    let (result, transient) =
        TestApi.classify_aws_sts_failure(403, "<Error><Code>InvalidClientTokenId</Code></Error>");
    assert_eq!(result, VerificationResult::Dead);
    assert!(
        !transient,
        "a dead credential must terminate the retry loop, not be re-probed"
    );
}

// ── the loop feeds a rate-limited attempt back into the global limiter ────────

#[tokio::test]
async fn retry_loop_records_rate_limited_attempt_as_backpressure() {
    // A single-attempt loop over a RateLimited verdict must raise the limiter's
    // error count by exactly 1 — the backoff policy is wired to global
    // backpressure, not just per-request sleeps. Runs with base_delay 0 (no real
    // sleep, no network).
    let raised = TestApi.retry_loop_records_rate_limit_feedback().await;
    assert_eq!(
        raised, 1,
        "a rate-limited attempt must add exactly one unit of backpressure"
    );
}
