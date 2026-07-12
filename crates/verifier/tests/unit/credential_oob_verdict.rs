//! Re-homed from the inline `oob_verdict_tests` in
//! `crates/verifier/src/verify/credential.rs` (the `no_inline_tests_in_verifier_src`
//! gate forbids inline `#[cfg(test)]`). Pins the OOB-combined-verdict policy
//! matrix — how `OobPolicy` × http-live × observed collapse to a final
//! `VerificationResult` (incl. the OobAndHttp+!http_live short-circuit that
//! justifies skipping the OOB wait). Exercised through the `testing` facade so
//! `oob_combined_verdict` stays `pub(crate)`.

use keyhog_core::{OobPolicy, VerificationResult};
use keyhog_verifier::testing::oob_combined_verdict;

/// The `combine_oob` short-circuit skips the OOB wait when
/// `OobAndHttp && !http_live`, on the premise that the verdict is
/// `http_only_result` REGARDLESS of the observation. Pin that premise so a
/// future policy edit can't silently make the observation matter here (which
/// would turn the latency optimization into a wrong verdict).
#[test]
fn oob_and_http_with_failed_http_ignores_observation() {
    for observed in [false, true] {
        assert_eq!(
            oob_combined_verdict(
                OobPolicy::OobAndHttp,
                VerificationResult::Dead,
                false, // http_live = false
                observed,
            ),
            VerificationResult::Dead,
            "OobAndHttp + !http_live must pass through http_only_result \
             regardless of observed={observed} (justifies skipping the wait)"
        );
        assert_eq!(
            oob_combined_verdict(
                OobPolicy::OobAndHttp,
                VerificationResult::RateLimited,
                false,
                observed,
            ),
            VerificationResult::RateLimited,
        );
    }
}

#[test]
fn oob_and_http_with_live_http_uses_observation() {
    assert_eq!(
        oob_combined_verdict(OobPolicy::OobAndHttp, VerificationResult::Live, true, true),
        VerificationResult::Live,
        "http_live && observed => Live"
    );
    assert_eq!(
        oob_combined_verdict(OobPolicy::OobAndHttp, VerificationResult::Live, true, false),
        VerificationResult::Dead,
        "http_live && !observed => Dead (parsed but not exfil-live)"
    );
}

#[test]
fn oob_only_uses_observation_then_transient_http_fallback() {
    assert_eq!(
        oob_combined_verdict(OobPolicy::OobOnly, VerificationResult::Dead, false, true),
        VerificationResult::Live,
        "observed => Live under OobOnly regardless of HTTP"
    );
    // Not observed: a transient HTTP result passes through...
    assert_eq!(
        oob_combined_verdict(
            OobPolicy::OobOnly,
            VerificationResult::RateLimited,
            true,
            false
        ),
        VerificationResult::RateLimited,
    );
    assert_eq!(
        oob_combined_verdict(
            OobPolicy::OobOnly,
            VerificationResult::Error("boom".into()),
            false,
            false,
        ),
        VerificationResult::Error("boom".into()),
    );
    // ...anything else is Dead.
    assert_eq!(
        oob_combined_verdict(OobPolicy::OobOnly, VerificationResult::Live, true, false),
        VerificationResult::Dead,
        "not observed + non-transient HTTP => Dead under OobOnly"
    );
}

#[test]
fn oob_optional_always_passes_through_http() {
    for observed in [false, true] {
        assert_eq!(
            oob_combined_verdict(
                OobPolicy::OobOptional,
                VerificationResult::Live,
                true,
                observed,
            ),
            VerificationResult::Live,
        );
        assert_eq!(
            oob_combined_verdict(
                OobPolicy::OobOptional,
                VerificationResult::Dead,
                false,
                observed,
            ),
            VerificationResult::Dead,
        );
    }
}
