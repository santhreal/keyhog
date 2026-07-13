//! Behavioral contract for the scanner's hard-exit code constants
//! (crates/scanner/src/process_exit.rs).
//!
//! The scanner has two deep paths that may hard-stop the process (a
//! caller-required GPU backend being unavailable, and a backend that cannot be
//! constructed) rather than degrade silently. Their exit codes MUST mirror the
//! CLI's documented process contract: `keyhog::exit_codes::EXIT_REQUIRE_GPU_UNMET`
//! (12) and `EXIT_SYSTEM_ERROR` (3). The CLI contract test source-string-checks
//! the mirror; this pins the COMPILED scanner-side values and their distinctness
//! (the two hard-stop reasons must be distinguishable by exit code).

use keyhog_scanner::testing::process_exit_codes_for_test as exit_codes;

#[test]
fn scanner_hard_exit_codes_match_documented_contract() {
    let (require_gpu_unmet, backend_unavailable) = exit_codes();
    assert_eq!(
        require_gpu_unmet, 12,
        "REQUIRE_GPU_UNMET_EXIT_CODE must mirror keyhog::exit_codes::EXIT_REQUIRE_GPU_UNMET (12)"
    );
    assert_eq!(
        backend_unavailable, 3,
        "BACKEND_UNAVAILABLE_EXIT_CODE must mirror keyhog::exit_codes::EXIT_SYSTEM_ERROR (3)"
    );
}

#[test]
fn the_two_hard_exit_codes_are_distinct() {
    let (require_gpu_unmet, backend_unavailable) = exit_codes();
    assert_ne!(
        require_gpu_unmet, backend_unavailable,
        "the require-GPU and backend-unavailable hard exits must be distinguishable by exit code"
    );
}
