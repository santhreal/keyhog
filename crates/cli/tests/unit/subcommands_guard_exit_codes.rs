use super::exit_code_for_guard_state;
use crate::exit_codes::{EXIT_FINDINGS, EXIT_SOURCE_FAILED, EXIT_SUCCESS};

#[test]
fn dirty_is_fail_closed_exit_13() {
    assert_eq!(exit_code_for_guard_state("dirty", 0), EXIT_SOURCE_FAILED);
}

#[test]
fn current_clean_is_success() {
    assert_eq!(exit_code_for_guard_state("current", 0), EXIT_SUCCESS);
}

#[test]
fn blocked_or_findings_are_exit_1() {
    assert_eq!(exit_code_for_guard_state("blocked", 0), EXIT_FINDINGS);
    assert_eq!(exit_code_for_guard_state("current", 2), EXIT_FINDINGS);
}

#[test]
fn unproven_states_are_exit_13() {
    for state in ["stopped", "indexing", "degraded", "stale-policy", "dirty"] {
        assert_eq!(
            exit_code_for_guard_state(state, 0),
            EXIT_SOURCE_FAILED,
            "{state}"
        );
    }
}
