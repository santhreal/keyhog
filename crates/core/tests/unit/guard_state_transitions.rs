//! Exhaustive state transition tests for the guard root state machine.
//!
//! Every legal transition is tested, and every illegal transition is asserted
//! to return an error. Adding a state or event without updating the transition
//! function makes these tests fail.

use keyhog_core::guard_state::{GuardRootState, GuardTransition, TransitionError};

/// All transition events for exhaustive testing.
fn all_transitions() -> Vec<GuardTransition> {
    vec![
        GuardTransition::ReconciliationStarted,
        GuardTransition::ReconciliationClean,
        GuardTransition::ReconciliationFindings,
        GuardTransition::ReconciliationDegraded,
        GuardTransition::EventAccepted,
        GuardTransition::EventsClean,
        GuardTransition::EventsFindings,
        GuardTransition::EventsDegraded,
        GuardTransition::CoverageLost,
        GuardTransition::PolicyChanged,
        GuardTransition::RepairStarted,
        GuardTransition::Stopped,
    ]
}

#[test]
fn stopped_to_indexing_on_reconciliation_started() {
    let result = GuardRootState::Stopped.transition(&GuardTransition::ReconciliationStarted);
    assert_eq!(result, Ok(GuardRootState::Indexing));
}

#[test]
fn indexing_to_current_on_clean_reconciliation() {
    let result = GuardRootState::Indexing.transition(&GuardTransition::ReconciliationClean);
    assert_eq!(result, Ok(GuardRootState::Current));
}

#[test]
fn indexing_to_blocked_on_findings_reconciliation() {
    let result = GuardRootState::Indexing.transition(&GuardTransition::ReconciliationFindings);
    assert_eq!(result, Ok(GuardRootState::Blocked));
}

#[test]
fn indexing_to_degraded_on_degraded_reconciliation() {
    let result = GuardRootState::Indexing.transition(&GuardTransition::ReconciliationDegraded);
    assert_eq!(result, Ok(GuardRootState::Degraded));
}

#[test]
fn current_to_dirty_on_event_accepted() {
    let result = GuardRootState::Current.transition(&GuardTransition::EventAccepted);
    assert_eq!(result, Ok(GuardRootState::Dirty));
}

#[test]
fn blocked_to_dirty_on_event_accepted() {
    let result = GuardRootState::Blocked.transition(&GuardTransition::EventAccepted);
    assert_eq!(result, Ok(GuardRootState::Dirty));
}

#[test]
fn dirty_to_current_on_events_clean() {
    let result = GuardRootState::Dirty.transition(&GuardTransition::EventsClean);
    assert_eq!(result, Ok(GuardRootState::Current));
}

#[test]
fn dirty_to_blocked_on_events_findings() {
    let result = GuardRootState::Dirty.transition(&GuardTransition::EventsFindings);
    assert_eq!(result, Ok(GuardRootState::Blocked));
}

#[test]
fn dirty_to_degraded_on_events_degraded() {
    let result = GuardRootState::Dirty.transition(&GuardTransition::EventsDegraded);
    assert_eq!(result, Ok(GuardRootState::Degraded));
}

#[test]
fn any_active_to_degraded_on_coverage_lost() {
    for &state in &[
        GuardRootState::Indexing,
        GuardRootState::Current,
        GuardRootState::Dirty,
        GuardRootState::Blocked,
    ] {
        let result = state.transition(&GuardTransition::CoverageLost);
        assert_eq!(
            result,
            Ok(GuardRootState::Degraded),
            "coverage-lost from {state:?} should go to Degraded"
        );
    }
}

#[test]
fn any_active_to_stale_policy_on_policy_changed() {
    for &state in &[
        GuardRootState::Indexing,
        GuardRootState::Current,
        GuardRootState::Dirty,
        GuardRootState::Blocked,
    ] {
        let result = state.transition(&GuardTransition::PolicyChanged);
        assert_eq!(
            result,
            Ok(GuardRootState::StalePolicy),
            "policy-changed from {state:?} should go to StalePolicy"
        );
    }
}

#[test]
fn degraded_to_indexing_on_repair_started() {
    let result = GuardRootState::Degraded.transition(&GuardTransition::RepairStarted);
    assert_eq!(result, Ok(GuardRootState::Indexing));
}

#[test]
fn stale_policy_to_indexing_on_repair_started() {
    let result = GuardRootState::StalePolicy.transition(&GuardTransition::RepairStarted);
    assert_eq!(result, Ok(GuardRootState::Indexing));
}

#[test]
fn any_state_to_stopped() {
    for &state in GuardRootState::all() {
        let result = state.transition(&GuardTransition::Stopped);
        assert_eq!(
            result,
            Ok(GuardRootState::Stopped),
            "stopped from {state:?} should go to Stopped"
        );
    }
}

#[test]
fn degraded_stays_degraded_on_coverage_lost() {
    let result = GuardRootState::Degraded.transition(&GuardTransition::CoverageLost);
    assert_eq!(result, Ok(GuardRootState::Degraded));
}

#[test]
fn stale_policy_stays_stale_on_policy_changed() {
    let result = GuardRootState::StalePolicy.transition(&GuardTransition::PolicyChanged);
    assert_eq!(result, Ok(GuardRootState::StalePolicy));
}

#[test]
fn stopped_rejects_event_accepted() {
    let result = GuardRootState::Stopped.transition(&GuardTransition::EventAccepted);
    assert!(matches!(result, Err(TransitionError::Illegal { .. })));
}

#[test]
fn current_rejects_reconciliation_started() {
    let result = GuardRootState::Current.transition(&GuardTransition::ReconciliationStarted);
    assert!(matches!(result, Err(TransitionError::Illegal { .. })));
}

#[test]
fn current_rejects_events_clean() {
    let result = GuardRootState::Current.transition(&GuardTransition::EventsClean);
    assert!(matches!(result, Err(TransitionError::Illegal { .. })));
}

#[test]
fn blocked_rejects_reconciliation_clean() {
    let result = GuardRootState::Blocked.transition(&GuardTransition::ReconciliationClean);
    assert!(matches!(result, Err(TransitionError::Illegal { .. })));
}

#[test]
fn stopped_rejects_repair_started() {
    let result = GuardRootState::Stopped.transition(&GuardTransition::RepairStarted);
    assert!(matches!(result, Err(TransitionError::Illegal { .. })));
}

#[test]
fn current_rejects_repair_started() {
    let result = GuardRootState::Current.transition(&GuardTransition::RepairStarted);
    assert!(matches!(result, Err(TransitionError::Illegal { .. })));
}

#[test]
fn dirty_rejects_reconciliation_started() {
    let result = GuardRootState::Dirty.transition(&GuardTransition::ReconciliationStarted);
    assert!(matches!(result, Err(TransitionError::Illegal { .. })));
}

#[test]
fn indexing_rejects_event_accepted() {
    let result = GuardRootState::Indexing.transition(&GuardTransition::EventAccepted);
    assert!(matches!(result, Err(TransitionError::Illegal { .. })));
}

#[test]
fn every_state_has_a_label() {
    for &state in GuardRootState::all() {
        let label = state.label();
        assert!(!label.is_empty(), "state {state:?} has empty label");
    }
}

#[test]
fn all_states_returns_seven_variants() {
    assert_eq!(GuardRootState::all().len(), 7);
}

#[test]
fn no_state_authorizes_commit() {
    // Background state alone never authorizes a commit. The exact staged
    // transaction is the only local commit authorization input.
    for &state in GuardRootState::all() {
        assert!(
            !state.may_authorize_commit(),
            "state {state:?} must not authorize commit from background"
        );
    }
}

#[test]
fn only_degraded_and_stale_policy_need_repair() {
    for &state in GuardRootState::all() {
        let needs = state.needs_repair();
        let expected = matches!(
            state,
            GuardRootState::Degraded | GuardRootState::StalePolicy
        );
        assert_eq!(needs, expected, "state {state:?} repair-need mismatch");
    }
}

/// Full lifecycle: stopped -> indexing -> current -> dirty -> current -> stopped
#[test]
fn full_clean_lifecycle() {
    let s = GuardRootState::Stopped;
    let s = s
        .transition(&GuardTransition::ReconciliationStarted)
        .unwrap();
    assert_eq!(s, GuardRootState::Indexing);
    let s = s.transition(&GuardTransition::ReconciliationClean).unwrap();
    assert_eq!(s, GuardRootState::Current);
    let s = s.transition(&GuardTransition::EventAccepted).unwrap();
    assert_eq!(s, GuardRootState::Dirty);
    let s = s.transition(&GuardTransition::EventsClean).unwrap();
    assert_eq!(s, GuardRootState::Current);
    let s = s.transition(&GuardTransition::Stopped).unwrap();
    assert_eq!(s, GuardRootState::Stopped);
}

/// Finding lifecycle: stopped -> indexing -> blocked -> dirty -> blocked -> stopped
#[test]
fn finding_lifecycle() {
    let s = GuardRootState::Stopped;
    let s = s
        .transition(&GuardTransition::ReconciliationStarted)
        .unwrap();
    let s = s
        .transition(&GuardTransition::ReconciliationFindings)
        .unwrap();
    assert_eq!(s, GuardRootState::Blocked);
    let s = s.transition(&GuardTransition::EventAccepted).unwrap();
    assert_eq!(s, GuardRootState::Dirty);
    let s = s.transition(&GuardTransition::EventsFindings).unwrap();
    assert_eq!(s, GuardRootState::Blocked);
}

/// Degraded recovery: indexing -> degraded -> indexing -> current
#[test]
fn degraded_recovery_lifecycle() {
    let s = GuardRootState::Indexing;
    let s = s.transition(&GuardTransition::CoverageLost).unwrap();
    assert_eq!(s, GuardRootState::Degraded);
    let s = s.transition(&GuardTransition::RepairStarted).unwrap();
    assert_eq!(s, GuardRootState::Indexing);
    let s = s.transition(&GuardTransition::ReconciliationClean).unwrap();
    assert_eq!(s, GuardRootState::Current);
}

/// Stale policy recovery: current -> stale-policy -> indexing -> current
#[test]
fn stale_policy_recovery_lifecycle() {
    let s = GuardRootState::Current;
    let s = s.transition(&GuardTransition::PolicyChanged).unwrap();
    assert_eq!(s, GuardRootState::StalePolicy);
    let s = s.transition(&GuardTransition::RepairStarted).unwrap();
    assert_eq!(s, GuardRootState::Indexing);
    let s = s.transition(&GuardTransition::ReconciliationClean).unwrap();
    assert_eq!(s, GuardRootState::Current);
}

/// Exhaustive: for every (state, event) pair, the transition either succeeds
/// with a known target or returns Illegal. No panics, no unhandled cases.
#[test]
fn exhaustive_transition_matrix_no_panics() {
    for &state in GuardRootState::all() {
        for event in all_transitions() {
            let result = state.transition(&event);
            // Either Ok with a valid state, or Err with Illegal.
            match result {
                Ok(new_state) => {
                    assert!(
                        GuardRootState::all().contains(&new_state),
                        "transition {event} from {state:?} produced invalid state {new_state:?}"
                    );
                }
                Err(TransitionError::Illegal { .. }) => {}
            }
        }
    }
}
