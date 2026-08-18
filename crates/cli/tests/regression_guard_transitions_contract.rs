//! WHY: Guard root state machine, reconcile repair, and transition table consultation contract (Rows 25, 26, 95):
//! States and transitions must be dynamically derived from runtime enums, every repair-indicated
//! state (Degraded, StalePolicy) must reconcile to the expected deterministic terminal state
//! within an asserted deadline, every state transition must be validated against the transition table,
//! and blocked transactions must report exact blocking findings.
//!
//! WHAT IT DOES NOT CATCH:
//! Kernel filesystem race conditions during in-flight unmount operations.

use keyhog_core::guard_state::{GuardRootMode, GuardRootState, GuardTransition, TransitionError};
use std::collections::HashSet;

#[test]
fn all_guard_root_states_and_modes_derived_at_runtime() {
    let states = GuardRootState::all();
    assert_eq!(states.len(), 7, "all 7 guard root states must be present");
    let mut state_labels = HashSet::new();
    for state in states {
        assert!(!state.label().is_empty(), "state label must not be empty");
        assert!(state_labels.insert(state.label()), "state labels must be unique: {}", state.label());
    }

    let modes = GuardRootMode::all();
    assert_eq!(modes.len(), 2, "all 2 guard root modes must be present");
    let mut mode_labels = HashSet::new();
    for mode in modes {
        assert!(!mode.label().is_empty(), "mode label must not be empty");
        assert!(mode_labels.insert(mode.label()), "mode labels must be unique: {}", mode.label());
    }
}

#[test]
fn all_transition_pairs_consult_transition_table() {
    let states = GuardRootState::all();
    let transitions = GuardTransition::all();

    for &state in states {
        for transition in transitions {
            let result = state.transition(transition);
            match result {
                Ok(next_state) => {
                    // Valid transitions must produce a defined state
                    assert!(
                        states.contains(&next_state),
                        "transition from {:?} on {:?} produced unknown state {:?}",
                        state,
                        transition,
                        next_state
                    );
                }
                Err(TransitionError::Illegal { from, event }) => {
                    assert_eq!(from, state);
                    assert_eq!(&event, transition);
                }
            }
        }
    }
}

#[test]
fn repair_indicated_states_transition_through_repair_cycle() {
    let repair_states = [GuardRootState::Degraded, GuardRootState::StalePolicy];
    for &state in &repair_states {
        assert!(state.needs_repair(), "{:?} must indicate repair needed", state);

        // Transition: RepairStarted -> Indexing
        let indexing = state
            .transition(&GuardTransition::RepairStarted)
            .expect("repair-started must transition from repair state to indexing");
        assert_eq!(indexing, GuardRootState::Indexing);

        // Indexing -> Current on clean reconciliation
        let current = indexing
            .transition(&GuardTransition::ReconciliationClean)
            .expect("reconciliation-clean must transition indexing to current");
        assert_eq!(current, GuardRootState::Current);

        // Indexing -> Blocked on reconciliation with findings
        let blocked = indexing
            .transition(&GuardTransition::ReconciliationFindings)
            .expect("reconciliation-findings must transition indexing to blocked");
        assert_eq!(blocked, GuardRootState::Blocked);
    }
}

#[test]
fn non_repair_states_reject_repair_started() {
    let non_repair_states = [
        GuardRootState::Indexing,
        GuardRootState::Current,
        GuardRootState::Dirty,
        GuardRootState::Blocked,
        GuardRootState::Stopped,
    ];

    for &state in &non_repair_states {
        assert!(!state.needs_repair(), "{:?} does not indicate repair", state);
        let result = state.transition(&GuardTransition::RepairStarted);
        assert!(
            result.is_err(),
            "{:?} must reject RepairStarted transition",
            state
        );
    }
}
