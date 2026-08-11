use super::{baseline_terminal_transition, guard_event_action, BaselineResult, GuardEventAction};
use keyhog_core::guard_state::{GuardRootState, GuardTransition};

#[test]
fn overflow_during_indexing_defers_coverage_lost() {
    assert_eq!(
        guard_event_action(Some(GuardRootState::Indexing), true),
        GuardEventAction::MarkDuringIndexing {
            coverage_lost: true
        }
    );
}

#[test]
fn events_during_indexing_mark_dirty_only() {
    assert_eq!(
        guard_event_action(Some(GuardRootState::Indexing), false),
        GuardEventAction::MarkDuringIndexing {
            coverage_lost: false
        }
    );
}

#[test]
fn overflow_on_current_uses_coverage_lost() {
    assert_eq!(
        guard_event_action(Some(GuardRootState::Current), true),
        GuardEventAction::Transition(GuardTransition::CoverageLost)
    );
}

#[test]
fn clean_with_indexing_overflow_is_degraded() {
    assert_eq!(
        baseline_terminal_transition(BaselineResult::Clean, true),
        GuardTransition::ReconciliationDegraded
    );
    assert_eq!(
        baseline_terminal_transition(BaselineResult::Clean, false),
        GuardTransition::ReconciliationClean
    );
    assert_eq!(
        baseline_terminal_transition(BaselineResult::Findings, true),
        GuardTransition::ReconciliationFindings
    );
}
