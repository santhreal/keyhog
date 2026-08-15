use super::{
    baseline_terminal_transition, guard_attestation_identity, guard_commit_terminal_state,
    guard_event_action, validate_staged_relative_path, BaselineResult, GuardEventAction,
};
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

#[test]
fn guard_commit_terminal_state_uses_default_policy_blockers() {
    assert_eq!(
        guard_commit_terminal_state(0, 0),
        GuardRootState::Current,
        "review-only findings do not block the default evidence policy"
    );
    assert_eq!(
        guard_commit_terminal_state(1, 0),
        GuardRootState::Blocked,
        "likely or confirmed findings block the default evidence policy"
    );
    assert_eq!(
        guard_commit_terminal_state(0, 1),
        GuardRootState::Degraded,
        "incomplete coverage remains fail closed"
    );
    assert_eq!(
        guard_commit_terminal_state(1, 1),
        GuardRootState::Blocked,
        "blocking findings retain exit precedence over coverage gaps"
    );
}

#[test]
fn guard_attestations_are_bound_to_the_exact_staged_path_set() {
    let base = keyhog_core::guard_state::GuardPolicyIdentity {
        build_identity: "build".to_string(),
        detector_digest: "detectors".to_string(),
        suppression_digest: "suppressions".to_string(),
        keyhogignore_digest: "ignore".to_string(),
        config_digest: "config".to_string(),
        decode_policy_version: 1,
        source_policy_digest: "source-policy".to_string(),
        guard_schema_version: 1,
        report_semantics_version: keyhog_core::guard_state::GUARD_REPORT_SEMANTICS_VERSION,
    };
    let env_identity = guard_attestation_identity(&base, &[".env.secret".to_string()]);
    let text_identity = guard_attestation_identity(&base, &["secret.txt".to_string()]);
    let aliased_identity = guard_attestation_identity(
        &base,
        &[".env.secret".to_string(), "secret.txt".to_string()],
    );

    assert_ne!(
        env_identity.short_digest().unwrap(),
        text_identity.short_digest().unwrap(),
        "a clean hit in unsupported text context must not authorize credential context"
    );
    assert_ne!(
        env_identity.short_digest().unwrap(),
        aliased_identity.short_digest().unwrap(),
        "adding a staged alias must invalidate the clean attestation"
    );
    assert!(
        !env_identity.source_policy_digest.contains(".env.secret"),
        "persisted policy identities retain only a digest of staged paths"
    );
}

#[test]
fn staged_source_paths_reject_non_normal_components_before_join() {
    for invalid in [
        "",
        "/outside",
        "..",
        "../outside",
        "nested/../../outside",
        "./file",
        "nested/./file",
        "nested//file",
        "nested/",
        "C:\\outside",
        "C:/outside",
        "\\\\server\\share",
        "nested\\..\\outside",
    ] {
        assert!(
            validate_staged_relative_path(invalid).is_err(),
            "staged path must reject non-normal, absolute, parent, current, and platform-prefix components: {invalid}"
        );
    }
    assert_eq!(
        validate_staged_relative_path("nested/config.env").unwrap(),
        std::path::Path::new("nested/config.env")
    );
}
