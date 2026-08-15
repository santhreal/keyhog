use super::{finalize_for_report, finalize_staged_for_report, guard_commit_exit_code};
use crate::args::ScanArgs;
use clap::Parser;
use keyhog_core::{EvidenceReasonCode, EvidenceVerdict, MatchLocation, RawMatch, Severity};
use std::sync::Arc;

fn staged_match(path: &std::path::Path) -> RawMatch {
    RawMatch {
        detector_id: Arc::from("guard-staged-test"),
        detector_name: Arc::from("Guard staged test"),
        service: Arc::from("guard-test"),
        severity: Severity::High,
        credential: keyhog_core::SensitiveString::from("staged-secret-value"),
        credential_hash: [9u8; 32].into(),
        companions: Default::default(),
        location: MatchLocation {
            source: Arc::from("git-staged"),
            file_path: Some(Arc::from(path.to_string_lossy().as_ref())),
            line: Some(2),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: None,
        evidence: EvidenceVerdict::from_reason(EvidenceReasonCode::VendorPattern),
    }
}

#[test]
fn staged_finalization_never_reads_worktree_inline_directives() {
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("secret.env");
    std::fs::write(
        &path,
        "// keyhog:ignore\nSTAGED_SECRET=worktree-placeholder\n",
    )
    .expect("write divergent worktree file");
    let root_arg = root.path().to_string_lossy().into_owned();
    let args =
        ScanArgs::try_parse_from(["scan", "--path", root_arg.as_str()]).expect("parse scan args");

    assert!(
        finalize_for_report(vec![staged_match(&path)], &args)
            .expect("finalize filesystem finding")
            .is_empty(),
        "the normal filesystem path must continue honoring inline directives"
    );
    let staged = finalize_staged_for_report(vec![staged_match(&path)], &args)
        .expect("finalize staged finding");
    assert_eq!(
        staged.len(),
        1,
        "staged bytes must not be suppressed by a divergent worktree directive"
    );
}

#[test]
fn guard_commit_exit_preserves_future_live_credential_exit() {
    assert_eq!(
        guard_commit_exit_code(crate::exit_codes::EXIT_LIVE_CREDENTIALS, false, 0),
        crate::exit_codes::EXIT_LIVE_CREDENTIALS
    );
    assert_eq!(
        guard_commit_exit_code(crate::exit_codes::EXIT_LIVE_CREDENTIALS, true, 3),
        crate::exit_codes::EXIT_LIVE_CREDENTIALS,
        "live credentials retain exit 10 even when guard coverage also fails closed"
    );
}
