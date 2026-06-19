//! Regression: `--verify` severity-shift contract (lane-10 coherence).
//!
//! docs/src/verification.md ("Severity shift on verification") and
//! docs/src/first-scan.md ("a dead credential is downgraded one severity tier,
//! `critical` → `high`, …, never collapsed to a fixed level") promise a concrete
//! behavior: when live verification rejects a credential (`Dead`) or the provider
//! reports it as explicitly disabled (`Revoked`), the finding's severity drops
//! exactly ONE tier via `Severity::downgrade_one`. Every other verification
//! outcome (`Live`/`RateLimited`/`Error`/`Unverifiable`/`Skipped`) is treated as
//! unverified and leaves severity untouched.
//!
//! Before this was wired, `into_finding` copied `group.severity` verbatim for
//! every verdict, so the documented downgrade simply never happened — a stale
//! doc making a false behavioral claim. These tests pin the real, wired behavior
//! at the single canonical construction point (`keyhog_verifier::into_finding`,
//! the one place every verified finding is built from a grouped match + verdict)
//! against EXACT severity values, so the doc claim can never silently drift from
//! the binary again.

use std::collections::HashMap;
use std::sync::Arc;

use keyhog_core::{DedupedMatch, MatchLocation, Severity, VerificationResult};
use keyhog_verifier::testing::{TestApi, VerifierTestApi};

/// Build a minimal grouped match carrying `severity`. The credential/location
/// content is irrelevant to the severity-shift contract; only `severity` and the
/// verdict drive the assertion.
fn group_with_severity(severity: Severity) -> DedupedMatch {
    DedupedMatch {
        detector_id: Arc::from("test-detector"),
        detector_name: Arc::from("Test Detector"),
        service: Arc::from("test-service"),
        severity,
        credential: keyhog_core::SensitiveString::from("planted-credential-value"),
        credential_hash: [7u8; 32],
        companions: HashMap::new(),
        primary_location: MatchLocation {
            source: Arc::from("test"),
            file_path: None,
            line: None,
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        additional_locations: vec![],
        confidence: Some(0.95),
    }
}

/// Every severity tier, ordered. The canonical `downgrade_one` chain is
/// Critical → High → Medium → Low → ClientSafe → Info, with Info a fixed point.
const ALL_SEVERITIES: [Severity; 6] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::ClientSafe,
    Severity::Info,
];

/// The exact one-tier-down image of each severity, matching
/// `Severity::downgrade_one`. Asserting against a hand-written table (not by
/// calling `downgrade_one` again) makes this an independent oracle: if someone
/// "fixes" `downgrade_one` to collapse to a fixed level, this table catches it.
fn expected_downgraded(s: Severity) -> Severity {
    match s {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low => Severity::ClientSafe,
        Severity::ClientSafe => Severity::Info,
        Severity::Info => Severity::Info, // fixed point — never below Info
    }
}

/// The verdicts that DOWNGRADE one tier per the docs table.
fn downgrading_verdicts() -> Vec<VerificationResult> {
    vec![VerificationResult::Dead, VerificationResult::Revoked]
}

/// The verdicts that leave severity UNCHANGED per the docs table.
fn unchanged_verdicts() -> Vec<VerificationResult> {
    vec![
        VerificationResult::Live,
        VerificationResult::RateLimited,
        VerificationResult::Error("network timeout".into()),
        VerificationResult::Unverifiable,
        VerificationResult::Skipped,
    ]
}

/// Data-driven: for EVERY (severity, dead-or-revoked verdict) pair the finding's
/// severity is exactly one tier below the input, matching the docs table and
/// `Severity::downgrade_one`. 6 severities × 2 verdicts = 12 exact assertions.
#[test]
fn dead_and_revoked_downgrade_exactly_one_tier_for_every_severity() {
    for &sev in &ALL_SEVERITIES {
        for verdict in downgrading_verdicts() {
            let finding =
                TestApi.into_finding(group_with_severity(sev), verdict.clone(), HashMap::new());
            let want = expected_downgraded(sev);
            assert_eq!(
                finding.severity, want,
                "verdict {verdict:?} on a {sev:?} finding must downgrade exactly one tier to \
                 {want:?} (docs/src/verification.md severity-shift table); got {:?}",
                finding.severity
            );
            // The verdict itself must survive verbatim onto the finding.
            assert_eq!(
                finding.verification, verdict,
                "into_finding must preserve the verification verdict {verdict:?}"
            );
        }
    }
}

/// Data-driven negative twin: for EVERY (severity, non-conclusive verdict) pair
/// the severity is UNCHANGED. 6 severities × 5 verdicts = 30 exact assertions.
/// This proves the downgrade is scoped to dead/revoked only and never leaks into
/// live/error/skipped/etc.
#[test]
fn non_conclusive_verdicts_leave_severity_unchanged_for_every_severity() {
    for &sev in &ALL_SEVERITIES {
        for verdict in unchanged_verdicts() {
            let finding =
                TestApi.into_finding(group_with_severity(sev), verdict.clone(), HashMap::new());
            assert_eq!(
                finding.severity, sev,
                "verdict {verdict:?} must leave a {sev:?} finding at {sev:?} \
                 (only dead/revoked downgrade per docs); got {:?}",
                finding.severity
            );
            assert_eq!(
                finding.verification, verdict,
                "into_finding must preserve the verification verdict {verdict:?}"
            );
        }
    }
}

/// The exact worked example the docs cite: a CRITICAL credential the provider
/// rejects becomes HIGH, and a CRITICAL credential that is LIVE stays CRITICAL.
/// Pins the precise values shown in verification.md's box example.
#[test]
fn critical_dead_becomes_high_critical_live_stays_critical() {
    let dead = TestApi.into_finding(
        group_with_severity(Severity::Critical),
        VerificationResult::Dead,
        HashMap::new(),
    );
    assert_eq!(
        dead.severity,
        Severity::High,
        "a CRITICAL dead credential must render as HIGH (verification.md box example: \
         the second box header reads HIGH, not CRITICAL)"
    );

    let live = TestApi.into_finding(
        group_with_severity(Severity::Critical),
        VerificationResult::Live,
        HashMap::new(),
    );
    assert_eq!(
        live.severity,
        Severity::Critical,
        "a CRITICAL live credential keeps CRITICAL (it really is what it claims to be)"
    );
}

/// Info is the floor: a dead Info-severity credential cannot drop below Info.
/// This is the boundary case of `downgrade_one`'s fixed point.
#[test]
fn dead_info_stays_info_no_underflow() {
    let f = TestApi.into_finding(
        group_with_severity(Severity::Info),
        VerificationResult::Dead,
        HashMap::new(),
    );
    assert_eq!(
        f.severity,
        Severity::Info,
        "Info is the lowest tier; a dead Info finding must stay Info (no underflow)"
    );
}
