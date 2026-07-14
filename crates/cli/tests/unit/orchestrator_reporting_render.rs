//! Completion-summary and progress-ticker renderers, relocated out of the
//! `orchestrator::reporting` source module (the `*_no_inline_tests` folder
//! gates forbid inline `#[cfg(test)]`). The pure formatting functions are
//! reached through the `crate::testing` facade (`CliTestApi`).

use keyhog::testing::{CliTestApi as _, API};

fn finding(verification: keyhog_core::VerificationResult) -> keyhog_core::VerifiedFinding {
    use std::borrow::Cow;
    use std::sync::Arc;
    keyhog_core::VerifiedFinding {
        detector_id: Arc::from("aws-access-key"),
        detector_name: Arc::from("AWS Key"),
        service: Arc::from("aws"),
        severity: keyhog_core::Severity::High,
        credential_redacted: Cow::Borrowed("AKIA..."),
        credential_hash: [0u8; 32].into(),
        companions_redacted: std::collections::HashMap::new(),
        location: keyhog_core::MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("a.txt")),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification,
        metadata: std::collections::HashMap::new(),
        additional_locations: vec![],
        entropy: None,
        confidence: Some(0.9),
    }
}

fn finding_with(
    severity: keyhog_core::Severity,
    verification: keyhog_core::VerificationResult,
) -> keyhog_core::VerifiedFinding {
    let mut finding = finding(verification);
    finding.severity = severity;
    finding
}

#[test]
fn breakdown_tallies_each_verification_state() {
    use keyhog_core::VerificationResult as V;
    let findings = vec![
        finding(V::Live),
        finding(V::Live),
        finding(V::Revoked),
        finding(V::Dead),
        finding(V::Skipped),
        finding(V::Unverifiable),
        finding(V::RateLimited),
        finding(V::Error("boom".to_string())),
    ];
    let tally = API.verification_tally(&findings);
    assert_eq!(tally.live, 2);
    assert_eq!(tally.inactive, 2, "revoked + dead");
    assert_eq!(tally.skipped, 1);
    assert_eq!(tally.unverifiable, 1);
    assert_eq!(tally.incomplete, 2, "ratelimited + error");
}

#[test]
fn all_skipped_says_verification_did_not_run() {
    use keyhog_core::VerificationResult as V;
    let findings = vec![
        finding(V::Skipped),
        finding(V::Skipped),
        finding(V::Skipped),
    ];
    let line = API
        .render_verification_summary(&findings, false)
        .expect("line for >0 findings");
    assert!(
        line.contains("liveness check did not run"),
        "honest 'we did not try': {line}"
    );
    assert!(
        line.contains("not checked"),
        "posture should be explicit: {line}"
    );
    assert!(line.contains("--verify"), "points at the flag: {line}");
    // The all-skipped branch emits the prose message, never a count breakdown
    // so it cannot read as "1 live", and carries no `·` separator.
    assert!(
        !line.contains('·'),
        "all-skipped uses the prose message, not a breakdown: {line}"
    );
}

#[test]
fn mixed_states_render_breakdown_omitting_zeros() {
    use keyhog_core::VerificationResult as V;
    let findings = vec![finding(V::Live), finding(V::Revoked), finding(V::Skipped)];
    let line = API.render_verification_summary(&findings, false).unwrap();
    assert!(line.contains("1 live"), "{line}");
    assert!(line.contains("1 revoked/dead"), "{line}");
    assert!(line.contains("1 not checked"), "{line}");
    assert!(line.contains("verification:"), "{line}");
    assert!(
        !line.contains("no verifier"),
        "zero category omitted: {line}"
    );
    assert!(
        !line.contains("inconclusive"),
        "zero category omitted: {line}"
    );
}

#[test]
fn no_findings_yields_no_verification_line() {
    assert_eq!(API.render_verification_summary(&[], false), None);
}

#[test]
fn severity_summary_is_heat_ordered_and_color_gated() {
    use keyhog_core::Severity as S;
    use keyhog_core::VerificationResult as V;
    let findings = vec![
        finding_with(S::Low, V::Skipped),
        finding_with(S::Critical, V::Skipped),
        finding_with(S::High, V::Skipped),
        finding_with(S::ClientSafe, V::Skipped),
        finding_with(S::High, V::Skipped),
    ];
    let plain = API.render_severity_summary(&findings, false).unwrap();
    assert_eq!(
        plain,
        "↳ severity: 1 critical · 2 high · 1 low · 1 client-safe"
    );
    assert!(!plain.contains('\x1b'), "plain severity line: {plain:?}");
    let colored = API.render_severity_summary(&findings, true).unwrap();
    assert!(
        colored.contains('\x1b'),
        "colored severity line should use heat SGR codes: {colored:?}"
    );
    assert!(colored.contains("1 critical"), "{colored}");
    assert!(colored.contains("2 high"), "{colored}");
    assert_eq!(API.render_severity_summary(&[], true), None);
}

#[test]
fn verification_summary_colours_posture_without_plain_ansi() {
    use keyhog_core::VerificationResult as V;
    let findings = vec![
        finding(V::Live),
        finding(V::Skipped),
        finding(V::Error("e".into())),
    ];
    let plain = API.render_verification_summary(&findings, false).unwrap();
    assert_eq!(
        plain,
        "↳ verification: 1 live · 1 not checked · 1 inconclusive"
    );
    assert!(
        !plain.contains('\x1b'),
        "plain verification line: {plain:?}"
    );
    let colored = API.render_verification_summary(&findings, true).unwrap();
    assert!(
        colored.contains('\x1b'),
        "colored verification line should use posture SGR codes: {colored:?}"
    );
    assert!(colored.contains("1 live"), "{colored}");
    assert!(colored.contains("1 not checked"), "{colored}");
}

#[test]
fn verification_line_is_color_gated() {
    use keyhog_core::VerificationResult as V;
    let findings = vec![finding(V::Live)];
    assert!(
        !API.render_verification_summary(&findings, false)
            .unwrap()
            .contains('\x1b'),
        "plain mode is ansi-free"
    );
    assert!(
        API.render_verification_summary(&findings, true)
            .unwrap()
            .contains('\x1b'),
        "color mode carries SGR codes"
    );
}

#[test]
fn progress_bar_endpoints_and_width() {
    // Empty: all rail, no full blocks; correct cell count.
    let empty = API.render_progress_bar(0.0, 22, false);
    assert_eq!(empty.chars().count(), 22, "bar must be exactly width cells");
    assert_eq!(empty.chars().filter(|&c| c == '█').count(), 0);
    assert!(empty.chars().all(|c| c == '░'));
    // Full: all full blocks.
    let full = API.render_progress_bar(1.0, 22, false);
    assert_eq!(full.chars().filter(|&c| c == '█').count(), 22);
    assert!(!full.contains('░'));
    // Half: ~11 full blocks (1/8-cell resolution rounds 0.5*22=11.0).
    let half = API.render_progress_bar(0.5, 22, false);
    assert_eq!(half.chars().filter(|&c| c == '█').count(), 11);
    // Clamp: out-of-range fractions never panic or overflow the width.
    assert_eq!(
        API.render_progress_bar(2.0, 22, false)
            .chars()
            .filter(|&c| c == '█')
            .count(),
        22
    );
    assert_eq!(API.render_progress_bar(-1.0, 22, false).chars().count(), 22);
}

#[test]
fn scanning_line_carries_pct_counts_findings_and_stage() {
    let line = API.render_scanning_ticker(50, 100, 3, 2.0, 0, false);
    assert!(line.contains("50%"), "percent: {line}");
    assert!(line.contains("50/100"), "scanned/total: {line}");
    assert!(line.contains("3 findings"), "lit findings: {line}");
    assert!(line.contains("scanning"), "stage label: {line}");
    // At 100% scanned the stage flips to finalizing and drops the ETA.
    let done = API.render_scanning_ticker(100, 100, 3, 2.0, 0, false);
    assert!(done.contains("finalizing"), "finalizing at full: {done}");
    assert!(!done.contains("eta"), "no eta once scanned==total: {done}");
}

#[test]
fn preparing_line_used_before_first_chunk() {
    let line = API.render_scanning_ticker(0, 0, 0, 0.4, 0, false);
    assert!(line.contains("preparing"), "pre-dispatch label: {line}");
    assert!(line.contains("0 findings"));
    assert!(
        !line.contains('%'),
        "no percent before total is known: {line}"
    );
}

#[test]
fn verification_line_carries_stage_and_candidate_count() {
    let line = API.render_verification_ticker(3, 1.2, 0, false);
    assert!(line.contains("verifying"), "stage label: {line}");
    assert!(
        line.contains("checking 3 secrets"),
        "candidate count: {line}"
    );
    assert!(
        !line.contains('%'),
        "verification is indeterminate until verifier results return: {line}"
    );
    let one = API.render_verification_ticker(1, 1.2, 0, false);
    assert!(one.contains("checking 1 secret"), "singular noun: {one}");
}

#[test]
fn reporting_line_carries_stage_and_finding_count() {
    let line = API.render_reporting_ticker(3, 1.2, 0, false);
    assert!(line.contains("reporting"), "stage label: {line}");
    assert!(line.contains("writing 3 findings"), "finding count: {line}");
    assert!(
        !line.contains('%'),
        "reporting is indeterminate while serialization/fsync runs: {line}"
    );
    let one = API.render_reporting_ticker(1, 1.2, 0, false);
    assert!(one.contains("writing 1 finding"), "singular noun: {one}");
}

#[test]
fn ticker_guard_stop_signals_and_joins_worker() {
    assert!(
        API.ticker_guard_spawns_and_joins(),
        "ticker guard must signal done and join its worker promptly"
    );
}

#[test]
fn plain_mode_emits_no_ansi_color_mode_does() {
    let plain = API.render_scanning_ticker(50, 100, 3, 2.0, 0, false);
    assert!(
        !plain.contains('\x1b'),
        "NO_COLOR line must be ansi-free: {plain:?}"
    );
    let verify_plain = API.render_verification_ticker(3, 1.2, 0, false);
    assert!(
        !verify_plain.contains('\x1b'),
        "plain verification line must be ansi-free: {verify_plain:?}"
    );
    let colored = API.render_scanning_ticker(50, 100, 3, 2.0, 0, true);
    assert!(colored.contains('\x1b'), "color line must carry SGR codes");
    let verify_colored = API.render_verification_ticker(3, 1.2, 0, true);
    assert!(
        verify_colored.contains('\x1b'),
        "color verification line must carry SGR codes"
    );
    let report_plain = API.render_reporting_ticker(3, 1.2, 0, false);
    assert!(
        !report_plain.contains('\x1b'),
        "plain reporting line must be ansi-free: {report_plain:?}"
    );
    let report_colored = API.render_reporting_ticker(3, 1.2, 0, true);
    assert!(
        report_colored.contains('\x1b'),
        "color reporting line must carry SGR codes"
    );
}

#[test]
fn fmt_secs_switches_to_minutes_past_a_minute() {
    assert_eq!(API.fmt_secs(8.25), "8.2s");
    assert_eq!(API.fmt_secs(59.94), "59.9s");
    assert_eq!(API.fmt_secs(59.95), "1m00s");
    assert_eq!(API.fmt_secs(59.96), "1m00s");
    assert_eq!(API.fmt_secs(64.0), "1m04s");
    assert_eq!(API.fmt_secs(119.6), "2m00s");
}
