//! Regression: the `.keyhogignore.toml` `severity_lte` / `severity` rank table
//! must agree with the `Severity` enum's derived ordering, which places
//! `ClientSafe` *below* `Low` (Info < ClientSafe < Low < Medium < High <
//! Critical). The previous rank table omitted `ClientSafe` entirely, so:
//!
//!   * `severity_lte = "low"` expanded to `{info, low}` and silently FAILED to
//!     suppress a client-safe finding that ranks below `low`.
//!   * `severity = "client-safe"` / `"client_safe"` were rejected at parse
//!     time as "unknown severity", so a rule targeting the client-safe tier
//!     could not be written at all.
//!
//! `FindingContext` reports a client-safe finding's severity as the kebab-case
//! `"client-safe"` (via `Severity::as_str`), so the suppressor's label set must
//! contain that exact string for the rule to fire.

use keyhog_core::{MatchLocation, Severity, VerificationResult, VerifiedFinding};
use std::collections::HashMap;
use std::sync::Arc;

fn finding(sev: Severity) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("aws-access-key"),
        detector_name: Arc::from("aws-access-key"),
        service: Arc::from("aws"),
        severity: sev,
        credential_redacted: std::borrow::Cow::Borrowed("REDACTED"),
        credential_hash: [0; 32].into(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("x")),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Skipped,
        metadata: HashMap::new(),
        additional_locations: Vec::new(),
        confidence: Some(0.9),
    }
}

#[test]
fn severity_lte_low_suppresses_client_safe_and_below() {
    let toml = r#"
[[suppress]]
detector = "aws-access-key"
severity_lte = "low"
"#;
    let s = keyhog_core::testing::CoreTestApi::rule_suppressor_parse(
        &keyhog_core::testing::TestApi,
        toml,
    )
    .expect("parse");
    // Info, ClientSafe, Low rank at or below "low" -> suppressed.
    assert!(s.matches(&finding(Severity::Info)), "info <= low");
    assert!(
        s.matches(&finding(Severity::ClientSafe)),
        "client-safe ranks below low and must be suppressed by severity_lte=low"
    );
    assert!(s.matches(&finding(Severity::Low)), "low <= low");
    // Medium and above are above the threshold -> kept.
    assert!(!s.matches(&finding(Severity::Medium)), "medium > low");
    assert!(!s.matches(&finding(Severity::High)), "high > low");
    assert!(!s.matches(&finding(Severity::Critical)), "critical > low");
}

#[test]
fn severity_eq_client_safe_matches_only_client_safe() {
    for spelling in ["client-safe", "client_safe", "CLIENT-SAFE"] {
        let toml =
            format!("[[suppress]]\ndetector = \"aws-access-key\"\nseverity = \"{spelling}\"\n");
        let s = keyhog_core::testing::CoreTestApi::rule_suppressor_parse(
            &keyhog_core::testing::TestApi,
            &toml,
        )
        .unwrap_or_else(|e| panic!("spelling {spelling:?} must parse: {e}"));
        assert!(
            s.matches(&finding(Severity::ClientSafe)),
            "severity={spelling:?} must match a ClientSafe finding"
        );
        assert!(
            !s.matches(&finding(Severity::Low)),
            "severity={spelling:?} must NOT match a Low finding"
        );
        assert!(
            !s.matches(&finding(Severity::Info)),
            "severity={spelling:?} must NOT match an Info finding"
        );
    }
}

#[test]
fn severity_lte_client_safe_keeps_low_and_above() {
    let toml = r#"
[[suppress]]
detector = "aws-access-key"
severity_lte = "client-safe"
"#;
    let s = keyhog_core::testing::CoreTestApi::rule_suppressor_parse(
        &keyhog_core::testing::TestApi,
        toml,
    )
    .expect("parse");
    assert!(s.matches(&finding(Severity::Info)), "info <= client-safe");
    assert!(
        s.matches(&finding(Severity::ClientSafe)),
        "client-safe <= client-safe"
    );
    assert!(
        !s.matches(&finding(Severity::Low)),
        "low ranks above client-safe and must be kept"
    );
}
