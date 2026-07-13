//! Regression: core severity-threshold suppression.
//!
//! Two coupled contracts are exercised here, both host-independent (pure enum
//! ordering + vyre's CPU rule evaluator, no Hyperscan/SIMD/GPU backend touched,
//! so every assertion below holds identically on an accelerator-less CI box):
//!
//!   1. `Severity`'s derived `Ord` MUST rank
//!      `Info < ClientSafe < Low < Medium < High < Critical`. Every
//!      severity-threshold decision (the `severity_lte` suppressor here, and the
//!      CLI `--min-severity` drop that shares this enum) rides on that order.
//!   2. A `[[suppress]]` rule's `severity_lte = "<tier>"` drops exactly the
//!      findings whose severity rank is at-or-below `<tier>` and KEEPS every
//!      finding strictly above it. `RuleSuppressor::matches(finding) == true`
//!      means the finding is suppressed (dropped from the report); `false` means
//!      it survives.
//!
//! The load-bearing adversarial case is `ClientSafe`: it ranks BELOW `Low`, so
//! `severity_lte = "low"` must also suppress client-safe findings. An earlier
//! rank table that omitted the `client-safe` tier silently skipped exactly those
//! findings, that regression is pinned by
//! [`severity_lte_low_also_suppresses_client_safe_below_it`].

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use keyhog_core::{
    CredentialHash, MatchLocation, RuleSuppressor, RuleSuppressorError, Severity,
    VerificationResult, VerifiedFinding,
};

/// Build a minimal `VerifiedFinding` carrying an exact severity, detector id,
/// and file path. Everything else is a fixed, suppression-irrelevant placeholder
/// (all-zero hash, no verification). All fields are public and the struct is not
/// `#[non_exhaustive]`, so this literal is the standalone-test construction path.
fn finding(severity: Severity, detector_id: &str, file_path: &str) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from("Test Detector"),
        service: Arc::from("test-service"),
        severity,
        credential_redacted: Cow::Borrowed("****"),
        credential_hash: CredentialHash::ZERO,
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from(file_path)),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: Vec::new(),
        confidence: None,
    }
}

/// Parse a `.keyhogignore.toml` body through the public `FromStr` surface,
/// panicking (with the parse error) on malformed TOML so a broken fixture is an
/// obvious failure rather than a silent skip.
fn suppressor(toml_body: &str) -> RuleSuppressor {
    toml_body
        .parse::<RuleSuppressor>()
        .unwrap_or_else(|e| panic!("suppressor parse failed: {e}"))
}

// ---------------------------------------------------------------------------
// 1. Severity Ord (the ordering every threshold rides on).
// ---------------------------------------------------------------------------

#[test]
fn severity_ord_is_critical_high_medium_low_client_safe_info() {
    // Strictly descending chain, each link asserted as a concrete bool.
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::ClientSafe);
    assert!(Severity::ClientSafe > Severity::Info);

    // The adversarial inversion: ClientSafe is BELOW Low, not above it.
    assert!(Severity::ClientSafe < Severity::Low);
    assert!(!(Severity::ClientSafe >= Severity::Low));

    // Transitive extreme + reflexive floor.
    assert!(Severity::Critical > Severity::Info);
    assert!(Severity::Info <= Severity::Info);
    assert_eq!(
        Severity::Medium.cmp(&Severity::Medium),
        std::cmp::Ordering::Equal
    );
}

#[test]
fn severity_sorts_into_canonical_low_to_high_order() {
    let mut tiers = vec![
        Severity::Critical,
        Severity::Info,
        Severity::High,
        Severity::ClientSafe,
        Severity::Medium,
        Severity::Low,
    ];
    tiers.sort();
    assert_eq!(
        tiers,
        vec![
            Severity::Info,
            Severity::ClientSafe,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ]
    );
}

#[test]
fn severity_downgrade_one_steps_exactly_one_tier_and_floors_at_info() {
    assert_eq!(Severity::Critical.downgrade_one(), Severity::High);
    assert_eq!(Severity::High.downgrade_one(), Severity::Medium);
    assert_eq!(Severity::Medium.downgrade_one(), Severity::Low);
    assert_eq!(Severity::Low.downgrade_one(), Severity::ClientSafe);
    assert_eq!(Severity::ClientSafe.downgrade_one(), Severity::Info);
    // Info is the floor: no lower bucket exists.
    assert_eq!(Severity::Info.downgrade_one(), Severity::Info);
}

// ---------------------------------------------------------------------------
// 2. severity_lte threshold suppression (kept vs suppressed per exact tier).
// ---------------------------------------------------------------------------

#[test]
fn severity_lte_low_suppresses_at_and_below_keeps_above() {
    let sup = suppressor("[[suppress]]\nseverity_lte = \"low\"\n");
    // At/below Low → suppressed (matches == true).
    assert!(sup.matches(&finding(Severity::Info, "d", "a.rs")));
    assert!(sup.matches(&finding(Severity::ClientSafe, "d", "a.rs")));
    assert!(sup.matches(&finding(Severity::Low, "d", "a.rs")));
    // Strictly above Low → kept (matches == false).
    assert!(!sup.matches(&finding(Severity::Medium, "d", "a.rs")));
    assert!(!sup.matches(&finding(Severity::High, "d", "a.rs")));
    assert!(!sup.matches(&finding(Severity::Critical, "d", "a.rs")));
}

#[test]
fn severity_lte_low_also_suppresses_client_safe_below_it() {
    // Pins the regression: client-safe ranks BELOW low, so a `severity_lte =
    // "low"` threshold MUST drop it. A rank table omitting the client-safe tier
    // silently kept these; this asserts the fixed behaviour with an exact bool.
    let sup = suppressor("[[suppress]]\nseverity_lte = \"low\"\n");
    assert_eq!(
        sup.matches(&finding(Severity::ClientSafe, "d", "a.rs")),
        true
    );
    // And a Low finding at the exact threshold is likewise suppressed.
    assert_eq!(sup.matches(&finding(Severity::Low, "d", "a.rs")), true);
}

#[test]
fn severity_lte_client_safe_boundary_keeps_low() {
    // Threshold exactly at client-safe: info + client-safe drop, low survives.
    let sup = suppressor("[[suppress]]\nseverity_lte = \"client-safe\"\n");
    assert!(sup.matches(&finding(Severity::Info, "d", "a.rs")));
    assert!(sup.matches(&finding(Severity::ClientSafe, "d", "a.rs")));
    assert!(!sup.matches(&finding(Severity::Low, "d", "a.rs")));
    assert!(!sup.matches(&finding(Severity::Medium, "d", "a.rs")));
}

#[test]
fn severity_lte_info_suppresses_only_info() {
    let sup = suppressor("[[suppress]]\nseverity_lte = \"info\"\n");
    assert!(sup.matches(&finding(Severity::Info, "d", "a.rs")));
    // ClientSafe ranks ABOVE Info, so it is kept.
    assert!(!sup.matches(&finding(Severity::ClientSafe, "d", "a.rs")));
    assert!(!sup.matches(&finding(Severity::Low, "d", "a.rs")));
    assert!(!sup.matches(&finding(Severity::Critical, "d", "a.rs")));
}

#[test]
fn severity_lte_medium_boundary_keeps_high_and_critical() {
    let sup = suppressor("[[suppress]]\nseverity_lte = \"medium\"\n");
    // Everything at/below medium is dropped.
    assert!(sup.matches(&finding(Severity::Info, "d", "a.rs")));
    assert!(sup.matches(&finding(Severity::ClientSafe, "d", "a.rs")));
    assert!(sup.matches(&finding(Severity::Low, "d", "a.rs")));
    assert!(sup.matches(&finding(Severity::Medium, "d", "a.rs")));
    // High and Critical survive.
    assert!(!sup.matches(&finding(Severity::High, "d", "a.rs")));
    assert!(!sup.matches(&finding(Severity::Critical, "d", "a.rs")));
}

#[test]
fn severity_lte_critical_suppresses_every_tier() {
    // Top of the ladder: nothing ranks above critical, so all six tiers drop.
    let sup = suppressor("[[suppress]]\nseverity_lte = \"critical\"\n");
    for sev in [
        Severity::Info,
        Severity::ClientSafe,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        assert!(
            sup.matches(&finding(sev, "d", "a.rs")),
            "severity_lte=critical must suppress {sev}"
        );
    }
}

#[test]
fn severity_lte_label_is_case_insensitive() {
    // Uppercase label normalises to the same threshold as lowercase.
    let sup = suppressor("[[suppress]]\nseverity_lte = \"LOW\"\n");
    assert!(sup.matches(&finding(Severity::Low, "d", "a.rs")));
    assert!(!sup.matches(&finding(Severity::Medium, "d", "a.rs")));
}

// ---------------------------------------------------------------------------
// 3. Exact-severity suppression + client-safe alias.
// ---------------------------------------------------------------------------

#[test]
fn severity_exact_match_drops_only_that_tier() {
    let sup = suppressor("[[suppress]]\nseverity = \"high\"\n");
    assert!(sup.matches(&finding(Severity::High, "d", "a.rs")));
    // Neither the tier above nor below is touched by an exact-equality rule.
    assert!(!sup.matches(&finding(Severity::Critical, "d", "a.rs")));
    assert!(!sup.matches(&finding(Severity::Medium, "d", "a.rs")));
}

#[test]
fn severity_exact_accepts_client_safe_underscore_alias() {
    // `client_safe` (underscore) is the serde alias for the `client-safe` tier;
    // the exact-match rule must resolve it to the same severity.
    let sup = suppressor("[[suppress]]\nseverity = \"client_safe\"\n");
    assert!(sup.matches(&finding(Severity::ClientSafe, "d", "a.rs")));
    assert!(!sup.matches(&finding(Severity::Low, "d", "a.rs")));
    assert!(!sup.matches(&finding(Severity::Info, "d", "a.rs")));
}

// ---------------------------------------------------------------------------
// 4. Combination semantics (AND within a table, OR across tables) + empty +
//    error path.
// ---------------------------------------------------------------------------

#[test]
fn severity_lte_ands_with_detector_within_one_table() {
    // AND: both severity threshold AND detector must match to suppress.
    let sup = suppressor("[[suppress]]\nseverity_lte = \"low\"\ndetector = \"aws-access-key\"\n");
    // aws + Low → both conditions true → suppressed.
    assert!(sup.matches(&finding(Severity::Low, "aws-access-key", "a.rs")));
    // aws + High → severity too high → kept despite detector match.
    assert!(!sup.matches(&finding(Severity::High, "aws-access-key", "a.rs")));
    // other detector + Low → detector mismatch → kept despite severity match.
    assert!(!sup.matches(&finding(Severity::Low, "stripe-secret-key", "a.rs")));
}

#[test]
fn multiple_suppress_tables_or_across_severities() {
    // OR across tables: a finding matching EITHER table is dropped.
    let sup =
        suppressor("[[suppress]]\nseverity = \"critical\"\n\n[[suppress]]\nseverity = \"info\"\n");
    assert!(sup.matches(&finding(Severity::Critical, "d", "a.rs")));
    assert!(sup.matches(&finding(Severity::Info, "d", "a.rs")));
    // A tier named by neither table survives.
    assert!(!sup.matches(&finding(Severity::Medium, "d", "a.rs")));
    assert!(!sup.matches(&finding(Severity::High, "d", "a.rs")));
}

#[test]
fn empty_suppressor_keeps_every_severity() {
    // No `[[suppress]]` tables → suppressor matches nothing; even a critical
    // finding is kept (matches == false), the recall-safe empty contract.
    let sup = suppressor("");
    assert_eq!(
        sup.matches(&finding(Severity::Critical, "d", "a.rs")),
        false
    );
    assert_eq!(sup.matches(&finding(Severity::Info, "d", "a.rs")), false);
    assert_eq!(sup.matches(&finding(Severity::Low, "d", "a.rs")), false);
}

#[test]
fn unknown_severity_lte_label_is_a_schema_error() {
    // A bogus threshold label must fail closed at parse time with a Schema error
    // naming the offending entry index (never a silently-empty suppressor).
    let result = "[[suppress]]\nseverity_lte = \"urgent\"\n".parse::<RuleSuppressor>();
    match result {
        Err(RuleSuppressorError::Schema {
            rule_index,
            message,
        }) => {
            assert_eq!(rule_index, 0);
            assert!(
                message.contains("urgent"),
                "schema error should name the bad label, got: {message}"
            );
        }
        other => panic!("expected Schema error for bad severity_lte, got {other:?}"),
    }
}
