//! Regression coverage for the core severity model: the one-step
//! `Severity::downgrade_one` ladder (diff-aware scoring) and the
//! `severity_lte` threshold expansion used by `.keyhogignore.toml`
//! `[[suppress]]` rules.
//!
//! Every assertion pins a concrete value: an exact `Severity` variant, a
//! `bool` suppression decision at a named threshold boundary, the exact
//! kebab-case wire form, or a specific `RuleSuppressorError` variant + index.
//!
//! Two load-bearing contracts are guarded here:
//!   1. `downgrade_one` walks EXACTLY one tier, is monotone non-increasing,
//!      floors at `Info`, and never skips the `ClientSafe` tier
//!      (`Low -> ClientSafe`, not `Low -> Info`).
//!   2. `severity_lte = "X"` suppresses every finding whose severity ranks at
//!      or below `X` and INCLUDES the `ClientSafe` tier below `Low` - the exact
//!      drift (`severity_lte = "low"` silently skipping client-safe findings)
//!      that the rank table + enum-`Ord` coherence exists to prevent.

use std::collections::HashMap;
use std::sync::Arc;

use keyhog_core::{
    CredentialHash, MatchLocation, RuleSuppressor, RuleSuppressorError, Severity,
    VerificationResult, VerifiedFinding,
};

/// The documented total ordering, lowest to highest. Mirrors the enum's derived
/// `Ord` and `Severity::ORDERED`; declared locally so the test proves the public
/// behaviour without reaching into the crate-private `ORDERED` table.
const ORDER: [Severity; 6] = [
    Severity::Info,
    Severity::ClientSafe,
    Severity::Low,
    Severity::Medium,
    Severity::High,
    Severity::Critical,
];

fn finding_with(severity: Severity, file: &str) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("demo-token"),
        detector_name: Arc::from("Demo Token"),
        service: Arc::from("demo"),
        severity,
        credential_redacted: "abc...wxyz".into(),
        credential_hash: CredentialHash::from_bytes([0u8; 32]),
        companions_redacted: std::collections::HashMap::new(),
        location: MatchLocation {
            source: Arc::from("fs"),
            file_path: Some(Arc::from(file)),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: Vec::new(),
        entropy: None,
        confidence: None,
    }
}

// ---------------------------------------------------------------------------
// downgrade_one: exactly-one-step ladder
// ---------------------------------------------------------------------------

#[test]
fn downgrade_one_walks_exactly_one_step_from_each_tier() {
    assert_eq!(Severity::Critical.downgrade_one(), Severity::High);
    assert_eq!(Severity::High.downgrade_one(), Severity::Medium);
    assert_eq!(Severity::Medium.downgrade_one(), Severity::Low);
    assert_eq!(Severity::Low.downgrade_one(), Severity::ClientSafe);
    assert_eq!(Severity::ClientSafe.downgrade_one(), Severity::Info);
}

#[test]
fn downgrade_one_floors_at_info() {
    // Info is the bottom bucket: downgrading it is a no-op fixpoint.
    assert_eq!(Severity::Info.downgrade_one(), Severity::Info);
}

#[test]
fn downgrade_one_is_monotonic_non_increasing() {
    // Every tier downgrades to something <= itself (never up).
    for &s in &ORDER {
        assert!(
            s.downgrade_one() <= s,
            "{s:?} downgraded UP to {:?}",
            s.downgrade_one()
        );
    }
    // Strictly down everywhere except the Info floor, which stays equal.
    for &s in &ORDER {
        if s == Severity::Info {
            assert_eq!(s.downgrade_one(), s);
        } else {
            assert!(s.downgrade_one() < s, "{s:?} failed to step strictly down");
        }
    }
}

#[test]
fn downgrade_one_lands_on_immediately_preceding_tier() {
    // For every non-floor tier, downgrade lands on the tier one index below in
    // the documented ordering - proof it steps exactly one rank, never two.
    for i in 1..ORDER.len() {
        assert_eq!(
            ORDER[i].downgrade_one(),
            ORDER[i - 1],
            "{:?} did not step to {:?}",
            ORDER[i],
            ORDER[i - 1]
        );
    }
    assert_eq!(ORDER[0].downgrade_one(), ORDER[0]);
}

#[test]
fn downgrade_one_repeated_reaches_info_and_stays() {
    // Five steps from Critical bottoms out at Info; further steps are fixpoints.
    let seq = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::ClientSafe,
        Severity::Info,
    ];
    let mut cur = Severity::Critical;
    for expected in seq {
        assert_eq!(cur, expected);
        cur = cur.downgrade_one();
    }
    // `cur` has now walked one past Info; it must have clamped at Info.
    assert_eq!(cur, Severity::Info);
    // Two further downgrades change nothing.
    assert_eq!(cur.downgrade_one().downgrade_one(), Severity::Info);
}

#[test]
fn downgrade_one_does_not_skip_client_safe_tier() {
    // Adversarial: a naive `Low -> Info` implementation would hide the tier that
    // `--hide-client-safe` gates. Low must land on ClientSafe, not Info or Low.
    let stepped = Severity::Low.downgrade_one();
    assert_eq!(stepped, Severity::ClientSafe);
    assert_ne!(stepped, Severity::Info);
    assert_ne!(stepped, Severity::Low);
    // And ClientSafe is a real intermediate: Low.downgrade_one().downgrade_one()
    // reaches Info in two steps, never one.
    assert_eq!(stepped.downgrade_one(), Severity::Info);
}

#[test]
fn downgrade_one_preserves_kebab_wire_form() {
    // Downgraded severities must still serialize through the kebab-case wire
    // form (the `ClientSafe` -> `"client-safe"` case is the one that drifts).
    assert_eq!(
        serde_json::to_string(&Severity::Critical.downgrade_one()).unwrap(),
        r#""high""#
    );
    assert_eq!(
        serde_json::to_string(&Severity::Low.downgrade_one()).unwrap(),
        r#""client-safe""#
    );
    assert_eq!(
        serde_json::to_string(&Severity::ClientSafe.downgrade_one()).unwrap(),
        r#""info""#
    );
}

#[test]
fn severity_total_order_ranking() {
    // The ordering `severity_lte` expansion depends on, asserted directly.
    assert!(Severity::Info < Severity::ClientSafe);
    assert!(Severity::ClientSafe < Severity::Low);
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
    let mut shuffled = vec![
        Severity::High,
        Severity::Info,
        Severity::Critical,
        Severity::ClientSafe,
        Severity::Low,
        Severity::Medium,
    ];
    shuffled.sort();
    assert_eq!(shuffled, ORDER.to_vec());
}

// ---------------------------------------------------------------------------
// severity_lte threshold expansion (end-to-end via RuleSuppressor)
// ---------------------------------------------------------------------------

#[test]
fn severity_lte_low_suppresses_at_and_below_including_client_safe() {
    let sup: RuleSuppressor = "[[suppress]]\nseverity_lte = \"low\"\n"
        .parse()
        .expect("severity_lte = low must parse");

    // At or below `low` -> suppressed (true). Crucially ClientSafe, which ranks
    // BELOW low, must be included; the whole rank table exists to guarantee this.
    assert!(sup.matches(&finding_with(Severity::Info, "a.rs")));
    assert!(sup.matches(&finding_with(Severity::ClientSafe, "a.rs")));
    assert!(sup.matches(&finding_with(Severity::Low, "a.rs")));

    // Above `low` -> NOT suppressed (false). Boundary is between Low and Medium.
    assert!(!sup.matches(&finding_with(Severity::Medium, "a.rs")));
    assert!(!sup.matches(&finding_with(Severity::High, "a.rs")));
    assert!(!sup.matches(&finding_with(Severity::Critical, "a.rs")));
}

#[test]
fn severity_lte_client_safe_threshold_boundary() {
    // kebab-case label must parse; threshold at client-safe includes only the
    // two lowest tiers.
    let sup: RuleSuppressor = "[[suppress]]\nseverity_lte = \"client-safe\"\n"
        .parse()
        .expect("severity_lte = client-safe must parse");

    assert!(sup.matches(&finding_with(Severity::Info, "a.rs")));
    assert!(sup.matches(&finding_with(Severity::ClientSafe, "a.rs")));
    // Low is the first tier ABOVE the threshold: must not be suppressed.
    assert!(!sup.matches(&finding_with(Severity::Low, "a.rs")));
    assert!(!sup.matches(&finding_with(Severity::Medium, "a.rs")));
    assert!(!sup.matches(&finding_with(Severity::Critical, "a.rs")));
}

#[test]
fn severity_lte_info_threshold_matches_only_info() {
    // Floor threshold: only the single lowest tier is at-or-below.
    let sup: RuleSuppressor = "[[suppress]]\nseverity_lte = \"info\"\n"
        .parse()
        .expect("severity_lte = info must parse");

    assert!(sup.matches(&finding_with(Severity::Info, "a.rs")));
    // ClientSafe ranks strictly above Info -> not matched.
    assert!(!sup.matches(&finding_with(Severity::ClientSafe, "a.rs")));
    assert!(!sup.matches(&finding_with(Severity::Low, "a.rs")));
    assert!(!sup.matches(&finding_with(Severity::Critical, "a.rs")));
}

#[test]
fn severity_lte_critical_threshold_matches_all_tiers() {
    // Top threshold: the whole ladder is at-or-below, every tier suppressed.
    let sup: RuleSuppressor = "[[suppress]]\nseverity_lte = \"critical\"\n"
        .parse()
        .expect("severity_lte = critical must parse");

    for &s in &ORDER {
        assert!(
            sup.matches(&finding_with(s, "a.rs")),
            "{s:?} should be <= critical and suppressed"
        );
    }
}

#[test]
fn severity_lte_case_insensitive_uppercase_label() {
    // `from_filter_label` lowercases; an uppercase label behaves identically.
    let sup: RuleSuppressor = "[[suppress]]\nseverity_lte = \"LOW\"\n"
        .parse()
        .expect("uppercase severity_lte = LOW must parse");

    assert!(sup.matches(&finding_with(Severity::Low, "a.rs")));
    assert!(sup.matches(&finding_with(Severity::ClientSafe, "a.rs")));
    assert!(!sup.matches(&finding_with(Severity::Medium, "a.rs")));
}

#[test]
fn severity_lte_ands_with_path_condition() {
    // Within one [[suppress]] entry, conditions AND together: a below-threshold
    // severity is only suppressed when the path condition ALSO matches.
    let sup: RuleSuppressor = "[[suppress]]\nseverity_lte = \"low\"\npath_contains = \"/tests/\"\n"
        .parse()
        .expect("combined entry must parse");

    // Low severity + matching path -> suppressed.
    assert!(sup.matches(&finding_with(Severity::Low, "pkg/tests/fixture.rs")));
    // Low severity + non-matching path -> NOT suppressed (AND fails on path).
    assert!(!sup.matches(&finding_with(Severity::Low, "pkg/src/main.rs")));
    // Matching path but above-threshold severity -> NOT suppressed (AND fails
    // on severity).
    assert!(!sup.matches(&finding_with(Severity::High, "pkg/tests/fixture.rs")));
}

#[test]
fn severity_lte_unknown_label_is_schema_error() {
    // A garbage threshold label fails schema validation at entry index 0 with a
    // message naming the offending value - it must NOT silently match nothing.
    let err = "[[suppress]]\nseverity_lte = \"sev\"\n"
        .parse::<RuleSuppressor>()
        .expect_err("unknown severity label must be rejected");
    match err {
        RuleSuppressorError::Schema {
            rule_index,
            message,
        } => {
            assert_eq!(rule_index, 0);
            assert!(
                message.contains("unknown severity"),
                "unexpected message: {message}"
            );
        }
        other => panic!("expected Schema error, got {other:?}"),
    }
}

#[test]
fn severity_lte_clientsafe_without_dash_is_rejected() {
    // Adversarial near-miss: only `client-safe` / `client_safe` are valid; the
    // undelimited `clientsafe` must fail closed rather than parse to some tier.
    let err = "[[suppress]]\nseverity_lte = \"clientsafe\"\n"
        .parse::<RuleSuppressor>()
        .expect_err("clientsafe (no separator) must be rejected");
    match err {
        RuleSuppressorError::Schema { rule_index, .. } => assert_eq!(rule_index, 0),
        other => panic!("expected Schema error, got {other:?}"),
    }
}
