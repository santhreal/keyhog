//! Regression contract for the detector-spec **severity** mapping.
//!
//! A detector's `severity` is Tier-B config: it is declared as a string in the
//! detector TOML (`severity = "critical"`) and deserialized into the
//! [`Severity`] enum by serde (`#[serde(rename_all = "kebab-case")]`, with an
//! `alias = "client_safe"` on the `ClientSafe` tier). Severity is what
//! `--min-severity` / `--hide-client-safe` gate on, so a silent mis-map (e.g.
//! `"critical"` parsed as the default `Info`) would over-suppress real leaks.
//!
//! This file pins, with concrete expected values:
//!   * the shipped `detectors/*.toml` severities read off the real on-disk
//!     corpus via the public [`load_detectors`] loader (one per tier),
//!   * every severity string's parse via the in-memory `load_detectors_from_str`
//!     testing facade (`high|medium|low|critical|info|client-safe`, plus the
//!     `client_safe` underscore alias),
//!   * the fail-closed negatives: a missing `severity` field and an unknown
//!     label are rejected, never silently defaulted,
//!   * the `Severity` enum's own default, `Display` text, `Ord`, and the public
//!     `downgrade_one` step.

use std::path::PathBuf;

use keyhog_core::testing::{CoreTestApi, TestApi};
use keyhog_core::{load_detectors, DetectorSpec, Severity, SpecError};

// ─── helpers ────────────────────────────────────────────────────────────────

/// Repo-root `detectors/` directory. `CARGO_MANIFEST_DIR` = `crates/core`;
/// pop twice to reach the workspace root, then descend into `detectors`.
fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

/// Load the full shipped corpus and return the detector with `id`.
fn shipped(id: &str) -> DetectorSpec {
    let detectors =
        load_detectors(&detector_dir()).expect("shipped detector corpus must load fail-closed");
    detectors
        .into_iter()
        .find(|d| d.id == id)
        .unwrap_or_else(|| panic!("shipped corpus must contain detector id `{id}`"))
}

/// Parse a single detector from an in-memory TOML string via the public
/// testing facade (no directory / no quality gate).
fn from_str(toml_str: &str) -> Result<Vec<DetectorSpec>, SpecError> {
    CoreTestApi::load_detectors_from_str(&TestApi, toml_str)
}

/// Build a minimal single-detector TOML whose only variable is the `severity`
/// literal. Every serde-required field (id/name/service/severity/patterns) is
/// present so the ONLY thing under test is the severity map.
fn detector_toml_with_severity(sev_literal: &str) -> String {
    format!(
        r#"
[detector]
id = "sev-probe"
name = "Severity Probe"
service = "probe"
severity = "{sev_literal}"
ml = {{ match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }}
keywords = ["probe_"]

[[detector.patterns]]
regex = "probe_[A-Z0-9]{{8}}"
"#
    )
}

/// Parse one detector from the severity-only fixture and return its severity.
fn parse_severity(sev_literal: &str) -> Severity {
    let toml = detector_toml_with_severity(sev_literal);
    let specs = from_str(&toml)
        .unwrap_or_else(|e| panic!("severity literal {sev_literal:?} must parse; got error: {e}"));
    assert_eq!(specs.len(), 1, "fixture declares exactly one detector");
    specs[0].severity
}

// ─── shipped on-disk TOML severities (one per tier) ──────────────────────────

/// `aws-access-key.toml` declares `severity = "critical"`: the highest tier.
#[test]
fn shipped_aws_access_key_severity_is_critical() {
    assert_eq!(shipped("aws-access-key").severity, Severity::Critical);
}

/// `abuseipdb-api-key.toml` declares `severity = "medium"`.
#[test]
fn shipped_abuseipdb_api_key_severity_is_medium() {
    assert_eq!(shipped("abuseipdb-api-key").severity, Severity::Medium);
}

/// `heap-analytics-key.toml` declares `severity = "low"`.
#[test]
fn shipped_heap_analytics_key_severity_is_low() {
    assert_eq!(shipped("heap-analytics-key").severity, Severity::Low);
}

// ─── every severity string parses to its exact enum tier ─────────────────────

#[test]
fn parse_critical_severity_string() {
    assert_eq!(parse_severity("critical"), Severity::Critical);
}

#[test]
fn parse_high_severity_string() {
    assert_eq!(parse_severity("high"), Severity::High);
}

#[test]
fn parse_medium_severity_string() {
    assert_eq!(parse_severity("medium"), Severity::Medium);
}

#[test]
fn parse_low_severity_string() {
    assert_eq!(parse_severity("low"), Severity::Low);
}

#[test]
fn parse_info_severity_string() {
    assert_eq!(parse_severity("info"), Severity::Info);
}

/// The canonical kebab-case spelling of the bug-bounty tier.
#[test]
fn parse_client_safe_kebab_severity_string() {
    assert_eq!(parse_severity("client-safe"), Severity::ClientSafe);
}

/// Adversarial: the `#[serde(alias = "client_safe")]` underscore spelling maps
/// to the SAME `ClientSafe` tier as the kebab-case form, the two are not two
/// different values (ONE-PLACE law).
#[test]
fn parse_client_safe_underscore_alias_equals_kebab() {
    assert_eq!(parse_severity("client_safe"), Severity::ClientSafe);
    assert_eq!(parse_severity("client_safe"), parse_severity("client-safe"));
}

// ─── fail-closed negatives ───────────────────────────────────────────────────

/// Negative twin: `severity` has NO `#[serde(default)]`, so a detector that
/// omits it is a hard parse error (`SpecError::InvalidToml`), never a silent
/// downgrade to the enum default `Info`. If it silently defaulted, a
/// severity-less detector would sneak under `--min-severity high`.
#[test]
fn missing_severity_field_is_rejected_not_defaulted() {
    let toml = r#"
[detector]
id = "no-sev"
name = "No Severity"
service = "probe"
keywords = ["probe_"]

[[detector.patterns]]
regex = "probe_[A-Z0-9]{8}"
"#;
    let err = from_str(toml).expect_err("missing severity must fail to parse, not default");
    assert!(
        matches!(err, SpecError::InvalidToml { .. }),
        "missing severity must surface as InvalidToml; got {err:?}"
    );
    let rendered = err.to_string();
    assert!(
        rendered.contains("severity"),
        "error should name the missing `severity` field; got: {rendered}"
    );
}

/// Adversarial: an unknown severity label (`"urgent"`) is not silently coerced
/// to any tier (it is rejected as `InvalidToml`).
#[test]
fn unknown_severity_label_is_rejected() {
    let toml = detector_toml_with_severity("urgent");
    let err = from_str(&toml).expect_err("unknown severity label must be rejected");
    assert!(
        matches!(err, SpecError::InvalidToml { .. }),
        "unknown severity label must surface as InvalidToml; got {err:?}"
    );
}

/// Adversarial: severity is case-sensitive kebab-case. `"Critical"` (capital
/// C, the Rust `Debug` spelling) is NOT a valid wire label and is rejected,
/// proving reporters must not round-trip through `format!("{:?}")`.
#[test]
fn capitalized_debug_style_severity_is_rejected() {
    let toml = detector_toml_with_severity("Critical");
    let err = from_str(&toml).expect_err("capitalized `Critical` is not a valid wire label");
    assert!(
        matches!(err, SpecError::InvalidToml { .. }),
        "capitalized label must surface as InvalidToml; got {err:?}"
    );
}

// ─── enum invariants backing the map ─────────────────────────────────────────

/// The enum default is `Info` (the `#[default]` variant). This is the value a
/// caller gets from `Severity::default()`, distinct from, and never a
/// substitute for (an explicitly-declared TOML severity).
#[test]
fn severity_enum_default_is_info() {
    assert_eq!(Severity::default(), Severity::Info);
}

/// `Display` renders each tier as its canonical kebab-case wire form, the same
/// strings the TOML uses to declare them, so parse and render are inverses.
#[test]
fn severity_display_matches_wire_labels() {
    assert_eq!(Severity::Info.to_string(), "info");
    assert_eq!(Severity::ClientSafe.to_string(), "client-safe");
    assert_eq!(Severity::Low.to_string(), "low");
    assert_eq!(Severity::Medium.to_string(), "medium");
    assert_eq!(Severity::High.to_string(), "high");
    assert_eq!(Severity::Critical.to_string(), "critical");
}

/// The derived `Ord` ranks tiers Info < ClientSafe < Low < Medium < High <
/// Critical, the ordering `--min-severity` relies on. A leaked AWS key
/// (`Critical`) must sort strictly above an `info` finding.
#[test]
fn severity_ordering_is_info_to_critical() {
    assert!(Severity::Info < Severity::ClientSafe);
    assert!(Severity::ClientSafe < Severity::Low);
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
    assert!(shipped("aws-access-key").severity > Severity::Info);
}

/// `downgrade_one` steps exactly one tier down, and `Info` is the floor (it
/// does not wrap or go negative). Used by diff-aware scoring for non-HEAD leaks.
#[test]
fn downgrade_one_steps_down_and_floors_at_info() {
    assert_eq!(Severity::Critical.downgrade_one(), Severity::High);
    assert_eq!(Severity::High.downgrade_one(), Severity::Medium);
    assert_eq!(Severity::Medium.downgrade_one(), Severity::Low);
    assert_eq!(Severity::Low.downgrade_one(), Severity::ClientSafe);
    assert_eq!(Severity::ClientSafe.downgrade_one(), Severity::Info);
    assert_eq!(Severity::Info.downgrade_one(), Severity::Info);
}
