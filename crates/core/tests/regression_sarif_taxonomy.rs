//! Regression: SARIF `tool.driver` metadata and per-detector `rules[]`
//! description/help/properties emission.
//!
//! DISTINCT from `regression_sarif_schema.rs` (outer envelope + result shape)
//! and `regression_sarif_taxonomies_autofix.rs` (CWE/OWASP taxa + per-result
//! `fixes[]`/`properties` cross-reference). This file pins the *rule object*
//! metadata a code-scanning platform renders in its rule catalog:
//!
//!   * `tool.driver.{name,version,informationUri}`: the driver identity, with
//!     version/informationUri sourced from the crate manifest (never hardcoded).
//!   * `rules[i].{shortDescription,fullDescription,help.text,help.markdown}`
//!     the composed human-facing rule copy.
//!   * `rules[i].helpUri`: prefers the detector `revoke_url`, falls back to
//!     `docs_url`, and is ABSENT when the remediation has neither.
//!   * `rules[i].properties.{service,severity,security-severity,tags}`: the
//!     GitHub code-scanning rule properties, exact per severity.
//!   * rule DEDUP: one rule per unique detector id even across N findings, while
//!     results stay 1:1 with findings.
//!
//! Every assertion pins a concrete value read from the actual source
//! (`report/sarif.rs::build_rule`, `report/sarif_uri.rs::
//! code_scanning_security_severity`) and Tier-B data (`data/remediation.toml`).
//! The whole file drives the real operator path: `write_report` with
//! `ReportFormat::Sarif`, then `serde_json` value assertions.

use keyhog_core::{
    write_report, MatchLocation, ReportFormat, Severity, VerificationResult, VerifiedFinding,
};
use std::borrow::Cow;
use std::collections::HashMap;

// ---- Concrete expected values (mirrored from source + Tier-B data) -----------

// aws-access-key remediation, verbatim from data/remediation.toml (detector row).
const AWS_ACTION: &str =
    "Disable or delete the exposed IAM access key, then rotate any paired secret access key and session token.";
const AWS_REVOKE_URL: &str =
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_ManagingAccessKeys";
const AWS_REVOKE_COMMAND: &str =
    "aws iam update-access-key --access-key-id {{credential}} --status Inactive";

// slack-app-token remediation: has docs_url, NO revoke_url, NO revoke_command.
const SLACK_APP_ACTION: &str =
    "Rotate the Slack app-level token from the app configuration and review socket-mode or workflow integrations using it.";
const SLACK_APP_DOCS_URL: &str = "https://api.slack.com/authentication/token-types#app";

// ---- Finding builders --------------------------------------------------------

fn finding_with(
    detector_id: &'static str,
    detector_name: &'static str,
    service: &'static str,
    severity: Severity,
    file_path: Option<&'static str>,
    line: Option<usize>,
) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: detector_id.into(),
        detector_name: detector_name.into(),
        service: service.into(),
        severity,
        credential_redacted: Cow::Borrowed("REDAC****"),
        credential_hash: [0u8; 32].into(),
        companions_redacted: std::collections::HashMap::new(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: file_path.map(Into::into),
            line,
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: vec![],
        confidence: Some(0.9),
    }
}

fn aws_finding() -> VerifiedFinding {
    finding_with(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        Some("config.env"),
        Some(12),
    )
}

fn render_sarif(findings: &[VerifiedFinding]) -> serde_json::Value {
    let mut buf = Vec::new();
    write_report(
        &mut buf,
        ReportFormat::Sarif {
            skip_summary: Vec::new(),
        },
        findings,
    )
    .expect("finish SARIF document");
    serde_json::from_slice(&buf).expect("SARIF output must parse as JSON")
}

fn driver(json: &serde_json::Value) -> &serde_json::Value {
    &json["runs"][0]["tool"]["driver"]
}

fn driver_rules(json: &serde_json::Value) -> Vec<serde_json::Value> {
    json["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("runs[0].tool.driver.rules must be a JSON array")
        .clone()
}

// ---- tool.driver identity ----------------------------------------------------

/// `tool.driver` carries name `"keyhog"`, the crate's own version, and the
/// crate manifest `repository` URL as `informationUri`: never a hardcoded org.
#[test]
fn driver_name_version_information_uri_are_manifest_sourced() {
    let json = render_sarif(&[aws_finding()]);
    let d = driver(&json);
    assert_eq!(d["name"].as_str(), Some("keyhog"), "driver name is keyhog");
    // version tracks the crate manifest, not the SARIF spec "2.1.0".
    assert_eq!(
        d["version"].as_str(),
        Some(env!("CARGO_PKG_VERSION")),
        "driver.version must be the crate version from the manifest"
    );
    assert_eq!(
        d["informationUri"].as_str(),
        Some(env!("CARGO_PKG_REPOSITORY")),
        "informationUri must be the manifest repository, never a hardcoded org"
    );
    // Concrete guard: the repository is the santhreal canonical, and NOT the
    // wrong `github.com/keyhog/keyhog` that a prior shape hardcoded.
    assert_eq!(
        d["informationUri"].as_str(),
        Some("https://github.com/santhreal/keyhog")
    );
    assert_ne!(
        d["informationUri"].as_str(),
        Some("https://github.com/keyhog/keyhog"),
        "must not regress to the old wrong org URL"
    );
}

/// An empty run (no findings) still emits a driver with name/version/
/// informationUri and an EMPTY rules array (the rule catalog is honestly empty).
#[test]
fn empty_run_driver_present_with_zero_rules() {
    let json = render_sarif(&[]);
    let d = driver(&json);
    assert_eq!(d["name"].as_str(), Some("keyhog"));
    assert_eq!(d["version"].as_str(), Some(env!("CARGO_PKG_VERSION")));
    assert_eq!(
        d["informationUri"].as_str(),
        Some(env!("CARGO_PKG_REPOSITORY"))
    );
    let rules = driver_rules(&json);
    assert_eq!(rules.len(), 0, "no findings -> zero rules");
}

// ---- rule descriptions -------------------------------------------------------

/// `rules[0].shortDescription.text` is exactly `"<service> secret detected"`.
#[test]
fn rule_short_description_text_is_service_secret_detected() {
    let json = render_sarif(&[aws_finding()]);
    let rules = driver_rules(&json);
    assert_eq!(
        rules[0]["shortDescription"]["text"].as_str(),
        Some("aws secret detected"),
        "shortDescription is '<service> secret detected'"
    );
}

/// `rules[0].fullDescription.text` composes service AND detector name exactly.
#[test]
fn rule_full_description_text_names_service_and_detector() {
    let json = render_sarif(&[aws_finding()]);
    let rules = driver_rules(&json);
    assert_eq!(
        rules[0]["fullDescription"]["text"].as_str(),
        Some("A aws secret was detected by the AWS Access Key detector"),
        "fullDescription composes '<service>' and '<detector_name>'"
    );
}

/// `rules[0].help.text` is the detector's remediation action verbatim.
#[test]
fn rule_help_text_is_detector_remediation_action() {
    let json = render_sarif(&[aws_finding()]);
    let rules = driver_rules(&json);
    assert_eq!(
        rules[0]["help"]["text"].as_str(),
        Some(AWS_ACTION),
        "help.text is the Tier-B remediation action, verbatim"
    );
}

/// `rules[0].help.markdown` composes action + fenced revoke command + a
/// "Reference:" line pointing at the revoke_url (the exact multi-part string).
#[test]
fn rule_help_markdown_composes_action_command_and_reference() {
    let json = render_sarif(&[aws_finding()]);
    let rules = driver_rules(&json);
    let expected = format!(
        "{AWS_ACTION}\n\nRevoke command:\n\n```sh\n{AWS_REVOKE_COMMAND}\n```\n\nReference: {AWS_REVOKE_URL}"
    );
    assert_eq!(
        rules[0]["help"]["markdown"].as_str(),
        Some(expected.as_str()),
        "help.markdown must compose action, fenced sh command, and the revoke_url reference"
    );
}

/// Negative twin for markdown: a detector WITHOUT a revoke_command emits NO
/// fenced code block, and the "Reference:" line falls back to docs_url.
#[test]
fn rule_help_markdown_omits_command_block_and_uses_docs_reference() {
    let f = finding_with(
        "slack-app-token",
        "Slack App Token",
        "slack",
        Severity::High,
        Some("app.env"),
        Some(4),
    );
    let json = render_sarif(&[f]);
    let rules = driver_rules(&json);
    let expected = format!("{SLACK_APP_ACTION}\n\nReference: {SLACK_APP_DOCS_URL}");
    assert_eq!(
        rules[0]["help"]["markdown"].as_str(),
        Some(expected.as_str()),
        "no revoke_command -> no ```sh block; reference falls back to docs_url"
    );
    assert!(
        !rules[0]["help"]["markdown"]
            .as_str()
            .unwrap()
            .contains("```sh"),
        "markdown must not contain a shell fence when there is no revoke command"
    );
}

// ---- rule helpUri (revoke_url -> docs_url -> absent) -------------------------

/// `rules[0].helpUri` prefers the detector `revoke_url` when present.
#[test]
fn rule_help_uri_prefers_revoke_url() {
    let json = render_sarif(&[aws_finding()]);
    let rules = driver_rules(&json);
    assert_eq!(
        rules[0]["helpUri"].as_str(),
        Some(AWS_REVOKE_URL),
        "helpUri prefers revoke_url"
    );
}

/// `rules[0].helpUri` falls back to `docs_url` when the remediation has no
/// `revoke_url` (slack-app-token has docs_url only).
#[test]
fn rule_help_uri_falls_back_to_docs_url() {
    let f = finding_with(
        "slack-app-token",
        "Slack App Token",
        "slack",
        Severity::High,
        Some("app.env"),
        Some(4),
    );
    let json = render_sarif(&[f]);
    let rules = driver_rules(&json);
    assert_eq!(
        rules[0]["helpUri"].as_str(),
        Some(SLACK_APP_DOCS_URL),
        "no revoke_url -> helpUri falls back to docs_url"
    );
}

/// `rules[0].helpUri` is ABSENT (key omitted) when the remediation resolves via
/// the severity fallback, which carries neither revoke_url nor docs_url.
#[test]
fn rule_help_uri_absent_for_severity_fallback_remediation() {
    let f = finding_with(
        "unmapped-detector-xyz",
        "Unmapped Detector",
        "totally-unknown-service",
        Severity::Medium,
        Some("f.txt"),
        Some(2),
    );
    let json = render_sarif(&[f]);
    let rules = driver_rules(&json);
    assert!(
        rules[0].get("helpUri").is_none(),
        "severity-fallback remediation has no URL; helpUri must be omitted, got {:?}",
        rules[0].get("helpUri")
    );
}

// ---- rule.properties (service / severity / security-severity / tags) --------

/// `rules[0].properties` carries service, kebab severity, the GitHub
/// code-scanning `security-severity` score, and the single `security` tag
/// exact values for a High aws finding.
#[test]
fn rule_properties_service_severity_security_severity_and_tags() {
    let json = render_sarif(&[aws_finding()]);
    let rules = driver_rules(&json);
    let props = &rules[0]["properties"];
    assert_eq!(props["service"].as_str(), Some("aws"));
    assert_eq!(
        props["severity"].as_str(),
        Some("high"),
        "severity is the lowercase kebab form"
    );
    assert_eq!(
        props["security-severity"].as_str(),
        Some("8.0"),
        "High maps to code-scanning security-severity 8.0"
    );
    let tags = props["tags"].as_array().expect("tags must be an array");
    assert_eq!(tags.len(), 1, "exactly one tag");
    assert_eq!(tags[0].as_str(), Some("security"));
}

/// `security-severity` score is exact across ALL six severities, and `severity`
/// uses the kebab `client-safe` form (adversarial: NOT `clientsafe`).
#[test]
fn rule_security_severity_score_exact_per_severity() {
    let cases = [
        (Severity::Critical, "critical", "9.5"),
        (Severity::High, "high", "8.0"),
        (Severity::Medium, "medium", "5.0"),
        (Severity::Low, "low", "2.0"),
        (Severity::ClientSafe, "client-safe", "1.0"),
        (Severity::Info, "info", "0.0"),
    ];
    for (sev, sev_str, score) in cases {
        let f = finding_with(
            "aws-access-key",
            "AWS Access Key",
            "aws",
            sev,
            Some("a.env"),
            Some(1),
        );
        let json = render_sarif(&[f]);
        let rules = driver_rules(&json);
        let props = &rules[0]["properties"];
        assert_eq!(
            props["severity"].as_str(),
            Some(sev_str),
            "severity {sev:?} must render as {sev_str:?}"
        );
        assert_eq!(
            props["security-severity"].as_str(),
            Some(score),
            "severity {sev:?} must map to security-severity {score:?}"
        );
    }
}

// ---- rule dedup / identity ---------------------------------------------------

/// N findings of the SAME detector produce exactly ONE rule (deduped by id) but
/// N results (rule accumulation is independent of result count).
#[test]
fn rules_dedupe_one_per_detector_across_n_findings() {
    let json = render_sarif(&[
        finding_with(
            "aws-access-key",
            "AWS Access Key",
            "aws",
            Severity::High,
            Some("a.env"),
            Some(1),
        ),
        finding_with(
            "aws-access-key",
            "AWS Access Key",
            "aws",
            Severity::High,
            Some("b.env"),
            Some(2),
        ),
        finding_with(
            "aws-access-key",
            "AWS Access Key",
            "aws",
            Severity::High,
            Some("c.env"),
            Some(3),
        ),
    ]);
    let rules = driver_rules(&json);
    assert_eq!(rules.len(), 1, "3 findings, 1 detector -> exactly 1 rule");
    assert_eq!(rules[0]["id"].as_str(), Some("aws-access-key"));
    let results = json["runs"][0]["results"]
        .as_array()
        .expect("results array");
    assert_eq!(results.len(), 3, "but results stay 1:1 with findings");
}

/// Three distinct detectors produce three rules sorted ascending by id, each
/// pairing the exact (id, name) (no cross-contamination of names between rules).
#[test]
fn rules_sorted_by_id_with_correct_id_name_pairs() {
    let json = render_sarif(&[
        finding_with(
            "stripe-secret-key",
            "Stripe Secret Key",
            "stripe",
            Severity::High,
            Some("a.rb"),
            Some(1),
        ),
        finding_with(
            "github-classic-pat",
            "GitHub Classic PAT",
            "github",
            Severity::High,
            Some("b.txt"),
            Some(2),
        ),
        finding_with(
            "aws-access-key",
            "AWS Access Key",
            "aws",
            Severity::High,
            Some("c.env"),
            Some(3),
        ),
    ]);
    let rules = driver_rules(&json);
    let pairs: Vec<(&str, &str)> = rules
        .iter()
        .map(|r| {
            (
                r["id"].as_str().expect("rule id"),
                r["name"].as_str().expect("rule name"),
            )
        })
        .collect();
    assert_eq!(
        pairs,
        vec![
            ("aws-access-key", "AWS Access Key"),
            ("github-classic-pat", "GitHub Classic PAT"),
            ("stripe-secret-key", "Stripe Secret Key"),
        ],
        "rules sorted ascending by id, each with its own exact name"
    );
}
