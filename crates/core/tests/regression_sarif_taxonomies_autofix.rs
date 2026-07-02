//! Regression: SARIF taxonomy block (CWE + OWASP), per-result taxonomy
//! cross-reference properties, the auto-fix `fixes[]` suggestion, and the
//! `tool.driver.rules[]` array must all carry the EXACT values a consuming
//! dashboard (GitHub Code Scanning, SonarQube, Splunk) relies on.
//!
//! Every assertion here is a concrete expected value drawn from the actual
//! source and Tier-B data:
//!   * `crates/core/src/report/sarif_taxonomies.rs` — the taxonomy JSON.
//!   * `crates/core/src/report/sarif.rs`            — result properties + fixes.
//!   * `crates/core/src/auto_fix.rs`                — env-var derivation.
//!   * `crates/core/data/service-env-vars.toml`     — curated env-var map.
//!   * `crates/core/data/remediation.toml`          — remediation advice.
//!
//! The whole file drives the real operator path: `write_report` with
//! `ReportFormat::Sarif`, then `serde_json` value assertions on the emitted
//! document. No production visibility is weakened.

use keyhog_core::{
    write_report, MatchLocation, ReportFormat, Severity, VerificationResult, VerifiedFinding,
};
use std::borrow::Cow;
use std::collections::HashMap;

// ---- Concrete expected values (single source of truth mirrored from code+data)

const CWE_ID: &str = "CWE-798";
const CWE_NAME: &str = "Use of Hard-coded Credentials";
const CWE_VERSION: &str = "4.13";
const CWE_HELP_URI: &str = "https://cwe.mitre.org/data/definitions/798.html";

const OWASP_ID: &str = "A07:2021";
const OWASP_NAME: &str = "Identification and Authentication Failures";
const OWASP_VERSION: &str = "2021";

// aws-access-key detector remediation, verbatim from data/remediation.toml.
const AWS_DETECTOR_ACTION: &str =
    "Disable or delete the exposed IAM access key, then rotate any paired secret access key and session token.";
const AWS_DETECTOR_REVOKE_URL: &str =
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_ManagingAccessKeys";
const AWS_DETECTOR_DOCS_URL: &str =
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html";
const AWS_DETECTOR_REVOKE_COMMAND: &str =
    "aws iam update-access-key --access-key-id {{credential}} --status Inactive";

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

fn taxonomies(json: &serde_json::Value) -> &Vec<serde_json::Value> {
    json["runs"][0]["taxonomies"]
        .as_array()
        .expect("runs[0].taxonomies must be a JSON array")
}

fn first_result(json: &serde_json::Value) -> &serde_json::Value {
    &json["runs"][0]["results"][0]
}

fn driver_rules(json: &serde_json::Value) -> &Vec<serde_json::Value> {
    json["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("runs[0].tool.driver.rules must be a JSON array")
}

// ---- Taxonomy block ----------------------------------------------------------

/// The taxonomies block has EXACTLY two entries: CWE then OWASP, in that order.
#[test]
fn taxonomies_block_has_cwe_then_owasp() {
    let json = render_sarif(&[aws_finding()]);
    let tax = taxonomies(&json);
    assert_eq!(
        tax.len(),
        2,
        "expected exactly CWE + OWASP taxonomy entries"
    );
    assert_eq!(tax[0]["name"].as_str(), Some("CWE"));
    assert_eq!(tax[1]["name"].as_str(), Some("OWASP"));
}

/// The CWE taxon carries the exact id, name, version, and helpUri for
/// CWE-798 "Use of Hard-coded Credentials".
#[test]
fn cwe_taxon_has_exact_798_metadata() {
    let json = render_sarif(&[aws_finding()]);
    let cwe = &taxonomies(&json)[0];
    assert_eq!(cwe["version"].as_str(), Some(CWE_VERSION));
    assert_eq!(
        cwe["informationUri"].as_str(),
        Some(CWE_HELP_URI),
        "CWE taxonomy informationUri must point at the 798 definition"
    );
    let taxa = cwe["taxa"].as_array().expect("CWE taxa is an array");
    assert_eq!(taxa.len(), 1, "exactly one CWE taxon");
    assert_eq!(taxa[0]["id"].as_str(), Some(CWE_ID));
    assert_eq!(taxa[0]["name"].as_str(), Some(CWE_NAME));
    assert_eq!(taxa[0]["helpUri"].as_str(), Some(CWE_HELP_URI));
}

/// The OWASP taxon carries the exact id, name, and version for A07:2021.
#[test]
fn owasp_taxon_has_exact_a07_metadata() {
    let json = render_sarif(&[aws_finding()]);
    let owasp = &taxonomies(&json)[1];
    assert_eq!(owasp["version"].as_str(), Some(OWASP_VERSION));
    let taxa = owasp["taxa"].as_array().expect("OWASP taxa is an array");
    assert_eq!(taxa.len(), 1, "exactly one OWASP taxon");
    assert_eq!(taxa[0]["id"].as_str(), Some(OWASP_ID));
    assert_eq!(taxa[0]["name"].as_str(), Some(OWASP_NAME));
    assert_eq!(
        owasp["informationUri"].as_str(),
        Some("https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/")
    );
}

/// Boundary: an empty run (no findings, only `finish()`) still emits the
/// taxonomies block with both taxa — a consumer of a "clean" run must still be
/// able to resolve the taxonomy references the schema promises.
#[test]
fn taxonomies_present_on_empty_run() {
    let json = render_sarif(&[]);
    let tax = taxonomies(&json);
    assert_eq!(tax.len(), 2);
    assert_eq!(tax[0]["taxa"][0]["id"].as_str(), Some(CWE_ID));
    assert_eq!(tax[1]["taxa"][0]["id"].as_str(), Some(OWASP_ID));
}

// ---- Per-result taxonomy cross-reference -------------------------------------

/// Each result's `properties.cwe` / `properties.owasp` carry the SAME ids the
/// taxonomy block defines, so the dashboard cross-reference resolves.
#[test]
fn result_properties_carry_matching_taxonomy_ids() {
    let json = render_sarif(&[aws_finding()]);
    let props = &first_result(&json)["properties"];
    assert_eq!(props["cwe"].as_str(), Some(CWE_ID));
    assert_eq!(props["owasp"].as_str(), Some(OWASP_ID));
    // And they must equal what the taxonomy block declares.
    let tax = taxonomies(&json);
    assert_eq!(props["cwe"].as_str(), tax[0]["taxa"][0]["id"].as_str());
    assert_eq!(props["owasp"].as_str(), tax[1]["taxa"][0]["id"].as_str());
}

// ---- Auto-fix `fixes[]` ------------------------------------------------------

/// The auto-fix inserts the exact curated `${AWS_ACCESS_KEY_ID}` replacement
/// (from data/service-env-vars.toml), not the screaming-snake fallback, and the
/// fix targets the finding's physical line.
#[test]
fn autofix_inserts_exact_curated_env_var_for_aws() {
    let json = render_sarif(&[aws_finding()]);
    let fixes = first_result(&json)["fixes"]
        .as_array()
        .expect("aws finding with file+line must produce a fixes[] entry");
    assert_eq!(fixes.len(), 1, "exactly one fix suggestion");
    let change = &fixes[0]["artifactChanges"][0];
    let replacement = &change["replacements"][0];
    assert_eq!(
        replacement["insertedContent"]["text"].as_str(),
        Some("${AWS_ACCESS_KEY_ID}"),
        "curated aws env var must win over the ACME-style fallback"
    );
    assert_eq!(
        replacement["deletedRegion"]["startLine"].as_u64(),
        Some(12),
        "the fix must delete the region at the finding's line"
    );
}

/// The fix description is the exact human-readable sentence, referencing both
/// the `${VAR}` replacement and the bare env-var name.
#[test]
fn autofix_description_is_exact_sentence() {
    let json = render_sarif(&[aws_finding()]);
    let fixes = first_result(&json)["fixes"].as_array().unwrap();
    assert_eq!(
        fixes[0]["description"]["text"].as_str(),
        Some(
            "Replace the leaked credential with `${AWS_ACCESS_KEY_ID}` \
             and load `AWS_ACCESS_KEY_ID` from your secret manager."
        )
    );
}

/// Negative twin for the env-var map: a service that IS in the curated map
/// (`openai`) must emit the community name `OPENAI_API_KEY`, proving the map is
/// consulted — the screaming-snake fallback would wrongly produce `OPENAI_KEY`.
#[test]
fn autofix_curated_openai_beats_screaming_snake_fallback() {
    let f = finding_with(
        "openai-api-key",
        "OpenAI API Key",
        "openai",
        Severity::High,
        Some("app.py"),
        Some(3),
    );
    let json = render_sarif(&[f]);
    let text = first_result(&json)["fixes"][0]["artifactChanges"][0]["replacements"][0]
        ["insertedContent"]["text"]
        .as_str()
        .expect("inserted content text");
    assert_eq!(text, "${OPENAI_API_KEY}");
    assert_ne!(
        text, "${OPENAI_KEY}",
        "must use the curated name, not the raw <SERVICE>_KEY derivation"
    );
}

/// Fallback path: a service NOT in the curated map derives the deterministic
/// `<SCREAMING_SNAKE>_KEY` name — `acme-widgets` -> `${ACME_WIDGETS_KEY}`.
#[test]
fn autofix_uncurated_service_uses_screaming_snake_key() {
    let f = finding_with(
        "custom-token",
        "Custom Token",
        "acme-widgets",
        Severity::Medium,
        Some("secrets.yml"),
        Some(7),
    );
    let json = render_sarif(&[f]);
    let text = first_result(&json)["fixes"][0]["artifactChanges"][0]["replacements"][0]
        ["insertedContent"]["text"]
        .as_str()
        .expect("inserted content text");
    assert_eq!(text, "${ACME_WIDGETS_KEY}");
}

/// Adversarial: substring, case-insensitive service matching still resolves to
/// the curated aws var. `Prod-AWS-Signer` contains `aws` (any case).
#[test]
fn autofix_substring_case_insensitive_service_match() {
    let f = finding_with(
        "custom-aws",
        "Custom AWS",
        "Prod-AWS-Signer",
        Severity::High,
        Some("main.tf"),
        Some(1),
    );
    let json = render_sarif(&[f]);
    let text = first_result(&json)["fixes"][0]["artifactChanges"][0]["replacements"][0]
        ["insertedContent"]["text"]
        .as_str()
        .expect("inserted content text");
    assert_eq!(text, "${AWS_ACCESS_KEY_ID}");
}

/// Boundary/negative: a path-less finding (stdin, no file_path) gets NO fix,
/// because there is no artifact to rewrite. The `fixes` key must be absent.
#[test]
fn autofix_absent_when_no_file_path() {
    let f = finding_with(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        None,
        Some(12),
    );
    let json = render_sarif(&[f]);
    let result = first_result(&json);
    assert!(
        result.get("fixes").is_none(),
        "path-less finding must not carry a fixes[] block, got {:?}",
        result.get("fixes")
    );
    // sanity: it still emitted a result, located at stdin.
    assert_eq!(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].as_str(),
        Some("stdin")
    );
}

// ---- Remediation properties (auto_fix::remediation_for) ----------------------

/// The detector-specific remediation for `aws-access-key` is surfaced verbatim
/// in `result.properties`, including the revoke command.
#[test]
fn result_properties_carry_exact_detector_remediation() {
    let json = render_sarif(&[aws_finding()]);
    let props = &first_result(&json)["properties"];
    assert_eq!(
        props["remediation.action"].as_str(),
        Some(AWS_DETECTOR_ACTION)
    );
    assert_eq!(
        props["remediation.revoke_url"].as_str(),
        Some(AWS_DETECTOR_REVOKE_URL)
    );
    assert_eq!(
        props["remediation.docs_url"].as_str(),
        Some(AWS_DETECTOR_DOCS_URL)
    );
    assert_eq!(
        props["remediation.revoke_command"].as_str(),
        Some(AWS_DETECTOR_REVOKE_COMMAND)
    );
}

/// Severity fallback: a finding whose detector id and service match no
/// remediation entry falls back to the `[[severity]]` row. A `medium`
/// finding gets the exact medium action and NO revoke url/command keys.
#[test]
fn result_properties_fall_back_to_severity_remediation() {
    let f = finding_with(
        "unmapped-detector-xyz",
        "Unmapped Detector",
        "totally-unknown-service",
        Severity::Medium,
        Some("f.txt"),
        Some(2),
    );
    let json = render_sarif(&[f]);
    let props = &first_result(&json)["properties"];
    assert_eq!(
        props["remediation.action"].as_str(),
        Some("Review usage, rotate if active, and move the secret into managed configuration.")
    );
    assert!(
        props.get("remediation.revoke_url").is_none(),
        "severity fallback has no revoke_url; the key must be omitted"
    );
    assert!(
        props.get("remediation.revoke_command").is_none(),
        "severity fallback has no revoke_command; the key must be omitted"
    );
}

// ---- driver.rules[] ----------------------------------------------------------

/// The driver rules array includes exactly one rule whose id is the detector
/// id, and the help_uri resolves to the detector's revoke_url.
#[test]
fn driver_rules_include_exact_rule_id_and_help_uri() {
    let json = render_sarif(&[aws_finding()]);
    let rules = driver_rules(&json);
    assert_eq!(rules.len(), 1, "one unique detector -> one rule");
    assert_eq!(rules[0]["id"].as_str(), Some("aws-access-key"));
    assert_eq!(rules[0]["name"].as_str(), Some("AWS Access Key"));
    // help_uri prefers revoke_url when present (see build_rule).
    assert_eq!(rules[0]["helpUri"].as_str(), Some(AWS_DETECTOR_REVOKE_URL));
    // And the result's ruleId cross-references that rule.
    assert_eq!(
        first_result(&json)["ruleId"].as_str(),
        Some("aws-access-key")
    );
}

/// Two distinct detectors produce exactly two rules, sorted by id, each with
/// its own concrete id — no dedup collision, no missing rule.
#[test]
fn driver_rules_sorted_and_deduped_across_detectors() {
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
            "aws-access-key",
            "AWS Access Key",
            "aws",
            Severity::High,
            Some("b.env"),
            Some(2),
        ),
        // duplicate detector id: must NOT create a third rule.
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
    let ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
    assert_eq!(
        ids,
        vec!["aws-access-key", "stripe-secret-key"],
        "rules must be exactly the two unique ids, sorted ascending"
    );
}
