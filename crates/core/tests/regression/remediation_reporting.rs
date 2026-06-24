use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use keyhog_core::{
    MatchLocation, ReportFormat, Severity, VerificationResult, VerifiedFinding,
    testing::{CoreTestApi, TestApi},
    write_report,
};

const REMEDIATION_DATA: &str = include_str!("../../data/remediation.toml");

#[derive(serde::Deserialize)]
struct RemediationData {
    #[serde(default)]
    detector: Vec<toml::Value>,
    #[serde(default)]
    service: Vec<toml::Value>,
    #[serde(default)]
    severity: Vec<toml::Value>,
}

const ALL_SEVERITY_ROWS: &str = r#"
[[severity]]
severity = "critical"
action = "critical action"

[[severity]]
severity = "high"
action = "high action"

[[severity]]
severity = "medium"
action = "medium action"

[[severity]]
severity = "low"
action = "low action"

[[severity]]
severity = "client-safe"
action = "client-safe action"

[[severity]]
severity = "info"
action = "info action"
"#;

fn parse_remediation_for_test(raw: &str) -> Result<(), String> {
    TestApi.parse_remediation_file_for_test(raw)
}

fn finding(detector_id: &str, name: &str, service: &str, severity: Severity) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from(name),
        service: Arc::from(service),
        severity,
        credential_redacted: Cow::Borrowed("AKIA...7XYA"),
        credential_hash: [7; 32].into(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("src/main.rs")),
            line: Some(12),
            offset: 34,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Live,
        metadata: HashMap::new(),
        additional_locations: Vec::new(),
        confidence: Some(0.99),
    }
}

fn report_json(finding: &VerifiedFinding) -> serde_json::Value {
    let mut out = Vec::new();
    write_report(&mut out, ReportFormat::Json, std::slice::from_ref(finding))
        .expect("json report writes");
    let parsed: serde_json::Value = serde_json::from_slice(&out).expect("json report parses");
    parsed[0].clone()
}

fn report_text(finding: &VerifiedFinding) -> String {
    let mut out = Vec::new();
    write_report(
        &mut out,
        ReportFormat::Text {
            color: false,
            example_suppressions: 0,
            dogfood_active: false,
        },
        std::slice::from_ref(finding),
    )
    .expect("text report writes");
    String::from_utf8(out).expect("text report is utf8")
}

fn report_sarif(finding: &VerifiedFinding) -> serde_json::Value {
    let mut out = Vec::new();
    write_report(
        &mut out,
        ReportFormat::Sarif {
            skip_summary: Vec::new(),
        },
        std::slice::from_ref(finding),
    )
    .expect("sarif report writes");
    serde_json::from_slice(&out).expect("sarif report parses")
}

#[test]
fn remediation_tier_b_data_parses_and_has_live_rows() {
    let parsed: RemediationData =
        toml::from_str(REMEDIATION_DATA).expect("remediation.toml parses");
    parse_remediation_for_test(REMEDIATION_DATA).expect("strict remediation.toml validates");
    assert!(
        parsed.detector.len() >= 8,
        "expected exact detector remediation rows"
    );
    assert!(
        parsed.service.len() >= 8,
        "expected service fallback remediation rows"
    );
    assert_eq!(
        parsed.severity.len(),
        6,
        "every Severity variant needs a data-backed fallback"
    );

    let aws = TestApi.remediation_action_for("aws-access-key", "aws", Severity::Critical);
    let slack = TestApi.remediation_action_for("slack-bot-token", "slack", Severity::Critical);
    assert_ne!(
        aws, slack,
        "AWS and Slack must not share generic action text"
    );
    assert!(aws.contains("IAM access key"), "aws action: {aws}");
    assert!(slack.contains("Slack bot token"), "slack action: {slack}");
    assert!(
        TestApi
            .remediation_docs_for("aws-access-key", "aws", Severity::Critical)
            .as_deref()
            .is_some_and(|url| url.contains("docs.aws.amazon.com")),
        "AWS remediation must carry provider docs"
    );
}

#[test]
fn remediation_parser_rejects_unknown_fields() {
    let raw = format!(
        r#"
[[service]]
match = "aws"
action = "rotate it"
revokee_url = "https://example.com/typo"

{ALL_SEVERITY_ROWS}
"#
    );
    let error = parse_remediation_for_test(&raw).expect_err("unknown field must fail closed");
    assert!(
        error.contains("unknown field")
            && error.contains("revokee_url")
            && error.contains("[[service]]"),
        "unexpected remediation unknown-field error: {error}"
    );
}

#[test]
fn remediation_parser_rejects_unknown_detector_ids() {
    let raw = format!(
        r#"
[[detector]]
id = "not-a-real-detector"
action = "rotate it"

{ALL_SEVERITY_ROWS}
"#
    );
    let error = parse_remediation_for_test(&raw).expect_err("unknown detector must fail closed");
    assert!(
        error.contains("unknown detector id") && error.contains("not-a-real-detector"),
        "unexpected remediation detector-id error: {error}"
    );
}

#[test]
fn remediation_parser_requires_every_severity_fallback() {
    let raw = r#"
[[severity]]
severity = "critical"
action = "critical action"
"#;
    let error = parse_remediation_for_test(raw).expect_err("missing severities must fail closed");
    assert!(
        error.contains("missing [[severity]] fallback") && error.contains("info"),
        "unexpected remediation severity-coverage error: {error}"
    );
}

#[test]
fn remediation_parser_rejects_duplicate_rows() {
    let raw = format!(
        r#"
[[service]]
match = "aws"
action = "rotate it"

[[service]]
match = "aws"
action = "rotate it again"

{ALL_SEVERITY_ROWS}
"#
    );
    let error = parse_remediation_for_test(&raw).expect_err("duplicate service must fail closed");
    assert!(
        error.contains("duplicate match") && error.contains("aws"),
        "unexpected remediation duplicate-row error: {error}"
    );
}

#[test]
fn json_report_carries_provider_specific_remediation() {
    let aws = finding(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::Critical,
    );
    let slack = finding(
        "slack-bot-token",
        "Slack Bot Token",
        "slack",
        Severity::Critical,
    );

    let aws_json = report_json(&aws);
    let slack_json = report_json(&slack);
    assert_eq!(
        aws_json["remediation"]["action"],
        "Disable or delete the exposed IAM access key, then rotate any paired secret access key and session token."
    );
    assert!(
        aws_json["remediation"]["revoke_url"]
            .as_str()
            .is_some_and(|url| url.contains("docs.aws.amazon.com")),
        "aws remediation should include AWS docs: {aws_json}"
    );
    assert_ne!(
        aws_json["remediation"]["action"], slack_json["remediation"]["action"],
        "provider-specific JSON remediation must not collapse to severity text"
    );
}

#[test]
fn text_report_prints_action_command_and_docs_from_remediation_data() {
    let aws = finding(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::Critical,
    );
    let out = report_text(&aws);
    assert!(
        out.contains("Action:") && out.contains("Disable or delete the exposed IAM access key"),
        "text report missing AWS action:\n{out}"
    );
    assert!(
        out.contains("Command:") && out.contains("aws iam update-access-key"),
        "text report missing AWS revoke command:\n{out}"
    );
    assert!(
        out.contains("Docs:") && out.contains("docs.aws.amazon.com"),
        "text report missing AWS docs:\n{out}"
    );
}

#[test]
fn sarif_report_carries_remediation_help_uri_markdown_and_properties() {
    let aws = finding(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::Critical,
    );
    let sarif = report_sarif(&aws);
    let rule = &sarif["runs"][0]["tool"]["driver"]["rules"][0];
    assert_eq!(
        rule["help"]["text"],
        "Disable or delete the exposed IAM access key, then rotate any paired secret access key and session token."
    );
    assert!(
        rule["help"]["markdown"]
            .as_str()
            .is_some_and(|markdown| markdown.contains("aws iam update-access-key")),
        "SARIF rule help.markdown must include revoke command: {rule}"
    );
    assert!(
        rule["helpUri"]
            .as_str()
            .is_some_and(|url| url.contains("docs.aws.amazon.com")),
        "SARIF rule helpUri must point at provider docs: {rule}"
    );

    let props = &sarif["runs"][0]["results"][0]["properties"];
    assert_eq!(
        props["remediation.action"],
        "Disable or delete the exposed IAM access key, then rotate any paired secret access key and session token."
    );
    assert!(
        props["remediation.revoke_command"]
            .as_str()
            .is_some_and(|command| command.contains("aws iam update-access-key")),
        "SARIF result properties must carry revoke command: {props}"
    );
}
