use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use keyhog_core::{
    write_report, MatchLocation, ReportFormat, Severity, VerificationResult, VerifiedFinding,
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

fn finding(detector_id: &str, name: &str, service: &str, severity: Severity) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from(name),
        service: Arc::from(service),
        severity,
        credential_redacted: Cow::Borrowed("AKIA...7XYA"),
        credential_hash: [7; 32],
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

    let aws = keyhog_core::testing::CoreTestApi::remediation_action_for(
        &keyhog_core::testing::TestApi,
        "aws-access-key",
        "aws",
        Severity::Critical,
    );
    let slack = keyhog_core::testing::CoreTestApi::remediation_action_for(
        &keyhog_core::testing::TestApi,
        "slack-bot-token",
        "slack",
        Severity::Critical,
    );
    assert_ne!(
        aws, slack,
        "AWS and Slack must not share generic action text"
    );
    assert!(aws.contains("IAM access key"), "aws action: {aws}");
    assert!(slack.contains("Slack bot token"), "slack action: {slack}");
    assert!(
        keyhog_core::testing::CoreTestApi::remediation_docs_for(
            &keyhog_core::testing::TestApi,
            "aws-access-key",
            "aws",
            Severity::Critical
        )
        .as_deref()
        .is_some_and(|url| url.contains("docs.aws.amazon.com")),
        "AWS remediation must carry provider docs"
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
