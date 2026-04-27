use keyhog_core::{JsonArrayReporter, JsonlReporter, Reporter, SarifReporter, TextReporter};
use keyhog_core::{MatchLocation, Severity, VerificationResult, VerifiedFinding};
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{self, Write};

fn sample_finding() -> VerifiedFinding {
    VerifiedFinding {
        detector_id: "slack-bot-token".into(),
        detector_name: "Slack Bot Token".into(),
        service: "slack".into(),
        severity: Severity::Critical,
        credential_redacted: Cow::Borrowed("xoxb***************"),
        credential_hash: "".into(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some("config.py".into()),
            line: Some(42),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Live,
        metadata: HashMap::from([("team".into(), "acme".into())]),
        additional_locations: vec![],
        confidence: Some(0.85),
    }
}

#[test]
fn text_reporter_output() {
    let mut buf = Vec::new();
    let mut reporter = TextReporter::new(&mut buf);
    reporter.report(&sample_finding()).unwrap();
    reporter.finish().unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.contains("LIVE"));
    assert!(output.contains("Slack Bot Token"));
    assert!(output.contains("config.py:42"));
}

#[test]
fn jsonl_reporter_output() {
    let mut buf = Vec::new();
    let mut reporter = JsonlReporter::new(&mut buf);
    reporter.report(&sample_finding()).unwrap();
    reporter.finish().unwrap();
    let output = String::from_utf8(buf).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
    assert_eq!(parsed["service"], "slack");
}

#[test]
fn sarif_reporter_basic_structure() {
    let mut buf = Vec::new();
    let mut reporter = SarifReporter::new(&mut buf);
    reporter.report(&sample_finding()).unwrap();
    reporter.finish().unwrap();
    let output = String::from_utf8(buf).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    assert_eq!(parsed["version"], "2.1.0");
    assert!(parsed["$schema"]
        .as_str()
        .unwrap()
        .contains("sarif-schema-2.1.0.json"));

    let runs = parsed["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1);

    let tool = &runs[0]["tool"]["driver"];
    assert_eq!(tool["name"], "keyhog");
    assert!(tool["version"].is_string());

    let rules = tool["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["id"], "slack-bot-token");
    assert_eq!(rules[0]["name"], "Slack Bot Token");
    assert!(rules[0]["properties"]["service"].is_string());

    let results = runs[0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["ruleId"], "slack-bot-token");
    assert_eq!(results[0]["level"], "error");
    assert!(results[0]["message"]["text"]
        .as_str()
        .unwrap()
        .contains("slack"));

    let location = &results[0]["locations"][0];
    assert_eq!(
        location["physicalLocation"]["artifactLocation"]["uri"],
        "config.py"
    );
    assert_eq!(location["physicalLocation"]["region"]["startLine"], 42);

    let props = &results[0]["properties"];
    assert_eq!(props["verification"], "live");
    assert_eq!(props["confidence"], 0.85);
    assert_eq!(props["metadata.team"], "acme");
}

#[test]
fn sarif_reporter_severity_mapping() {
    let severities = vec![
        (Severity::Critical, "error"),
        (Severity::High, "error"),
        (Severity::Medium, "warning"),
        (Severity::Low, "note"),
        (Severity::Info, "note"),
    ];

    for (sev, expected_level) in severities {
        let mut finding = sample_finding();
        finding.severity = sev;
        finding.detector_id = format!("test-{}", expected_level).into();

        let mut buf = Vec::new();
        let mut reporter = SarifReporter::new(&mut buf);
        reporter.report(&finding).unwrap();
        reporter.finish().unwrap();

        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert_eq!(
            results[0]["level"], expected_level,
            "severity {:?} should map to level {}",
            sev, expected_level
        );
    }
}

#[test]
fn sarif_reporter_multiple_findings() {
    let mut buf = Vec::new();
    let mut reporter = SarifReporter::new(&mut buf);

    let finding1 = sample_finding();
    let mut finding2 = sample_finding();
    finding2.detector_id = "github-token".into();
    finding2.detector_name = "GitHub Token".into();
    finding2.service = "github".into();
    finding2.location.file_path = Some(".env".into());
    finding2.location.line = Some(10);

    reporter.report(&finding1).unwrap();
    reporter.report(&finding2).unwrap();
    reporter.finish().unwrap();

    let output = String::from_utf8(buf).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    assert_eq!(rules.len(), 2);

    let results = parsed["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
}

#[test]
fn sarif_reporter_deduplicates_rules_for_same_detector() {
    let mut buf = Vec::new();
    let mut reporter = SarifReporter::new(&mut buf);

    let finding1 = sample_finding();
    let mut finding2 = sample_finding();
    finding2.location.line = Some(99);
    finding2.location.file_path = Some("other.py".into());

    reporter.report(&finding1).unwrap();
    reporter.report(&finding2).unwrap();
    reporter.finish().unwrap();

    let output = String::from_utf8(buf).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    assert_eq!(rules.len(), 1);
}

#[test]
fn sarif_reporter_git_location() {
    let mut finding = sample_finding();
    finding.location.commit = Some("abc123".into());
    finding.location.author = Some("developer".into());
    finding.location.date = Some("2026-03-20T12:00:00Z".into());

    let mut buf = Vec::new();
    let mut reporter = SarifReporter::new(&mut buf);
    reporter.report(&finding).unwrap();
    reporter.finish().unwrap();

    let output = String::from_utf8(buf).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    let location = &parsed["runs"][0]["results"][0]["locations"][0];
    let logical_locs = location["logicalLocations"].as_array().unwrap();

    assert_eq!(logical_locs.len(), 3);
    assert_eq!(logical_locs[0]["kind"], "commit");
    assert_eq!(logical_locs[0]["name"], "abc123");
    assert_eq!(logical_locs[1]["kind"], "author");
    assert_eq!(logical_locs[1]["name"], "developer");
    assert_eq!(logical_locs[2]["kind"], "date");
    assert_eq!(logical_locs[2]["name"], "2026-03-20T12:00:00Z");
}

#[test]
fn sarif_reporter_related_locations() {
    let mut finding = sample_finding();
    finding.additional_locations = vec![MatchLocation {
        source: "filesystem".into(),
        file_path: Some("backup.py".into()),
        line: Some(100),
        offset: 0,
        commit: None,
        author: None,
        date: None,
    }];

    let mut buf = Vec::new();
    let mut reporter = SarifReporter::new(&mut buf);
    reporter.report(&finding).unwrap();
    reporter.finish().unwrap();

    let output = String::from_utf8(buf).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    let related = parsed["runs"][0]["results"][0]["relatedLocations"]
        .as_array()
        .unwrap();
    assert_eq!(related.len(), 1);
    assert_eq!(
        related[0]["physicalLocation"]["artifactLocation"]["uri"],
        "backup.py"
    );
    assert_eq!(related[0]["physicalLocation"]["region"]["startLine"], 100);
}

#[derive(Default)]
struct FailingWriter {
    fail_on_write: bool,
    fail_on_flush: bool,
}

impl Write for FailingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.fail_on_write {
            Err(io::Error::other("write failed"))
        } else {
            Ok(buf.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.fail_on_flush {
            Err(io::Error::other("flush failed"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn json_array_reporter_new_propagates_opening_write_errors() {
    let result = JsonArrayReporter::new(FailingWriter {
        fail_on_write: true,
        fail_on_flush: false,
    });
    match result {
        Ok(_) => panic!("expected JsonArrayReporter::new to fail"),
        Err(error) => assert!(error.to_string().contains("write failed")),
    }
}

#[test]
fn jsonl_reporter_finish_flushes_writer() {
    let mut reporter = JsonlReporter::new(FailingWriter {
        fail_on_write: false,
        fail_on_flush: true,
    });
    let error = reporter.finish().unwrap_err();
    assert!(error.to_string().contains("flush failed"));
}
