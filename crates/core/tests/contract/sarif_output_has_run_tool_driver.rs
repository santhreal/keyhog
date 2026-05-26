//! Contract: SARIF output exposes `runs[0].tool.driver.name` with the exact tool id.

use keyhog_core::{
    MatchLocation, Reporter, SarifReporter, Severity, VerificationResult, VerifiedFinding,
};
use std::borrow::Cow;
use std::collections::HashMap;

const TOOL_DRIVER_NAME: &str = "keyhog";

fn sample_finding() -> VerifiedFinding {
    VerifiedFinding {
        detector_id: "oracle-detector".into(),
        detector_name: "Oracle Detector".into(),
        service: "oracle".into(),
        severity: Severity::High,
        credential_redacted: Cow::Borrowed("****"),
        credential_hash: "deadbeef".into(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some("config.env".into()),
            line: Some(7),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: vec![],
        confidence: Some(0.75),
    }
}

/// SARIF report must identify KeyHog via `tool.driver.name == "keyhog"`.
#[test]
fn sarif_output_has_run_tool_driver() {
    let mut buf = Vec::new();
    {
        let mut reporter = SarifReporter::new(&mut buf);
        reporter.report(&sample_finding()).expect("report finding");
        reporter.finish().expect("finish SARIF document");
    }

    let parsed: serde_json::Value =
        serde_json::from_slice(&buf).expect("SARIF output must parse as JSON");

    let driver_name = parsed["runs"][0]["tool"]["driver"]["name"]
        .as_str()
        .expect("runs[0].tool.driver.name must be a string");

    assert_eq!(
        driver_name, TOOL_DRIVER_NAME,
        "SARIF tool.driver.name must be exactly {TOOL_DRIVER_NAME:?}, got {driver_name:?}"
    );
}
