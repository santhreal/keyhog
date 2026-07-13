//! SARIF coverage transparency: skipped and partially covered inputs surface as
//! `runs[0].invocations[].toolExecutionNotifications` so a consuming platform
//! knows the scan did not cover the whole tree (a "no results" run with skips is
//! not a clean bill of health). Zero-count categories are omitted; an all-clean
//! run emits no invocations block.

use crate::support::reporters::SarifReporter;
#[test]
fn sarif_skip_summary_emits_tool_execution_notifications() {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut r = SarifReporter::new(&mut buf).with_skip_summary(vec![
            ("binary (extension or content sniff)".to_string(), 5),
            ("unreadable (permission denied or I/O error)".to_string(), 2),
            (
                "exclusion policy (.keyhogignore, --exclude-paths, or lock/minified/vendored defaults)"
                    .to_string(),
                0,
            ), // dropped
        ]);
        r.finish().unwrap();
    }
    let json: serde_json::Value = serde_json::from_slice(&buf).expect("valid SARIF JSON");

    let invocations = json["runs"][0]["invocations"]
        .as_array()
        .expect("invocations array present when files were skipped");
    assert_eq!(invocations.len(), 1);
    assert_eq!(
        invocations[0]["executionSuccessful"].as_bool(),
        Some(true),
        "skipping files is expected, not an execution failure"
    );

    let notes = invocations[0]["toolExecutionNotifications"]
        .as_array()
        .expect("toolExecutionNotifications array");
    assert_eq!(
        notes.len(),
        2,
        "the zero-count category must be filtered out, leaving binary + unreadable"
    );

    let by_reason: std::collections::HashMap<String, i64> = notes
        .iter()
        .map(|n| {
            (
                n["properties"]["reason"].as_str().unwrap().to_string(),
                n["properties"]["count"].as_i64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        by_reason.get("binary (extension or content sniff)"),
        Some(&5)
    );
    assert_eq!(
        by_reason.get("unreadable (permission denied or I/O error)"),
        Some(&2)
    );

    for n in notes {
        assert_eq!(n["level"].as_str(), Some("note"));
        assert_eq!(n["descriptor"]["id"].as_str(), Some("keyhog/coverage-gap"));
    }
    assert!(
        notes.iter().any(|n| n["message"]["text"]
            .as_str()
            .unwrap()
            .contains("5 coverage gap(s): binary")),
        "notification text must state the count and coverage-gap reason"
    );
}

#[test]
fn sarif_without_skips_emits_no_invocations_block() {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut r = SarifReporter::new(&mut buf);
        r.finish().unwrap();
    }
    let json: serde_json::Value = serde_json::from_slice(&buf).expect("valid SARIF JSON");
    assert!(
        json["runs"][0].get("invocations").is_none(),
        "a fully-covered scan must not emit an invocations/notifications block"
    );
}

#[test]
fn sarif_with_skips_is_still_valid_json_with_results() {
    // The invocations block must not corrupt the streamed results array / doc.
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut r = SarifReporter::new(&mut buf)
            .with_skip_summary(vec![("exceeded --max-file-size".to_string(), 3)]);
        r.finish().unwrap();
    }
    let json: serde_json::Value = serde_json::from_slice(&buf).expect("valid SARIF JSON");
    assert_eq!(json["version"].as_str(), Some("2.1.0"));
    assert!(json["runs"][0]["results"].as_array().unwrap().is_empty());
    assert!(json["runs"][0]["tool"]["driver"]["name"].as_str() == Some("keyhog"));
    assert_eq!(
        json["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]["properties"]["count"]
            .as_i64(),
        Some(3)
    );
}
