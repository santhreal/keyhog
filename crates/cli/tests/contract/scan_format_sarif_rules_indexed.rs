//! Contract: `--format sarif` tool.driver.rules includes all ruleIds referenced in results.

use crate::e2e::support::{binary, write_temp_file};
use std::collections::HashSet;
use std::process::Command;

#[test]
fn scan_format_sarif_rules_indexed() {
    // Plant AWS key to guarantee a finding with a specific ruleId
    let (_dir, path) = write_temp_file("secret.env", "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--format",
            "sarif",
            "--no-suppress-test-fixtures",
        ])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(1));

    let sarif: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid SARIF JSON");

    let run = &sarif["runs"][0];

    // Collect all ruleIds from tool.driver.rules[]
    let defined_rules: HashSet<String> = run["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules must be an array")
        .iter()
        .filter_map(|r| r["id"].as_str().map(str::to_string))
        .collect();

    // Collect all ruleIds referenced in results[]
    let referenced_rules: HashSet<String> = run["results"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|r| r["ruleId"].as_str().map(str::to_string))
        .collect();

    // Every referenced ruleId must be defined in tool.driver.rules
    for rule_id in &referenced_rules {
        assert!(
            defined_rules.contains(rule_id),
            "result references ruleId '{}' which is not in tool.driver.rules[] — github code-scanning would drop it",
            rule_id
        );
    }

    // Verify at least one rule and one result for the planted secret
    assert!(
        !defined_rules.is_empty(),
        "must have at least one rule defined"
    );
    assert!(
        !referenced_rules.is_empty(),
        "must have at least one result for the planted secret"
    );
}
