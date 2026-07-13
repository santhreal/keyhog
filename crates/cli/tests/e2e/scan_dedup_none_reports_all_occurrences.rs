//! E2E: `--dedup none` preserves duplicate findings in one file.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_dedup_none_reports_all_occurrences() {
    let key = concat!("AK", "IAQYLPMN5HFIQR7XYA");
    let gh = concat!("gh", "p_aBcD1234EFgh5678ijkl9012MNop343hK7n2");
    let fixture = format!("AWS_ACCESS_KEY_ID = \"{key}\"\nGH_TOKEN = \"{gh}\"\n",);
    let (_dir, path) = write_temp_file("multi.txt", &fixture);
    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--daemon=off",
            "--format",
            "json",
            "--dedup",
            "none",
        ])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(1));
    let parsed = serde_json::from_slice::<serde_json::Value>(&output.stdout).expect("json");
    let arr = parsed.as_array().expect("array");
    let ids: Vec<String> = arr
        .iter()
        .filter_map(|f| {
            f.get("detector_id")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .collect();
    // Law 6: the two DISTINCT planted secrets must each surface as their OWN
    // detector, not merely "2 findings", a dedup bug returning the same
    // credential twice would satisfy a bare `len() >= 2` count.
    assert!(
        ids.iter().any(|id| id == "aws-access-key"),
        "the planted AWS key must surface as aws-access-key; got {ids:?}"
    );
    assert!(
        ids.iter().any(|id| id.contains("github")),
        "the planted GitHub token must surface as a github detector (distinct from the AWS key); got {ids:?}"
    );
}
