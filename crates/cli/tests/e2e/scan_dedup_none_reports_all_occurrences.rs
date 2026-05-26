//! E2E: `--dedup none` preserves duplicate findings in one file.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_dedup_none_reports_all_occurrences() {
    let key = concat!("AK", "IAQYLPMN5HFIQR7XYA");
    let gh = concat!("gh", "p_aBcD1234EFgh5678ijkl9012MNop3456qrST");
    let fixture = format!("AWS_ACCESS_KEY_ID = \"{key}\"\nGH_TOKEN = \"{gh}\"\n",);
    let (_dir, path) = write_temp_file("multi.txt", &fixture);
    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--format", "json", "--dedup", "none"])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(1));
    let parsed = serde_json::from_slice::<serde_json::Value>(&output.stdout).expect("json");
    let arr = parsed.as_array().expect("array");
    assert!(
        arr.len() >= 2,
        "distinct secrets with --dedup none must surface multiple findings; got {}",
        arr.len()
    );
}
