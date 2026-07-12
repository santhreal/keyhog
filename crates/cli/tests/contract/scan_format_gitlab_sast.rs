//! Contract: `--format gitlab-sast` emits GitLab SAST report JSON.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

fn scan(path: &std::path::Path) -> std::process::Output {
    Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
            "--format",
            "gitlab-sast",
        ])
        .arg(path)
        .output()
        .expect("spawn keyhog scan --format gitlab-sast")
}

#[test]
fn clean_scan_emits_empty_gitlab_sast_report() {
    let (_dir, path) = write_temp_file("clean.env", "no secrets here\n");
    let output = scan(&path);
    assert_eq!(
        output.status.code(),
        Some(0),
        "clean GitLab SAST scan must exit 0"
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("GitLab SAST JSON parses");
    assert_eq!(report["scan"]["type"], "sast");
    assert_eq!(report["scan"]["scanner"]["id"], "keyhog");
    assert_eq!(
        report["vulnerabilities"]
            .as_array()
            .expect("vulnerabilities array")
            .len(),
        0
    );
}

#[test]
fn planted_secret_emits_gitlab_sast_vulnerability() {
    let plaintext = "AKIAKPQXRMSNTBVWYZBN";
    let (_dir, path) = write_temp_file(
        "secret.env",
        &format!("clean line\nAWS_ACCESS_KEY_ID={plaintext}\n"),
    );
    let output = scan(&path);
    assert_eq!(
        output.status.code(),
        Some(1),
        "planted unverified secret must exit 1"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains(plaintext),
        "GitLab SAST output must not leak plaintext credentials"
    );

    let report: serde_json::Value = serde_json::from_str(&stdout).expect("GitLab SAST JSON parses");
    let vulnerabilities = report["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities array");
    assert!(
        !vulnerabilities.is_empty(),
        "planted secret must produce a SAST vulnerability"
    );
    let vuln = &vulnerabilities[0];
    assert_eq!(vuln["category"], "sast");
    assert_eq!(vuln["severity"], "Critical");
    assert_eq!(vuln["location"]["start_line"], 2);
    assert_eq!(vuln["identifiers"][0]["type"], "keyhog_rule");
    assert_eq!(vuln["details"]["credential"]["value"], "AK...BN");
}
