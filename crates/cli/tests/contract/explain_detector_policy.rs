//! The shipped explainer must expose detector-local admission policy, not only
//! regexes. Operators tune generic detection in the owning detector TOML.

use std::path::PathBuf;
use std::process::{Command, Output};

fn explain(detector_id: &str) -> Output {
    let detectors = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("detectors");
    Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .args(["explain", detector_id, "--detectors"])
        .arg(detectors)
        .output()
        .unwrap_or_else(|error| panic!("run keyhog explain {detector_id}: {error}"))
}

#[test]
fn explain_generic_secret_prints_detector_owned_entropy_and_bpe_policy() {
    let output = explain("generic-secret");

    assert_eq!(
        output.status.code(),
        Some(0),
        "explain failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "Detection policy:",
        "kind: phase2-generic",
        "entropy_high: 4.5 bits/byte",
        "entropy_low: 3 bits/byte",
        "bpe_max_bytes_per_token: 2.2 UTF-8 bytes/token",
        "entropy_floor: 2.8 bits/byte through 24 bytes",
        "policy owner: [detector] in the loaded detector TOML",
    ] {
        assert!(
            stdout.contains(expected),
            "explain output is missing {expected:?}:\n{stdout}"
        );
    }
}

#[test]
fn explain_password_reports_explicit_bpe_disablement() {
    let output = explain("generic-password");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("bpe_enabled: false"),
        "password policy must expose explicit BPE disablement:\n{stdout}"
    );
    assert!(
        !stdout.contains("bpe_max_bytes_per_token:"),
        "disabled policy must not retain a magic BPE ceiling:\n{stdout}"
    );
}
