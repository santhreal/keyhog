//! The shipped explainer must expose detector-local admission policy, not only
//! regexes. Operators tune generic detection in the owning detector TOML.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn explain_generic_secret_prints_detector_owned_entropy_and_bpe_policy() {
    let detectors = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("detectors");
    let output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .args(["explain", "generic-secret", "--detectors"])
        .arg(detectors)
        .output()
        .expect("run keyhog explain generic-secret");

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
        "source: detectors/generic-secret.toml",
    ] {
        assert!(
            stdout.contains(expected),
            "explain output is missing {expected:?}:\n{stdout}"
        );
    }
}
