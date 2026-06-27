//! Adversarial: `detectors --detectors <bad path>` must not silently return an
//! empty listing. An EXPLICIT non-existent `--detectors` path is a deliberate
//! fail-closed (Law 10): `validate_detector_path_for_scan` refuses to silently
//! substitute a different corpus than the operator named, and points them at the
//! fix (omit `--detectors` for the embedded corpus). The contract this guards is
//! "never silently empty" — satisfied by a loud, actionable error just as well
//! as by a listing; only a silent empty success is forbidden. (Omitting
//! `--detectors` entirely falls back to the embedded corpus; that path is
//! covered by the listing tests.)

use crate::support::binary;
use std::process::Command;

#[test]
fn detectors_missing_detectors_dir_hostile() {
    let output = Command::new(binary())
        .args([
            "detectors",
            "--detectors",
            "/nonexistent/keyhog-detectors-dir",
        ])
        .output()
        .expect("spawn detectors");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        // If it lists, it must list real detectors — never a silent empty success.
        assert!(
            stdout.contains("aws-access-key") || stdout.contains("detector"),
            "detectors must not silently return empty on bad --detectors; stdout={stdout}"
        );
    } else {
        // The fail-closed path: a loud, actionable error that names the bad path
        // and the remedy, never an empty exit with no explanation.
        assert!(
            stderr.contains("/nonexistent/keyhog-detectors-dir")
                && stderr.contains("--detectors")
                && (stderr.contains("does not exist") || stderr.contains("embedded corpus")),
            "bad --detectors must fail loudly with the path and the omit-flag remedy, \
             not a silent empty error; code={:?} stderr={stderr}",
            output.status.code()
        );
    }
}
