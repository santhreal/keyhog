//! Contract: ambient `KEYHOG_DETECTORS` never selects the detector corpus.
//!
//! Only `--detectors` / the config file choose a detector directory. Driven
//! through the real binary and the emitted detector listing, so the guarantee
//! is observed rather than grepped out of `orchestrator_config.rs`.

use crate::support::binary;
use std::process::Command;
use tempfile::TempDir;

/// A detector directory holding exactly one TOML, so a corpus that honored it
/// would list exactly one detector.
fn single_detector_dir() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../detectors/twilio-api-key.toml");
    std::fs::copy(&repo, dir.path().join("twilio-api-key.toml"))
        .expect("copy a single detector TOML into the fixture dir");
    dir
}

fn detector_ids(env: Option<&std::path::Path>, args: &[&str]) -> Vec<String> {
    let mut command = Command::new(binary());
    command.args(["detectors", "--format", "json"]).args(args);
    match env {
        Some(dir) => {
            command.env("KEYHOG_DETECTORS", dir);
        }
        None => {
            command.env_remove("KEYHOG_DETECTORS");
        }
    }
    let output = command.output().expect("spawn keyhog detectors");
    assert_eq!(
        output.status.code(),
        Some(0),
        "detectors listing must exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("detector listing must be JSON");
    parsed
        .as_array()
        .expect("detector listing must be a JSON array")
        .iter()
        .map(|d| d["id"].as_str().expect("detector id").to_owned())
        .collect()
}

#[test]
fn ambient_keyhog_detectors_does_not_select_the_detector_corpus() {
    let dir = single_detector_dir();
    let baseline = detector_ids(None, &[]);
    let with_env = detector_ids(Some(dir.path()), &[]);

    assert_eq!(
        with_env, baseline,
        "KEYHOG_DETECTORS must be ignored: the corpus comes from --detectors / config"
    );
    assert!(
        with_env.len() > 1,
        "the env-pointed one-detector dir must not have replaced the corpus, got {with_env:?}"
    );
}

#[test]
fn explicit_detectors_flag_wins_over_ambient_keyhog_detectors() {
    // Proves the oracle above is not vacuous: the same listing does move when
    // the supported surface selects a directory.
    let dir = single_detector_dir();
    let explicit = detector_ids(
        Some(dir.path()),
        &["--detectors", dir.path().to_str().expect("utf-8 path")],
    );
    assert_eq!(explicit, vec!["twilio-api-key".to_owned()]);
}
