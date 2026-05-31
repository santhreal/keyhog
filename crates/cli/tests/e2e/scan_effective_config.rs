//! E2E: effective config oracle prints the exact scan policy and exits.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

fn effective_config(args: &[&str]) -> (String, String, Option<i32>) {
    let output = Command::new(binary())
        .env("KEYHOG_PRINT_EFFECTIVE_CONFIG", "1")
        .args(args)
        .output()
        .expect("spawn keyhog");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code(),
    )
}

#[test]
fn scan_effective_config_env_prints_and_exits_without_source() {
    let (stdout, stderr, code) = effective_config(&["scan", "--no-daemon"]);

    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stderr.is_empty(),
        "effective-config oracle must not emit scan errors; stderr={stderr}"
    );
    for required in [
        "[effective-config]",
        "min_confidence = 0.4",
        "ml_enabled = true",
        "max_decode_depth = 10",
        "max_decode_bytes = 524288",
        "disabled_detectors = ",
    ] {
        assert!(
            stdout.contains(required),
            "effective config missing `{required}`; stdout={stdout}"
        );
    }
}

#[test]
fn scan_effective_config_baked_values_equal_explicit_flags() {
    let dir = TempDir::new().expect("tempdir");
    let config_path = dir.path().join(".keyhog.toml");
    std::fs::write(
        &config_path,
        "min_confidence = 0.7\n\
         decode_depth = 3\n\
         decode_size_limit = \"256KB\"\n\
         no_ml = true\n",
    )
    .expect("write config");

    let config_path = config_path.to_string_lossy();
    let (from_config, config_stderr, config_code) =
        effective_config(&["scan", "--no-daemon", "--config", &config_path]);
    let (from_flags, flags_stderr, flags_code) = effective_config(&[
        "scan",
        "--no-daemon",
        "--min-confidence",
        "0.7",
        "--decode-depth",
        "3",
        "--decode-size-limit",
        "256KB",
        "--no-ml",
    ]);

    assert_eq!(config_code, Some(0), "stderr={config_stderr}");
    assert_eq!(flags_code, Some(0), "stderr={flags_stderr}");
    assert_eq!(from_config, from_flags);
    assert!(from_config.contains("min_confidence = 0.7"));
    assert!(from_config.contains("max_decode_depth = 3"));
    assert!(from_config.contains("max_decode_bytes = 262144"));
    assert!(from_config.contains("ml_enabled = false"));
}
