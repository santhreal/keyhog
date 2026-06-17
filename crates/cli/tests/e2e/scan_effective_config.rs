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

fn effective_config_with_toml(toml: &str) -> (String, String, Option<i32>) {
    let dir = TempDir::new().expect("tempdir");
    let config_path = dir.path().join(".keyhog.toml");
    std::fs::write(&config_path, toml).expect("write config");
    let config_path = config_path.to_string_lossy();
    effective_config(&["scan", "--no-daemon", "--config", &config_path])
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

#[test]
fn scan_effective_config_no_decode_sets_depth_zero() {
    let (stdout, stderr, code) = effective_config(&["scan", "--no-daemon", "--no-decode"]);

    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("max_decode_depth = 0"),
        "--no-decode must reach the printed engine config; stdout={stdout}"
    );
}

#[test]
fn scan_effective_config_fast_disables_decode_entropy_and_ml() {
    let (stdout, stderr, code) = effective_config(&["scan", "--no-daemon", "--fast"]);

    assert_eq!(code, Some(0), "stderr={stderr}");
    for required in [
        "ml_enabled = false",
        "entropy_enabled = false",
        "max_decode_depth = 0",
    ] {
        assert!(
            stdout.contains(required),
            "--fast effective config missing `{required}`; stdout={stdout}"
        );
    }
}

#[test]
fn scan_effective_config_rejects_invalid_config_byte_sizes() {
    let (stdout, stderr, code) = effective_config_with_toml(
        "decode_size_limit = \"10\"\n\
         max_file_size = \"wat\"\n\
         regex_dfa_limit = \"1XB\"\n",
    );

    assert_eq!(code, Some(2), "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.is_empty(),
        "invalid config must not print config: {stdout}"
    );
    for required in [
        "invalid .keyhog.toml configuration",
        "decode_size_limit = \"10\"",
        "missing a unit",
        "max_file_size = \"wat\"",
        "unknown size suffix",
        "regex_dfa_limit = \"1XB\"",
    ] {
        assert!(
            stderr.contains(required),
            "stderr missing `{required}`; stderr={stderr}"
        );
    }
}

#[test]
fn scan_effective_config_rejects_invalid_config_enums_and_min_length() {
    let (stdout, stderr, code) = effective_config_with_toml(
        "format = \"yaml\"\n\
         severity = \"urgent\"\n\
         dedup = \"global\"\n\
         min_secret_len = 0\n\
         [scan]\n\
         format = \"xml\"\n\
         severity = \"panic\"\n\
         dedup = \"all\"\n\
         min_secret_len = 0\n",
    );

    assert_eq!(code, Some(2), "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.is_empty(),
        "invalid config must not print config: {stdout}"
    );
    for required in [
        "format = \"yaml\"",
        "severity = \"urgent\"",
        "dedup = \"global\"",
        "min_secret_len = 0",
        "[scan].format = \"xml\"",
        "[scan].severity = \"panic\"",
        "[scan].dedup = \"all\"",
        "[scan].min_secret_len = 0",
    ] {
        assert!(
            stderr.contains(required),
            "stderr missing `{required}`; stderr={stderr}"
        );
    }
}
