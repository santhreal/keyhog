//! E2E: `keyhog config --effective` prints the exact scan policy and exits.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

fn effective_config(args: &[&str]) -> (String, String, Option<i32>) {
    let output = Command::new(binary())
        .arg("config")
        .arg("--effective")
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
    effective_config(&["--config", &config_path])
}

fn home_temp_cache_dir(name: &str) -> (TempDir, String) {
    let home = dirs::home_dir().expect("home directory required for cache-dir allowlist");
    let root = TempDir::new_in(home).expect("home tempdir");
    let cache_dir = root.path().join(name);
    std::fs::create_dir_all(&cache_dir).expect("create cache dir");
    let cache_dir = cache_dir.to_string_lossy().to_string();
    (root, cache_dir)
}

#[test]
fn config_effective_prints_and_exits_without_source() {
    let (stdout, stderr, code) = effective_config(&[]);

    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stderr.is_empty(),
        "effective-config command must not emit scan errors; stderr={stderr}"
    );
    for required in [
        "[effective-config]",
        "backend = auto",
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
fn config_effective_prints_backend_override() {
    let (stdout, stderr, code) = effective_config(&["--backend", "simd"]);

    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("backend = simd-regex"),
        "--backend must be visible in resolved config; stdout={stdout}"
    );
}

#[test]
fn scan_ignores_legacy_effective_config_env() {
    let output = Command::new(binary())
        .arg("scan")
        .arg("--no-daemon")
        .arg("--backend")
        .arg("cpu")
        .env("KEYHOG_PRINT_EFFECTIVE_CONFIG", "1")
        .output()
        .expect("spawn keyhog scan");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(2),
        "scan without a source should fail honestly; stderr={stderr}"
    );
    assert!(
        !stdout.contains("[effective-config]"),
        "legacy env must not activate a hidden print-and-exit path; stdout={stdout}"
    );
}

#[test]
fn config_effective_baked_values_equal_explicit_flags() {
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
    let (from_config, config_stderr, config_code) = effective_config(&["--config", &config_path]);
    let (from_flags, flags_stderr, flags_code) = effective_config(&[
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
fn config_effective_prints_hyperscan_cache_dir_and_cli_overrides_toml() {
    let (_config_root, config_cache) = home_temp_cache_dir("config-hs-cache");
    let (_cli_root, cli_cache) = home_temp_cache_dir("cli-hs-cache");
    let dir = TempDir::new().expect("tempdir");
    let config_path = dir.path().join(".keyhog.toml");
    std::fs::write(
        &config_path,
        format!(
            "[system]\ncache_dir = {}\n",
            toml::Value::String(config_cache)
        ),
    )
    .expect("write config");

    let config_path = config_path.to_string_lossy();
    let (stdout, stderr, code) =
        effective_config(&["--config", &config_path, "--cache-dir", &cli_cache]);

    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains(&format!("hyperscan_cache_dir = {cli_cache}")),
        "--cache-dir must be visible in effective config and override TOML; stdout={stdout}"
    );
}

#[test]
fn config_effective_prints_autoroute_cache_and_cli_overrides_toml() {
    let (_config_root, config_cache_dir) = home_temp_cache_dir("config-autoroute-cache");
    let (_cli_root, cli_cache_dir) = home_temp_cache_dir("cli-autoroute-cache");
    let config_cache = format!("{config_cache_dir}/autoroute.json");
    let cli_cache = format!("{cli_cache_dir}/autoroute.json");
    let dir = TempDir::new().expect("tempdir");
    let config_path = dir.path().join(".keyhog.toml");
    std::fs::write(
        &config_path,
        format!(
            "[system]\nautoroute_cache = {}\n",
            toml::Value::String(config_cache)
        ),
    )
    .expect("write config");

    let config_path = config_path.to_string_lossy();
    let (stdout, stderr, code) =
        effective_config(&["--config", &config_path, "--autoroute-cache", &cli_cache]);

    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains(&format!("autoroute_cache_path = {cli_cache}")),
        "--autoroute-cache must be visible in effective config and override TOML; stdout={stdout}"
    );

    let (stdout, stderr, code) =
        effective_config(&["--config", &config_path, "--autoroute-cache", "off"]);
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("autoroute_cache_path = <disabled>"),
        "--autoroute-cache off must visibly disable autoroute persistence; stdout={stdout}"
    );
}

#[test]
fn config_effective_prints_aws_canary_account_count() {
    let (stdout, stderr, code) = effective_config_with_toml(
        "[aws]\n\
         canary_accounts = [\"609629065308\"]\n\
         knockoff_accounts = [\"000000000001\"]\n",
    );

    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("aws_canary_accounts = 2"),
        "[aws] canary/knockoff accounts must be visible in effective config; stdout={stdout}"
    );
}

#[test]
fn config_effective_prints_scanner_tuning_from_toml() {
    let (stdout, stderr, code) = effective_config_with_toml(
        "[tuning]\n\
         fallback_hs = false\n\
         hs_prefilter_max_len = 8192\n\
         fallback_anchor = false\n\
         homoglyph_gate = false\n\
         homoglyph_ascii_skip = false\n\
         fallback_reverse = true\n\
         prefilter_truncate = false\n\
         fallback_prefix_gate = true\n\
         decode_focus = false\n\
         confirmed_suffix_gate = false\n\
         no_candidate_gate = false\n\
         fallback_localizer = true\n\
         gpu_moe_timeout_ms = 12345\n",
    );

    assert_eq!(code, Some(0), "stderr={stderr}");
    for required in [
        "tuning_fallback_hs = false",
        "tuning_hs_prefilter_max_len = 8192",
        "tuning_fallback_anchor = false",
        "tuning_homoglyph_gate = false",
        "tuning_homoglyph_ascii_skip = false",
        "tuning_fallback_reverse = true",
        "tuning_prefilter_truncate = false",
        "tuning_fallback_prefix_gate = true",
        "tuning_decode_focus = false",
        "tuning_confirmed_suffix_gate = false",
        "tuning_no_candidate_gate = false",
        "tuning_fallback_localizer = true",
        "tuning_gpu_moe_timeout_ms = 12345",
    ] {
        assert!(
            stdout.contains(required),
            "[tuning] key must reach effective config: missing `{required}`; stdout={stdout}"
        );
    }
}

#[test]
fn config_effective_ignores_legacy_detection_tuning_env() {
    let output = Command::new(binary())
        .arg("config")
        .arg("--effective")
        .env("KEYHOG_CONFIRMED_GATE", "0")
        .env("KEYHOG_NO_CANDIDATE_GATE", "0")
        .env("KEYHOG_DECODE_FOCUS", "0")
        .env("KEYHOG_HOMOGLYPH_GATE", "0")
        .env("KEYHOG_HOMOGLYPH_ASCII_SKIP", "0")
        .env("KEYHOG_FALLBACK_ANCHOR", "0")
        .env("KEYHOG_FALLBACK_HS", "0")
        .env("KEYHOG_FALLBACK_HS_MAX_LEN", "1")
        .env("KEYHOG_FALLBACK_PREFIX_GATE", "1")
        .env("KEYHOG_FALLBACK_REVERSE", "1")
        .env("KEYHOG_PREFILTER_TRUNCATE", "0")
        .env("KEYHOG_LOCALIZER", "1")
        .output()
        .expect("spawn keyhog config");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(0), "stderr={stderr}");
    for required in [
        "tuning_fallback_hs = true",
        "tuning_hs_prefilter_max_len = 4096",
        "tuning_fallback_anchor = true",
        "tuning_homoglyph_gate = true",
        "tuning_homoglyph_ascii_skip = true",
        "tuning_fallback_reverse = false",
        "tuning_prefilter_truncate = true",
        "tuning_fallback_prefix_gate = false",
        "tuning_decode_focus = true",
        "tuning_confirmed_suffix_gate = true",
        "tuning_no_candidate_gate = true",
        "tuning_fallback_localizer = false",
    ] {
        assert!(
            stdout.contains(required),
            "legacy detection env must not alter scanner tuning: missing `{required}`; stdout={stdout}"
        );
    }
}

#[test]
fn config_effective_scan_section_decode_depth_is_wired() {
    let (stdout, stderr, code) = effective_config_with_toml(
        "[scan]\n\
         decode_depth = 4\n",
    );

    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("max_decode_depth = 4"),
        "[scan].decode_depth must reach the engine config; stdout={stdout}"
    );
}

#[cfg(all(feature = "web", feature = "git"))]
#[test]
fn config_effective_source_limits_follow_config_and_cli_precedence() {
    let dir = TempDir::new().expect("tempdir");
    let config_path = dir.path().join(".keyhog.toml");
    std::fs::write(
        &config_path,
        "[limits]\n\
         stdin_bytes = \"1MB\"\n\
         web_response_bytes = \"2MB\"\n\
         git_chunks = 17\n",
    )
    .expect("write config");

    let config_path = config_path.to_string_lossy();
    let (stdout, stderr, code) =
        effective_config(&["--config", &config_path, "--limit-stdin-bytes", "3MB"]);

    assert_eq!(code, Some(0), "stderr={stderr}");
    for required in [
        "limit_stdin_bytes = 3145728",
        "limit_web_response_bytes = 2097152",
        "limit_git_chunks = 17",
    ] {
        assert!(
            stdout.contains(required),
            "effective config missing `{required}`; stdout={stdout}"
        );
    }
}

#[test]
fn config_effective_no_decode_sets_depth_zero() {
    let (stdout, stderr, code) = effective_config(&["--no-decode"]);

    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("max_decode_depth = 0"),
        "--no-decode must reach the printed engine config; stdout={stdout}"
    );
}

#[test]
fn config_effective_fast_disables_decode_entropy_and_ml() {
    let (stdout, stderr, code) = effective_config(&["--fast"]);

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
fn config_effective_rejects_invalid_config_byte_sizes() {
    let (stdout, stderr, code) = effective_config_with_toml(
        "decode_size_limit = \"10\"\n\
         max_file_size = \"wat\"\n\
         regex_dfa_limit = \"1XB\"\n\
         [limits]\n\
         stdin_bytes = \"9\"\n",
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
        "[limits].stdin_bytes = \"9\"",
    ] {
        assert!(
            stderr.contains(required),
            "stderr missing `{required}`; stderr={stderr}"
        );
    }
}

#[test]
fn config_effective_rejects_malformed_toml() {
    let (stdout, stderr, code) = effective_config_with_toml("this is not = = valid toml [[[\n");

    assert_eq!(code, Some(2), "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.is_empty(),
        "malformed config must not print config: {stdout}"
    );
    for required in [
        "invalid .keyhog.toml configuration",
        ".keyhog.toml",
        "failed to parse TOML",
        "Fix: correct the TOML syntax",
    ] {
        assert!(
            stderr.contains(required),
            "stderr missing `{required}`; stderr={stderr}"
        );
    }
    assert!(
        !stderr.contains("Failed to parse .keyhog.toml"),
        "old warning-and-defaults path must not survive; stderr={stderr}"
    );
}

#[test]
fn config_effective_rejects_missing_explicit_config_path() {
    let dir = TempDir::new().expect("tempdir");
    let missing = dir.path().join("missing-keyhog.toml");
    let missing_arg = missing.to_string_lossy();
    let (stdout, stderr, code) = effective_config(&["--config", &missing_arg]);

    assert_eq!(code, Some(2), "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.is_empty(),
        "missing explicit config must not print config: {stdout}"
    );
    for required in [
        "invalid .keyhog.toml configuration",
        missing_arg.as_ref(),
        "failed to read config file",
        "Fix: make the file readable",
    ] {
        assert!(
            stderr.contains(required),
            "stderr missing `{required}`; stderr={stderr}"
        );
    }
}

#[test]
fn config_effective_rejects_invalid_config_enums_and_min_length() {
    let (stdout, stderr, code) = effective_config_with_toml(
        "format = \"yaml\"\n\
         severity = \"urgent\"\n\
         dedup = \"global\"\n\
         decode_depth = 11\n\
         min_secret_len = 0\n\
         [scan]\n\
         format = \"xml\"\n\
         severity = \"panic\"\n\
         dedup = \"all\"\n\
         decode_depth = 0\n\
         min_secret_len = 0\n\
         [tuning]\n\
         gpu_moe_timeout_ms = 0\n",
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
        "decode_depth = 11",
        "min_secret_len = 0",
        "[scan].format = \"xml\"",
        "[scan].severity = \"panic\"",
        "[scan].dedup = \"all\"",
        "[scan].decode_depth = 0",
        "[scan].min_secret_len = 0",
        "[tuning].gpu_moe_timeout_ms",
    ] {
        assert!(
            stderr.contains(required),
            "stderr missing `{required}`; stderr={stderr}"
        );
    }
}

#[test]
fn config_effective_rejects_invalid_aws_canary_accounts() {
    let (stdout, stderr, code) = effective_config_with_toml(
        "[aws]\n\
         canary_accounts = [\"1234\"]\n\
         knockoff_accounts = [\"\"]\n",
    );

    assert_eq!(code, Some(2), "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.is_empty(),
        "invalid config must not print config: {stdout}"
    );
    for required in [
        "invalid .keyhog.toml configuration",
        "[aws].canary_accounts",
        "12-digit AWS account id",
        "[aws].knockoff_accounts",
        "must not be empty",
    ] {
        assert!(
            stderr.contains(required),
            "stderr missing `{required}`; stderr={stderr}"
        );
    }
}
