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
    effective_config_with_toml_and_args(toml, &[])
}

fn effective_config_with_toml_and_args(toml: &str, args: &[&str]) -> (String, String, Option<i32>) {
    let dir = TempDir::new().expect("tempdir");
    let config_path = dir.path().join(".keyhog.toml");
    std::fs::write(&config_path, toml).expect("write config");
    let config_path = config_path.to_string_lossy();
    let mut command_args = vec!["--config", config_path.as_ref()];
    command_args.extend_from_slice(args);
    effective_config(&command_args)
}

#[test]
fn explicit_backend_does_not_hide_an_invalid_configured_gpu_policy() {
    let (_stdout, stderr, code) =
        effective_config_with_toml_and_args("[system]\ngpu = \"bogus\"\n", &["--backend", "cpu"]);

    assert_eq!(code, Some(2));
    assert!(
        stderr.contains("[system].gpu") && stderr.contains("expected auto, off, or required"),
        "invalid config must remain visible under an explicit backend; stderr={stderr}"
    );
}

fn home_temp_cache_dir(name: &str) -> (TempDir, String) {
    let home = dirs::home_dir().expect("home directory required for cache-dir allowlist");
    let root = TempDir::new_in(home).expect("home tempdir");
    let cache_dir = root.path().join(name);
    std::fs::create_dir_all(&cache_dir).expect("create cache dir");
    let cache_dir = cache_dir.to_string_lossy().to_string();
    (root, cache_dir)
}

fn write_calibration_cache(dir: &TempDir, name: &str, detector_id: &str) -> String {
    let cache = dir.path().join(name);
    std::fs::write(
        &cache,
        format!(r#"{{"version":1,"detectors":{{"{detector_id}":{{"alpha":2,"beta":1}}}}}}"#),
    )
    .expect("write calibration cache");
    cache.to_string_lossy().to_string()
}

#[test]
fn configuration_doc_states_malformed_config_fails_closed() {
    let doc = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/src/reference/configuration.md"
    ));
    for stale in [
        "malformed file warns",
        "warns and is ignored",
        "scan still runs on defaults",
        "is ignored (the scan still runs on defaults)",
    ] {
        assert!(
            !doc.contains(stale),
            "configuration.md must not advertise the retired warning-and-defaults config fallback: {stale:?}"
        );
    }
    for required in [
        "malformed `.keyhog.toml`",
        "fails closed",
        "before any scan output is written",
        "`--no-config`",
    ] {
        assert!(
            doc.contains(required),
            "configuration.md must state the fail-closed malformed-config contract; missing {required:?}"
        );
    }
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
        "batch_pipeline = false",
        "threads = auto",
        "reader_threads = auto",
        "fused_batch = 32",
        "fused_depth = auto",
        "gpu = auto",
        "autoroute_gpu = false",
        "autoroute_calibration = false",
        "profile = false",
        "perf_trace = false",
        "verify = false",
        "format = text",
        "severity = all",
        "dedup = credential",
        "show_secrets = false",
        "hide_client_safe = false",
        "suppress_test_fixtures = true",
        "lockdown = false",
        "verify_timeout_secs = 5",
        "verify_concurrency = 5",
        "verify_rate_rps = 5",
        "http_proxy = unset",
        "insecure_tls = false",
        "allow_script_verify = false",
        "verify_oob = false",
        "verify_oob_timeout_secs = 30",
        "min_confidence = 0.4",
        "entropy_bpe_max_bytes_per_token = 2.2",
        "entropy_bpe_policy = scan-fallback",
        "ml_enabled = true",
        "max_decode_depth = 10",
        "max_decode_bytes = 524288",
        "validate_decode = true",
        "per_chunk_timeout_ms = off",
        "disabled_detectors = ",
        "calibration_cache_path = <disabled>",
        "calibration_entries = 0",
    ] {
        assert!(
            stdout.contains(required),
            "effective config missing `{required}`; stdout={stdout}"
        );
    }
}

#[test]
fn config_effective_reports_client_safe_and_report_policy() {
    let (stdout, stderr, code) = effective_config_with_toml(
        "[scan]\nseverity = \"client-safe\"\nformat = \"json\"\ndedup = \"file\"\n",
    );
    assert_eq!(code, Some(0), "stderr={stderr}");
    for expected in ["severity = client-safe", "format = json", "dedup = file"] {
        assert!(
            stdout.contains(expected),
            "effective config missing {expected:?}: {stdout}"
        );
    }
}

#[cfg(feature = "verify")]
#[test]
fn config_effective_reports_verifier_policy_without_exposing_proxy_credentials() {
    let (stdout, stderr, code) = effective_config(&[
        "--verify",
        "--timeout",
        "9",
        "--verify-concurrency",
        "7",
        "--verify-rate",
        "2.5",
        "--proxy",
        "http://user:password@127.0.0.1:8080",
        "--insecure",
    ]);
    assert_eq!(code, Some(0), "stderr={stderr}");
    for required in [
        "verify = true",
        "verify_timeout_secs = 9",
        "verify_concurrency = 7",
        "verify_rate_rps = 2.5",
        "http_proxy = configured",
        "insecure_tls = true",
    ] {
        assert!(stdout.contains(required), "missing {required:?}: {stdout}");
    }
    assert!(
        !stdout.contains("user") && !stdout.contains("password"),
        "effective config must report proxy policy without leaking URL credentials: {stdout}"
    );
}

#[test]
fn config_effective_example_file_parses_on_default_build() {
    let example = concat!(env!("CARGO_MANIFEST_DIR"), "/../../.keyhog.toml.example");
    let (stdout, stderr, code) = effective_config(&["--config", example]);

    assert_eq!(code, Some(0), "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("[effective-config]"),
        "example config must produce effective config output; stdout={stdout}"
    );
    assert!(
        !stderr.contains("invalid .keyhog.toml configuration"),
        "example config must not be a stale or feature-incompatible template; stderr={stderr}"
    );
}

#[test]
fn config_effective_reflects_bpe_bound_cli_flag_and_toml() {
    // WIRING proof for `entropy_bpe_max_bytes_per_token`: the flag and the TOML
    // key must reach the resolved ScanConfig and surface in the effective dump
    // a flag that only parses is not wired. The default is 2.2 (asserted above);
    // an explicit override must change the emitted value end to end.
    let (stdout, stderr, code) = effective_config(&["--entropy-bpe-max-bytes-per-token", "3.5"]);
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("entropy_bpe_max_bytes_per_token = 3.5"),
        "CLI --entropy-bpe-max-bytes-per-token 3.5 must reach the effective ScanConfig; stdout={stdout}"
    );
    assert!(
        stdout.contains("entropy_bpe_policy = scan-override"),
        "an explicit CLI BPE value must visibly override detector-local/scan fallback policy; stdout={stdout}"
    );

    // Same via the `[scan]` TOML key (CLI absent → TOML value wins over default).
    let (stdout, stderr, code) = effective_config_with_toml(
        "[scan]\nmin_confidence = 0.4\nentropy_bpe_max_bytes_per_token = 1.9\n",
    );
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("entropy_bpe_max_bytes_per_token = 1.9"),
        "[scan] entropy_bpe_max_bytes_per_token = 1.9 must reach the effective ScanConfig; stdout={stdout}"
    );
    assert!(
        stdout.contains("entropy_bpe_policy = scan-override"),
        "an explicit TOML BPE value must visibly override detector-local policy; stdout={stdout}"
    );

    // Retired flat spellings fail closed rather than acting as compatibility
    // aliases for the canonical table.
    let (stdout, stderr, code) = effective_config_with_toml(
        "entropy_bpe_max_bytes_per_token = 1.8\n[scan]\nentropy_bpe_max_bytes_per_token = 1.9\n",
    );
    assert_eq!(code, Some(2), "stdout={stdout}\nstderr={stderr}");
    assert!(
        stderr.contains("unknown field `entropy_bpe_max_bytes_per_token`"),
        "retired flat scan policy must fail closed; stderr={stderr}"
    );

    // Presence is semantic even when the numeric value equals the compiled
    // fallback: detector-local policies may differ from 2.2, so an explicitly
    // typed 2.2 still overrides them and must not collapse into "unset".
    let (stdout, stderr, code) = effective_config(&["--entropy-bpe-max-bytes-per-token", "2.2"]);
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("entropy_bpe_policy = scan-override"),
        "an explicit default-valued BPE flag must preserve override intent; stdout={stdout}"
    );

    let (stdout, stderr, code) =
        effective_config_with_toml("[scan]\nentropy_bpe_max_bytes_per_token = 2.2\n");
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("entropy_bpe_policy = scan-override"),
        "an explicit default-valued [scan] BPE key must preserve override intent; stdout={stdout}"
    );
}

#[test]
fn config_effective_rejects_invalid_bpe_bounds_on_cli_and_toml() {
    for invalid in ["0", "-1", "NaN", "inf"] {
        let (stdout, stderr, code) =
            effective_config(&["--entropy-bpe-max-bytes-per-token", invalid]);
        assert_eq!(
            code,
            Some(2),
            "invalid CLI ratio {invalid:?}; stdout={stdout}\nstderr={stderr}"
        );
        assert!(
            stderr.contains("must be finite and greater than 0.0"),
            "CLI rejection must state the valid domain for {invalid:?}; stderr={stderr}"
        );
    }

    for toml in [
        "[scan]\nentropy_bpe_max_bytes_per_token = 0.0\n",
        "[scan]\nentropy_bpe_max_bytes_per_token = -1.0\n",
        "[scan]\nentropy_bpe_max_bytes_per_token = nan\n",
        "[scan]\nentropy_bpe_max_bytes_per_token = inf\n",
    ] {
        let (stdout, stderr, code) = effective_config_with_toml(toml);
        assert_eq!(
            code,
            Some(2),
            "invalid TOML ratio; stdout={stdout}\nstderr={stderr}"
        );
        assert!(
            stderr.contains("invalid .keyhog.toml configuration")
                && stderr.contains("must be finite and greater than 0.0"),
            "TOML rejection must fail closed with the shared bound; stderr={stderr}"
        );
    }
}

#[test]
fn config_effective_validates_entropy_threshold_on_every_surface() {
    let (stdout, stderr, code) = effective_config_with_toml("[scan]\nentropy_threshold = 5.25\n");
    assert_eq!(code, Some(0), "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("entropy_threshold = 5.25"),
        "nested entropy threshold must reach the effective scanner config; stdout={stdout}"
    );

    for invalid in ["-1", "8.1", "NaN", "inf"] {
        let (stdout, stderr, code) = effective_config(&["--entropy-threshold", invalid]);
        assert_eq!(
            code,
            Some(2),
            "invalid CLI entropy threshold {invalid}; stdout={stdout}\nstderr={stderr}"
        );
        assert!(
            stderr.contains("finite value between 0.0 and 8.0"),
            "CLI error must state the mathematical entropy range; stderr={stderr}"
        );
    }

    for toml in [
        "[scan]\nentropy_threshold = -1.0\n",
        "[scan]\nentropy_threshold = 8.1\n",
        "[scan]\nentropy_threshold = nan\n",
        "[scan]\nentropy_threshold = inf\n",
    ] {
        let (stdout, stderr, code) = effective_config_with_toml(toml);
        assert_eq!(
            code,
            Some(2),
            "invalid TOML entropy threshold; stdout={stdout}\nstderr={stderr}"
        );
        assert!(
            stderr.contains("invalid .keyhog.toml configuration")
                && stderr.contains("finite value between 0.0 and 8.0"),
            "TOML error must fail closed with the shared entropy range; stderr={stderr}"
        );
    }
}

#[test]
fn config_effective_prints_explicit_diagnostic_flags() {
    let (stdout, stderr, code) = effective_config(&["--profile", "--perf-trace"]);

    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("profile = true"),
        "--profile must be visible in resolved config; stdout={stdout}"
    );
    assert!(
        stdout.contains("perf_trace = true"),
        "--perf-trace must be visible in resolved config; stdout={stdout}"
    );
}

#[test]
fn config_effective_prints_batch_pipeline_cli_and_toml() {
    let (stdout, stderr, code) = effective_config(&["--batch-pipeline"]);

    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("batch_pipeline = true"),
        "--batch-pipeline must be visible in resolved config; stdout={stdout}"
    );

    let (stdout, stderr, code) = effective_config_with_toml("[system]\nbatch_pipeline = true\n");
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("batch_pipeline = true"),
        "[system].batch_pipeline must reach resolved config; stdout={stdout}"
    );

    let dir = TempDir::new().expect("tempdir");
    let config_path = dir.path().join(".keyhog.toml");
    std::fs::write(&config_path, "[system]\nbatch_pipeline = true\n").expect("write config");
    let config_path = config_path.to_string_lossy();
    let (stdout, stderr, code) =
        effective_config(&["--config", &config_path, "--no-batch-pipeline"]);
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("batch_pipeline = false"),
        "--no-batch-pipeline must visibly override TOML; stdout={stdout}"
    );
}

#[test]
fn config_effective_prints_gpu_policy_cli_and_toml() {
    let (stdout, stderr, code) = effective_config(&["--no-gpu"]);
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("gpu = off"),
        "--no-gpu must be visible in resolved config; stdout={stdout}"
    );

    let (stdout, stderr, code) = effective_config(&["--require-gpu"]);
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("gpu = required"),
        "--require-gpu must be visible in resolved config; stdout={stdout}"
    );

    let (stdout, stderr, code) = effective_config_with_toml("[system]\ngpu = \"required\"\n");
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("gpu = required"),
        "[system].gpu must reach resolved config; stdout={stdout}"
    );

    let dir = TempDir::new().expect("tempdir");
    let config_path = dir.path().join(".keyhog.toml");
    std::fs::write(&config_path, "[system]\ngpu = \"required\"\n").expect("write config");
    let config_path = config_path.to_string_lossy();
    let (stdout, stderr, code) = effective_config(&["--config", &config_path, "--no-gpu"]);
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("gpu = off"),
        "--no-gpu must visibly override TOML; stdout={stdout}"
    );
}

#[test]
fn config_effective_prints_autoroute_gpu_cli_and_toml() {
    let (stdout, stderr, code) = effective_config(&["--autoroute-gpu"]);
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("autoroute_gpu = true"),
        "--autoroute-gpu must be visible in resolved config; stdout={stdout}"
    );

    let (stdout, stderr, code) = effective_config_with_toml("[system]\nautoroute_gpu = true\n");
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("autoroute_gpu = true"),
        "[system].autoroute_gpu must reach resolved config; stdout={stdout}"
    );

    let dir = TempDir::new().expect("tempdir");
    let config_path = dir.path().join(".keyhog.toml");
    std::fs::write(&config_path, "[system]\nautoroute_gpu = true\n").expect("write config");
    let config_path = config_path.to_string_lossy();
    let (stdout, stderr, code) =
        effective_config(&["--config", &config_path, "--no-autoroute-gpu"]);
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("autoroute_gpu = false"),
        "--no-autoroute-gpu must visibly override TOML; stdout={stdout}"
    );
}

#[test]
fn config_effective_prints_per_chunk_timeout_cli_and_toml() {
    let (stdout, stderr, code) = effective_config(&["--per-chunk-timeout-ms", "1234"]);
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("per_chunk_timeout_ms = 1234"),
        "--per-chunk-timeout-ms must be visible in resolved config; stdout={stdout}"
    );

    let (stdout, stderr, code) =
        effective_config_with_toml("[scan]\nper_chunk_timeout_ms = 9012\n");
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("per_chunk_timeout_ms = 9012"),
        "[scan].per_chunk_timeout_ms must reach resolved config; stdout={stdout}"
    );
}

#[test]
fn config_effective_prints_threading_chunking_cli_and_toml() {
    let (stdout, stderr, code) = effective_config(&[
        "--threads",
        "2",
        "--reader-threads",
        "1",
        "--fused-batch",
        "17",
        "--fused-depth",
        "3",
    ]);
    assert_eq!(code, Some(0), "stderr={stderr}");
    for required in [
        "threads = 2",
        "reader_threads = 1",
        "fused_batch = 17",
        "fused_depth = 3",
    ] {
        assert!(
            stdout.contains(required),
            "CLI threading/chunking config missing `{required}`; stdout={stdout}"
        );
    }

    let (stdout, stderr, code) = effective_config_with_toml(
        "[scan]\n\
         threads = 4\n\
         reader_threads = 2\n\
         fused_batch = 23\n\
         fused_depth = 5\n",
    );
    assert_eq!(code, Some(0), "stderr={stderr}");
    for required in [
        "threads = 4",
        "reader_threads = 2",
        "fused_batch = 23",
        "fused_depth = 5",
    ] {
        assert!(
            stdout.contains(required),
            "[scan] threading/chunking config missing `{required}`; stdout={stdout}"
        );
    }
}

#[test]
fn config_effective_prints_autoroute_calibration_cli() {
    let (stdout, stderr, code) = effective_config(&["--autoroute-calibrate"]);
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("autoroute_calibration = true"),
        "--autoroute-calibrate must be visible in resolved config; stdout={stdout}"
    );
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
        .arg("--daemon=off")
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
        "decode_size_limit = \"256KB\"\n\
         no_ml = true\n\
         [scan]\n\
         min_confidence = 0.7\n\
         decode_depth = 3\n",
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
fn config_effective_prints_documented_generic_keyword_low_entropy_toml_key() {
    let (stdout, stderr, code) =
        effective_config_with_toml("generic_keyword_low_entropy = false\n");

    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("generic_keyword_low_entropy = false"),
        "documented TOML generic_keyword_low_entropy=false must visibly reach resolved scanner config; stdout={stdout}"
    );
}

#[test]
fn config_effective_prints_regex_dfa_limit_cli_and_toml() {
    let (stdout, stderr, code) = effective_config(&["--regex-dfa-limit", "512KB"]);

    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("regex_dfa_limit = 524288"),
        "--regex-dfa-limit must be visible in resolved config; stdout={stdout}"
    );

    let (stdout, stderr, code) = effective_config_with_toml("regex_dfa_limit = \"256KB\"\n");

    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("regex_dfa_limit = 262144"),
        "regex_dfa_limit TOML key must be visible in resolved config; stdout={stdout}"
    );
}

#[test]
fn config_effective_prints_gpu_batch_input_limit_cli_and_toml() {
    // Unset must report VRAM-adaptive, never a fixed byte count.
    let (stdout, stderr, code) = effective_config(&[]);
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("gpu_batch_input_limit = VRAM-adaptive"),
        "unset gpu_batch_input_limit must report the VRAM-adaptive default; stdout={stdout}"
    );

    // `--gpu-batch-input-limit 256MB` (= 256 MiB) reaches resolved config.
    let (stdout, stderr, code) = effective_config(&["--gpu-batch-input-limit", "256MB"]);
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("gpu_batch_input_limit = 268435456"),
        "--gpu-batch-input-limit must be visible in resolved config; stdout={stdout}"
    );

    // The canonical `[scan]` key must resolve identically.
    let (stdout, stderr, code) =
        effective_config_with_toml("[scan]\ngpu_batch_input_limit = \"512MB\"\n");
    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("gpu_batch_input_limit = 536870912"),
        "gpu_batch_input_limit TOML key must be visible in resolved config; stdout={stdout}"
    );
}

#[test]
fn retired_megascan_input_names_are_rejected() {
    let (stdout, stderr, code) = effective_config(&["--megascan-input-len", "256MB"]);
    assert_eq!(code, Some(2), "stdout={stdout}; stderr={stderr}");
    assert!(stderr.contains("unexpected argument '--megascan-input-len'"));

    let (stdout, stderr, code) = effective_config_with_toml("megascan_input_len = \"512MB\"\n");
    assert_eq!(code, Some(2), "stdout={stdout}; stderr={stderr}");
    assert!(stderr.contains("unknown field `megascan_input_len`"));
}

#[test]
fn gpu_batch_limit_rejects_retired_flat_spelling() {
    let (stdout, stderr, code) = effective_config_with_toml(
        "gpu_batch_input_limit = \"256MB\"\n[scan]\ngpu_batch_input_limit = \"512MB\"\n",
    );
    assert_eq!(code, Some(2), "stdout={stdout}; stderr={stderr}");
    assert!(
        stderr.contains("unknown field `gpu_batch_input_limit`"),
        "retired flat spelling must fail closed; stderr={stderr}"
    );
}

#[test]
fn config_effective_reports_active_default_caps_not_off() {
    // With no --regex-dfa-limit / --max-file-size override the engine still
    // enforces a compiled-default DFA cache cap (1 MiB) and a default max file
    // size (100 MiB; files above it are silently skipped). `--effective` must
    // report the real active default, never "off": rendering "off" would tell
    // the operator no cap is in force when one is, hiding a coverage gap.
    let (stdout, stderr, code) = effective_config_with_toml("");

    assert_eq!(
        code,
        Some(0),
        "config --effective should exit 0; stderr={stderr}"
    );
    assert!(
        stdout.contains("regex_dfa_limit = 1048576 (default)"),
        "unset regex_dfa_limit must report the compiled 1 MiB default, not 'off'; stdout={stdout}"
    );
    assert!(
        stdout.contains("max_file_size = 104857600 (default)"),
        "unset max_file_size must report the compiled 100 MiB default, not 'off'; stdout={stdout}"
    );
    assert!(
        !stdout.contains("regex_dfa_limit = off") && !stdout.contains("max_file_size = off"),
        "neither cap may render as 'off' while a default cap is active; stdout={stdout}"
    );
}

#[test]
fn config_effective_prints_source_policy_controls() {
    let dir = TempDir::new().expect("tempdir");
    let cache_path = dir.path().join("incremental.db");
    let config_path = dir.path().join(".keyhog.toml");
    std::fs::write(
        &config_path,
        format!(
            "max_file_size = \"5MB\"\n\
             [scan]\n\
             exclude = [\"target/\", \"*.pem\"]\n\
             incremental = true\n\
             incremental_cache = {}\n",
            toml::Value::String(cache_path.to_string_lossy().to_string())
        ),
    )
    .expect("write config");

    let config_path = config_path.to_string_lossy();
    let (stdout, stderr, code) =
        effective_config(&["--config", &config_path, "--no-default-excludes"]);

    assert_eq!(code, Some(0), "stderr={stderr}");
    for required in [
        "max_file_size = 5242880",
        "no_default_excludes = true",
        "exclude_paths = 2",
        "incremental = true",
    ] {
        assert!(
            stdout.contains(required),
            "effective config missing `{required}`; stdout={stdout}"
        );
    }
    assert!(
        stdout.contains(&format!("incremental_cache = {}", cache_path.display())),
        "effective config must show the resolved incremental cache path; stdout={stdout}"
    );
}

#[test]
#[cfg(feature = "git")]
fn config_effective_prints_max_commits_cli_and_toml() {
    let (stdout, stderr, code) = effective_config_with_toml("max_commits = 456\n");

    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("max_commits = 456"),
        "max_commits TOML key must be visible in resolved source config; stdout={stdout}"
    );

    let dir = TempDir::new().expect("tempdir");
    let config_path = dir.path().join(".keyhog.toml");
    std::fs::write(&config_path, "max_commits = 111\n").expect("write config");
    let config_path = config_path.to_string_lossy();
    let (stdout, stderr, code) =
        effective_config(&["--config", &config_path, "--max-commits", "789"]);

    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains("max_commits = 789"),
        "--max-commits must override TOML in resolved source config; stdout={stdout}"
    );
}

#[test]
#[cfg(feature = "simd")]
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
fn config_effective_prints_calibration_cache_and_cli_overrides_toml() {
    let config_root = TempDir::new().expect("config tempdir");
    let cli_root = TempDir::new().expect("cli tempdir");
    let config_cache =
        write_calibration_cache(&config_root, "config-calibration.json", "config-id");
    let cli_cache = write_calibration_cache(&cli_root, "cli-calibration.json", "cli-id");
    let dir = TempDir::new().expect("tempdir");
    let config_path = dir.path().join(".keyhog.toml");
    std::fs::write(
        &config_path,
        format!(
            "[system]\ncalibration_cache = {}\n",
            toml::Value::String(config_cache)
        ),
    )
    .expect("write config");

    let config_path = config_path.to_string_lossy();
    let (stdout, stderr, code) =
        effective_config(&["--config", &config_path, "--calibration-cache", &cli_cache]);

    assert_eq!(code, Some(0), "stderr={stderr}");
    assert!(
        stdout.contains(&format!("calibration_cache_path = {cli_cache}"))
            && stdout.contains("calibration_entries = 1")
            && stdout.contains("calibration_digest = "),
        "--calibration-cache must be visible in effective config and override TOML; stdout={stdout}"
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
         hs_shard_target = 41\n\
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
         gpu_recall_floor = true\n\
         gpu_moe_timeout_ms = 12345\n",
    );

    assert_eq!(code, Some(0), "stderr={stderr}");
    for required in [
        "tuning_fallback_hs = false",
        "tuning_hs_prefilter_max_len = 8192",
        "tuning_hs_shard_target = 41",
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
        "tuning_gpu_recall_floor = true",
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
        "tuning_hs_shard_target = 320",
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
         cloud_max_objects = 23\n\
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
        "limit_cloud_max_objects = 23",
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
fn config_effective_toml_no_entropy_overrides_deep_preset() {
    let (stdout, stderr, code) = effective_config_with_toml(
        "deep = true\n\
         no_entropy = true\n",
    );

    assert_eq!(code, Some(0), "stderr={stderr}");
    for required in ["max_decode_depth = 10", "entropy_enabled = false"] {
        assert!(
            stdout.contains(required),
            "TOML deep + no_entropy must resolve to deep decode with entropy disabled; \
             missing `{required}`; stdout={stdout}"
        );
    }
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
fn config_effective_toml_precision_enables_precision_preset() {
    let (stdout, stderr, code) = effective_config_with_toml("precision = true\n");

    assert_eq!(code, Some(0), "stderr={stderr}");
    for required in [
        "min_confidence = 0.85",
        "entropy_enabled = false",
        "max_decode_depth = 1",
    ] {
        assert!(
            stdout.contains(required),
            "TOML precision preset missing `{required}`; stdout={stdout}"
        );
    }
}

#[test]
fn config_effective_rejects_fast_with_entropy_only_toml_knobs() {
    let (stdout, stderr, code) = effective_config_with_toml(
        "fast = true\n\
         no_decode = true\n\
         no_entropy = true\n\
         entropy_source_files = true\n\
         generic_keyword_low_entropy = false\n\
         [scan]\n\
         entropy_threshold = 5.0\n\
         min_secret_len = 32\n",
    );

    assert_eq!(code, Some(2), "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.is_empty(),
        "invalid config must not print config: {stdout}"
    );
    for required in [
        "invalid .keyhog.toml configuration",
        "no_decode",
        "no_entropy",
        "entropy_source_files",
        "entropy_threshold",
        "generic_keyword_low_entropy = false",
        "[scan].min_secret_len",
        "fast mode disables entropy/decode",
    ] {
        assert!(
            stderr.contains(required),
            "stderr missing `{required}`; stderr={stderr}"
        );
    }
}

#[test]
fn config_effective_rejects_precision_with_entropy_only_toml_knobs() {
    let (stdout, stderr, code) = effective_config_with_toml(
        "precision = true\n\
         no_decode = true\n\
         no_entropy = true\n\
         entropy_source_files = true\n\
         generic_keyword_low_entropy = false\n\
         [scan]\n\
         entropy_threshold = 5.0\n\
         min_secret_len = 32\n",
    );

    assert_eq!(code, Some(2), "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.is_empty(),
        "invalid config must not print config: {stdout}"
    );
    for required in [
        "invalid .keyhog.toml configuration",
        "no_decode",
        "no_entropy",
        "entropy_source_files",
        "entropy_threshold",
        "generic_keyword_low_entropy = false",
        "[scan].min_secret_len",
        "precision mode disables entropy/decode",
    ] {
        assert!(
            stderr.contains(required),
            "stderr missing `{required}`; stderr={stderr}"
        );
    }
}

#[test]
fn config_effective_rejects_multiple_toml_scan_presets() {
    let (stdout, stderr, code) = effective_config_with_toml(
        "fast = true\n\
         deep = true\n\
         precision = true\n",
    );

    assert_eq!(code, Some(2), "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.is_empty(),
        "invalid config must not print config: {stdout}"
    );
    assert!(
        stderr.contains("fast/deep/precision: choose only one scan preset"),
        "stderr must explain the preset conflict; stderr={stderr}"
    );
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
fn config_effective_rejects_unknown_top_level_toml_key() {
    let (stdout, stderr, code) = effective_config_with_toml("no_entropy_ml_scoring = true\n");

    assert_eq!(code, Some(2), "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.is_empty(),
        "unknown top-level config must not print config: {stdout}"
    );
    for required in [
        "invalid .keyhog.toml configuration",
        ".keyhog.toml",
        "failed to parse TOML",
        "unknown field",
        "no_entropy_ml_scoring",
        "Fix: correct the TOML syntax",
    ] {
        assert!(
            stderr.contains(required),
            "stderr missing `{required}`; stderr={stderr}"
        );
    }
}

#[test]
fn config_effective_rejects_unknown_nested_scan_toml_key() {
    let (stdout, stderr, code) =
        effective_config_with_toml("[scan]\nno_keyword_low_entropy = true\n");

    assert_eq!(code, Some(2), "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.is_empty(),
        "unknown nested config must not print config: {stdout}"
    );
    for required in [
        "invalid .keyhog.toml configuration",
        ".keyhog.toml",
        "failed to parse TOML",
        "unknown field",
        "no_keyword_low_entropy",
        "Fix: correct the TOML syntax",
    ] {
        assert!(
            stderr.contains(required),
            "stderr missing `{required}`; stderr={stderr}"
        );
    }
}

#[test]
fn config_effective_rejects_unknown_detector_override_toml_key() {
    let (stdout, stderr, code) =
        effective_config_with_toml("[detector.generic-api-key]\nsuppress = true\n");

    assert_eq!(code, Some(2), "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.is_empty(),
        "unknown detector override must not print config: {stdout}"
    );
    for required in [
        "invalid .keyhog.toml configuration",
        ".keyhog.toml",
        "failed to parse TOML",
        "unknown field",
        "suppress",
        "Fix: correct the TOML syntax",
    ] {
        assert!(
            stderr.contains(required),
            "stderr missing `{required}`; stderr={stderr}"
        );
    }
}

#[test]
fn config_effective_rejects_retired_suppress_table() {
    let (stdout, stderr, code) =
        effective_config_with_toml("[suppress]\nhashes = [\"sha256:abc123\"]\n");

    assert_eq!(code, Some(2), "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.is_empty(),
        "retired suppress table must not print config: {stdout}"
    );
    for required in [
        "invalid .keyhog.toml configuration",
        ".keyhog.toml",
        "failed to parse TOML",
        "unknown field",
        "suppress",
        "Fix: correct the TOML syntax",
    ] {
        assert!(
            stderr.contains(required),
            "stderr missing `{required}`; stderr={stderr}"
        );
    }
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
        "[scan]\n\
         format = \"xml\"\n\
         severity = \"panic\"\n\
         dedup = \"all\"\n\
         decode_depth = 0\n\
         min_secret_len = 0\n\
         reader_threads = 0\n\
         fused_batch = 0\n\
         fused_depth = 0\n\
         per_chunk_timeout_ms = 0\n\
         [tuning]\n\
         hs_shard_target = 0\n\
         gpu_moe_timeout_ms = 0\n",
    );

    assert_eq!(code, Some(2), "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.is_empty(),
        "invalid config must not print config: {stdout}"
    );
    for required in [
        "[scan].format = \"xml\"",
        "[scan].severity = \"panic\"",
        "[scan].dedup = \"all\"",
        "[scan].decode_depth = 0",
        "[scan].min_secret_len = 0",
        "[scan].reader_threads = 0",
        "[scan].fused_batch = 0",
        "[scan].fused_depth = 0",
        "[scan].per_chunk_timeout_ms = 0",
        "[tuning].hs_shard_target",
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
