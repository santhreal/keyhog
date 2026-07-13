use super::support::ENV_LOCK;
use clap::{CommandFactory, Parser};
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};
use keyhog_scanner::hw_probe::{parse_backend_str, BACKEND_OVERRIDE_VALUES};
use keyhog_scanner::GpuInitPolicy;

fn scan_args(args: &[&str]) -> ScanArgs {
    ScanArgs::try_parse_from(args).expect("parse scan args")
}

fn with_route_policy_lock(test: impl FnOnce()) {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    test();
}

#[test]
fn explicit_simd_backend_skips_gpu_compile() {
    with_route_policy_lock(|| {
        let args = scan_args(&["scan", "--backend", "simd", "--path", "."]);
        assert_eq!(
            API.gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::ForceDisabled
        );
    });
}

#[test]
fn explicit_gpu_backend_forces_gpu_compile() {
    with_route_policy_lock(|| {
        let args = scan_args(&["scan", "--backend", "gpu", "--path", "."]);
        assert_eq!(
            API.gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::ForceEnabled
        );
    });
}

#[test]
fn filesystem_auto_scan_skips_gpu_compile() {
    with_route_policy_lock(|| {
        let args = scan_args(&["scan", "--backend", "auto", "--path", "."]);
        assert_eq!(
            API.gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::ForceDisabled
        );
    });
}

#[test]
fn filesystem_auto_scan_with_existing_autoroute_cache_keeps_gpu_policy_open() {
    with_route_policy_lock(|| {
        let cache = tempfile::Builder::new()
            .prefix("keyhog_gpu_policy_existing_cache_")
            .suffix(".json")
            .tempfile()
            .expect("create placeholder autoroute cache");
        let cache_arg = cache.path().to_string_lossy().into_owned();
        let args = scan_args(&[
            "scan",
            "--backend",
            "auto",
            "--autoroute-cache",
            &cache_arg,
            "--path",
            ".",
        ]);

        assert_eq!(
            API.gpu_init_policy_for_resolved_autoroute_for_test(
                &args,
                Some(cache.path()),
                false,
                false,
            ),
            GpuInitPolicy::FromRuntimePolicy,
            "an existing autoroute cache must be validated by the router with full runtime identity; \
             startup policy must not force-disable GPU first"
        );
    });
}

#[test]
fn filesystem_autoroute_gpu_calibration_keeps_gpu_policy_open_without_cache() {
    with_route_policy_lock(|| {
        let args = scan_args(&[
            "scan",
            "--backend",
            "auto",
            "--autoroute-calibrate",
            "--autoroute-gpu",
            "--path",
            ".",
        ]);
        assert_eq!(
            API.gpu_init_policy_for_resolved_autoroute_for_test(&args, None, true, true),
            GpuInitPolicy::FromRuntimePolicy,
            "explicit GPU calibration must be able to acquire GPU runtime before any cache exists"
        );
    });
}

#[test]
fn batch_pipeline_filesystem_auto_keeps_runtime_gpu_policy() {
    with_route_policy_lock(|| {
        let args = scan_args(&[
            "scan",
            "--backend",
            "auto",
            "--batch-pipeline",
            "--path",
            ".",
        ]);
        assert_eq!(
            API.gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::FromRuntimePolicy
        );
    });
}

#[test]
fn stdin_auto_scan_keeps_runtime_gpu_policy() {
    with_route_policy_lock(|| {
        let args = scan_args(&["scan", "--backend", "auto", "--stdin"]);
        assert_eq!(
            API.gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::FromRuntimePolicy
        );
    });
}

#[test]
fn backend_flag_gpu_overrides_filesystem_auto_skip() {
    with_route_policy_lock(|| {
        let args = scan_args(&["scan", "--backend", "gpu", "--path", "."]);
        assert_eq!(
            API.gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::ForceEnabled
        );
    });
}

#[test]
fn no_gpu_flag_forces_disabled_policy_for_auto() {
    with_route_policy_lock(|| {
        let args = scan_args(&["scan", "--backend", "auto", "--no-gpu", "--path", "."]);
        assert_eq!(
            API.gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::ForceDisabled
        );
    });
}

#[test]
fn require_gpu_flag_keeps_auto_filesystem_gpu_policy_open() {
    with_route_policy_lock(|| {
        let args = scan_args(&["scan", "--backend", "auto", "--require-gpu", "--path", "."]);
        assert_eq!(
            API.gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::FromRuntimePolicy
        );
    });
}

#[test]
fn autoroute_config_digest_distinguishes_detector_local_from_explicit_bpe_policy() {
    let detector_local = keyhog_scanner::ScannerConfig::default();
    let mut explicit_same_value = detector_local.clone();
    explicit_same_value.entropy_bpe_max_bytes_per_token_override =
        Some(detector_local.entropy_bpe_max_bytes_per_token);

    assert_ne!(
        API.autoroute_config_digest_for_scanner(detector_local),
        API.autoroute_config_digest_for_scanner(explicit_same_value),
        "an explicit scan-wide BPE override changes behavior for detector-tuned policies even when its numeric value equals the compiled fallback"
    );
}

#[test]
fn autoroute_config_digest_includes_source_limits() {
    with_route_policy_lock(|| {
        let mut default_limit = scan_args(&["scan", "--no-config", "--stdin"]);
        let default_digest = API
            .autoroute_config_digest_for_args(&mut default_limit)
            .expect("default resolved config digest");

        let mut smaller_stdin = scan_args(&[
            "scan",
            "--no-config",
            "--stdin",
            "--limit-stdin-bytes",
            "1MiB",
        ]);
        let smaller_digest = API
            .autoroute_config_digest_for_args(&mut smaller_stdin)
            .expect("limited resolved config digest");

        assert_ne!(
            default_digest, smaller_digest,
            "autoroute cache identity must include resolved source limits because they change workload bytes and route cost"
        );
    });
}

#[test]
fn autoroute_config_digest_includes_min_secret_len() {
    let mut default_len = scan_args(&["scan", "--no-config", "--stdin"]);
    let default_digest = API
        .autoroute_config_digest_for_args(&mut default_len)
        .expect("resolved default config digest");

    let mut longer_secret_len =
        scan_args(&["scan", "--no-config", "--stdin", "--min-secret-len", "48"]);
    let longer_digest = API
        .autoroute_config_digest_for_args(&mut longer_secret_len)
        .expect("resolved min_secret_len digest");

    assert_ne!(
        default_digest,
        longer_digest,
        "autoroute cache identity must include min_secret_len because it changes entropy fallback candidate admission"
    );
}

#[test]
fn canonical_calibration_shares_normal_identity_but_gpu_exclusion_is_isolated() {
    let mut normal = scan_args(&["scan", "--no-config", "--stdin"]);
    let normal_digest = API
        .autoroute_config_digest_for_args(&mut normal)
        .expect("normal resolved config digest");

    let mut canonical = scan_args(&[
        "scan",
        "--no-config",
        "--stdin",
        "--autoroute-calibrate",
        "--autoroute-gpu",
    ]);
    let canonical_digest = API
        .autoroute_config_digest_for_args(&mut canonical)
        .expect("canonical calibration digest");
    assert_eq!(
        canonical_digest, normal_digest,
        "all-candidate calibration must persist under the normal scan identity it serves"
    );

    let mut gpu_excluded = scan_args(&[
        "scan",
        "--no-config",
        "--stdin",
        "--autoroute-calibrate",
        "--no-autoroute-gpu",
    ]);
    let gpu_excluded_digest = API
        .autoroute_config_digest_for_args(&mut gpu_excluded)
        .expect("GPU-excluded calibration digest");
    assert_ne!(
        gpu_excluded_digest, normal_digest,
        "incomplete diagnostic calibration must not replace normal all-candidate evidence"
    );

    let mut cpu_only_normal = scan_args(&["scan", "--no-config", "--stdin", "--no-gpu"]);
    let cpu_only_normal_digest = API
        .autoroute_config_digest_for_args(&mut cpu_only_normal)
        .expect("CPU-only normal config digest");
    let mut cpu_only_calibration = scan_args(&[
        "scan",
        "--no-config",
        "--stdin",
        "--no-gpu",
        "--autoroute-calibrate",
    ]);
    let cpu_only_calibration_digest = API
        .autoroute_config_digest_for_args(&mut cpu_only_calibration)
        .expect("CPU-only calibration config digest");
    assert_eq!(
        cpu_only_calibration_digest, cpu_only_normal_digest,
        "GPU exclusion is complete when the resolved runtime policy disables GPU"
    );
}

/// Coherence gate: every value the `--backend` flag ADVERTISES (clap
/// `PossibleValuesParser`) must be RECOGNIZED by the canonical
/// `parse_backend_str`, which both the gpu-init policy and the actual scan
/// routing delegate to. This pins them together so a future
/// advertised value that nobody teaches the parser fails CI instead of
/// silently no-op'ing.
#[test]
fn every_advertised_backend_value_is_recognized_by_the_canonical_parser() {
    let cmd = ScanArgs::command();
    let backend = cmd
        .get_arguments()
        .find(|a| a.get_id() == "backend")
        .expect("the scan command must expose a --backend argument");
    let advertised: Vec<String> = backend
        .get_possible_values()
        .iter()
        .map(|v| v.get_name().to_string())
        .collect();
    assert!(
        advertised.len() >= 4,
        "the --backend flag must advertise its fixed value set; got {advertised:?}"
    );
    let expected: Vec<String> = BACKEND_OVERRIDE_VALUES
        .iter()
        .map(|value| value.to_string())
        .collect();
    assert_eq!(
        advertised, expected,
        "Clap --backend values must come from the scanner-owned backend override contract"
    );
    for canonical_label in ["gpu", "simd", "cpu"] {
        assert!(
            advertised.iter().any(|value| value == canonical_label),
            "canonical backend label `{canonical_label}` must be accepted at the CLI boundary"
        );
    }
    for value in &advertised {
        let parsed_args = ScanArgs::try_parse_from(["scan", "--backend", value, "--path", "."])
            .unwrap_or_else(|error| {
                panic!("clap rejected advertised --backend `{value}`: {error}")
            });
        assert_eq!(
            parsed_args.backend.as_deref(),
            Some(value.as_str()),
            "clap must preserve the advertised backend token for routing"
        );

        if value == "auto" {
            // `auto` is the explicit "defer to the router" choice, not a fixed
            // backend the parser names.
            assert_eq!(
                parse_backend_str(value),
                None,
                "`auto` must not resolve to a fixed backend"
            );
        } else {
            assert!(
                parse_backend_str(value).is_some(),
                "advertised --backend value `{value}` is not recognized by the \
                 canonical parse_backend_str: clap accepts it but routing would \
                 silently ignore it (alias-list drift)"
            );
        }
    }
}
