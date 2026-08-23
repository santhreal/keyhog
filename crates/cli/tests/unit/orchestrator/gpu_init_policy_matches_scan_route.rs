use super::support::ENV_LOCK;
use clap::{CommandFactory, Parser};
use keyhog::args::{ScanArgs, WatchArgs};
use keyhog::testing::{CliTestApi as _, API};
use keyhog_scanner::hw_probe::{parse_backend_str, BACKEND_OVERRIDE_VALUES};
use keyhog_scanner::{gpu::GpuRuntimePolicy, GpuInitPolicy, ScanBackend};

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
            GpuInitPolicy::SelectedBackend(keyhog_scanner::ScanBackend::SimdCpu)
        );
    });
}

/// WHY: explicit host routes must not initialize WGPU or native GPU drivers;
/// persistent CPU/SIMD processes otherwise retain the full accelerator stack.
#[test]
fn explicit_host_backends_keep_router_gpu_probe_closed() {
    let host_backends: Vec<_> = BACKEND_OVERRIDE_VALUES
        .iter()
        .filter_map(|value| parse_backend_str(value))
        .filter(|backend| !backend.is_gpu())
        .collect();
    assert!(
        !host_backends.is_empty(),
        "the advertised backend registry must retain at least one host route"
    );
    for backend in host_backends {
        for policy in [GpuRuntimePolicy::Auto, GpuRuntimePolicy::Required] {
            assert!(
                !API.router_gpu_participates_for_test(Some(backend), policy),
                "{} under {policy:?} admitted a GPU census",
                backend.label()
            );
        }
    }
    assert!(!API.router_uses_gpu_probe_for_test(false));
}

#[test]
fn autoroute_and_explicit_gpu_routes_keep_gpu_probe_open() {
    assert!(API.router_gpu_participates_for_test(None, GpuRuntimePolicy::Auto));
    assert!(!API.router_gpu_participates_for_test(None, GpuRuntimePolicy::Disabled));
    for backend in [
        ScanBackend::GpuCuda,
        ScanBackend::GpuMetal,
        ScanBackend::GpuWgpu,
    ] {
        assert!(API.router_gpu_participates_for_test(Some(backend), GpuRuntimePolicy::Auto));
    }
    assert!(API.router_uses_gpu_probe_for_test(true));
}

#[test]
fn explicit_gpu_backend_forces_gpu_compile() {
    with_route_policy_lock(|| {
        let args = scan_args(&["scan", "--backend", "gpu-wgpu", "--path", "."]);
        assert_eq!(
            API.gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::SelectedBackend(keyhog_scanner::ScanBackend::GpuWgpu)
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
        let args = scan_args(&["scan", "--backend", "gpu-cuda", "--path", "."]);
        assert_eq!(
            API.gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::SelectedBackend(keyhog_scanner::ScanBackend::GpuCuda)
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
fn autoroute_config_digest_includes_engine_resource_caps() {
    with_route_policy_lock(|| {
        let mut baseline = scan_args(&["scan", "--no-config", "--stdin"]);
        let baseline_digest = API
            .autoroute_config_digest_for_args(&mut baseline)
            .expect("baseline resolved config digest");

        let mut capped = scan_args(&[
            "scan",
            "--no-config",
            "--stdin",
            "--regex-dfa-limit",
            "256KiB",
            "--gpu-batch-input-limit",
            "512MiB",
        ]);
        let capped_digest = API
            .autoroute_config_digest_for_args(&mut capped)
            .expect("capped resolved config digest");

        assert_ne!(
            baseline_digest, capped_digest,
            "resource caps change compiled and routed work, so they must invalidate autoroute evidence"
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
        default_digest, longer_digest,
        "autoroute cache identity must include min_secret_len because it changes entropy fallback candidate admission"
    );
}

#[test]
fn autoroute_config_digest_includes_decoded_payload_validation() {
    let mut validated = keyhog_scanner::ScannerConfig::default();
    let validated_digest = API.autoroute_config_digest_for_scanner(validated.clone());

    validated.validate_decode = false;
    let unvalidated_digest = API.autoroute_config_digest_for_scanner(validated);

    assert_ne!(
        validated_digest, unvalidated_digest,
        "decoded payload validation changes recursive scanner work and must invalidate autoroute evidence"
    );
}

#[test]
fn autoroute_config_digest_includes_hot_path_instrumentation() {
    let baseline = keyhog_scanner::ScannerConfig::default();
    let baseline_digest = API.autoroute_config_digest_for_scanner(baseline.clone());

    let mut profiled = baseline.clone();
    profiled.profile = true;
    assert_ne!(
        baseline_digest,
        API.autoroute_config_digest_for_scanner(profiled),
        "profile instrumentation changes hot-path cost and cannot reuse unprofiled route evidence"
    );

    let mut traced = baseline;
    traced.perf_trace = true;
    assert_ne!(
        baseline_digest,
        API.autoroute_config_digest_for_scanner(traced),
        "perf-trace instrumentation changes hot-path cost and cannot reuse untraced route evidence"
    );
}

#[test]
fn every_calibration_shape_shares_the_normal_scan_config_identity() {
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

    // A calibration that deliberately excludes an eligible GPU is a different
    // candidate census, and that difference is carried by the persisted HOST
    // generation, not by this digest. `AutorouteHostProfile` records
    // `eligible_backends` plus the full GPU device, runtime, driver and
    // batch-limit identity, and a cache row only loads when the whole profile
    // compares equal, so CPU-only evidence still cannot replay under a scan
    // that admits a GPU. See
    // `cpu_only_calibration_cannot_replay_under_a_gpu_admitting_scan`.
    //
    // Hashing it here as well was not redundant-but-harmless. On any host or
    // build with no GPU candidate the exclusion is vacuous and the two host
    // profiles are identical, so the digest was the only thing that differed
    // and it differed on every run: calibration wrote decisions under a key no
    // scan would ever request.
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
    assert_eq!(
        gpu_excluded_digest, normal_digest,
        "a calibration must look up its own evidence under the normal scan identity"
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

/// Per-detector config splits across two identities, and putting it in the
/// wrong one is fatal in opposite directions.
///
/// `[detector.<id>] enabled = false` and a per-detector `confidence_floor` are
/// per-invocation filters. They MUST NOT reach the autoroute identity: an
/// install publishes four calibrated policy configs, none of which carries a
/// user's disable list, so hashing it made every such scan reject the whole
/// table and exit 2 with nothing scanned. They MUST reach the matcher artifact
/// identity, because a matcher compiled for the full corpus cannot be replayed
/// for a filtered one.
#[test]
fn per_detector_config_binds_the_matcher_identity_and_not_the_route_identity() {
    let directory = tempfile::tempdir().expect("config directory");
    let baseline_path = directory.path().join("baseline.toml");
    std::fs::write(&baseline_path, "[scan]\n").expect("write baseline config");
    let disabled_path = directory.path().join("disabled.toml");
    std::fs::write(
        &disabled_path,
        "[detector.razorpay-key-secret]\nenabled = false\n",
    )
    .expect("write disabling config");
    let floor_path = directory.path().join("floor.toml");
    std::fs::write(
        &floor_path,
        "[detector.razorpay-key-secret]\nmin_confidence = 0.99\n",
    )
    .expect("write floor config");

    let digests = |path: &std::path::Path| {
        let raw = path.to_str().expect("config path is utf-8");
        let mut route_args = scan_args(&["scan", "--config", raw, "--stdin"]);
        let route = API
            .autoroute_config_digest_for_args(&mut route_args)
            .expect("autoroute config digest");
        let mut matcher_args = scan_args(&["scan", "--config", raw, "--stdin"]);
        let matcher = API
            .matcher_resolved_config_digest_for_args(&mut matcher_args)
            .expect("matcher resolved config digest");
        (route, matcher)
    };

    let (baseline_route, baseline_matcher) = digests(&baseline_path);
    for path in [&disabled_path, &floor_path] {
        let (route, matcher) = digests(path);
        assert_eq!(
            route,
            baseline_route,
            "per-detector config must reuse the calibrated route identity ({})",
            path.display()
        );
        assert_ne!(
            matcher,
            baseline_matcher,
            "per-detector config must not reuse a matcher artifact built for the full corpus ({})",
            path.display()
        );
    }
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
    let watch_command = WatchArgs::command();
    let watch_backend = watch_command
        .get_arguments()
        .find(|argument| argument.get_id() == "backend")
        .expect("the watch command must expose a --backend argument");
    let watch_advertised: Vec<String> = watch_backend
        .get_possible_values()
        .iter()
        .map(|value| value.get_name().to_string())
        .collect();
    assert_eq!(
        watch_advertised, expected,
        "watch and scan must consume the same scanner-owned backend vocabulary"
    );
    for canonical_label in ["gpu-cuda", "gpu-wgpu", "simd", "cpu"] {
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
        let watch_args = WatchArgs::try_parse_from(["watch", "--backend", value])
            .unwrap_or_else(|error| panic!("watch rejected advertised backend `{value}`: {error}"));
        assert_eq!(
            watch_args.backend.as_deref(),
            Some(value.as_str()),
            "watch must preserve the same backend token for routing"
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
