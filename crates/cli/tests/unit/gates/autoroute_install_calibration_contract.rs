#[test]
fn installer_primes_autoroute_and_runtime_requires_explicit_calibration() {
    let mut backend = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch/backend.rs"
    ))
    .expect("backend router source readable");
    let backend_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/orchestrator/dispatch/backend");
    for file in [
        "calibration.rs",
        "evidence.rs",
        "host.rs",
        "store.rs",
        "workload.rs",
    ] {
        backend.push('\n');
        backend.push_str(
            &std::fs::read_to_string(backend_dir.join(file))
                .unwrap_or_else(|error| panic!("backend submodule {file} readable: {error}")),
        );
    }
    backend.push('\n');
    backend.push_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/autoroute_cache_path.rs"
        ))
        .expect("autoroute cache path source readable"),
    );
    let atomic_file =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/atomic_file.rs"))
            .expect("atomic file source readable");
    let stable_hash =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/stable_hash.rs"))
            .expect("stable hash source readable");
    let install_sh =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../install.sh"))
            .expect("install.sh readable");
    let install_ps1 =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../install.ps1"))
            .expect("install.ps1 readable");
    let readme = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../README.md"))
        .expect("README readable");
    let env_ref = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/src/reference/env.md"
    ))
    .expect("env reference readable");
    let dispatch = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch.rs"
    ))
    .expect("dispatch source readable");
    let run = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/run.rs"
    ))
    .expect("orchestrator run source readable");
    let fused = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch/fused.rs"
    ))
    .expect("fused dispatch source readable");
    let streaming = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/streaming.rs"
    ))
    .expect("streaming source helper readable");
    let config = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator_config.rs"
    ))
    .expect("orchestrator config source readable");
    let effective_config = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator_config/effective.rs"
    ))
    .expect("effective config source readable");
    let calibration_config = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator_config/calibration.rs"
    ))
    .expect("calibration config source readable");
    let orchestrator_mod = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/mod.rs"
    ))
    .expect("orchestrator module source readable");
    let watch = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/subcommands/watch.rs"
    ))
    .expect("watch source readable");
    let daemon_server =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/daemon/server.rs"))
            .expect("daemon server source readable");
    let installer_release = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/installer/release.rs"
    ))
    .expect("installer release source readable");
    let scan_system = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/subcommands/scan_system.rs"
    ))
    .expect("scan-system source readable");
    let scanner_hw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../scanner/src/hw_probe/mod.rs"
    ))
    .expect("scanner hardware probe source readable");
    let scanner_gpu = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../scanner/src/gpu.rs"
    ))
    .expect("scanner gpu source readable");
    let scanner_gpu_backend = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../scanner/src/gpu/backend.rs"
    ))
    .expect("scanner gpu backend source readable");
    let scanner_engine = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../scanner/src/engine/mod.rs"
    ))
    .expect("scanner engine source readable");
    let scanner_gpu_region_dispatch = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../scanner/src/engine/gpu_region_dispatch.rs"
    ))
    .expect("scanner GPU region dispatch source readable");
    let scanner_backend_triggered = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../scanner/src/engine/backend_triggered.rs"
    ))
    .expect("scanner backend-triggered source readable");
    let readme_text = readme.split_whitespace().collect::<Vec<_>>().join(" ");
    let env_ref_text = env_ref.split_whitespace().collect::<Vec<_>>().join(" ");

    assert!(
        backend.contains("calibration_mode")
            && backend.contains("autoroute calibration required")
            && backend.contains("Normal auto scans never")
            && backend.contains("benchmark, guess")
            && backend.contains("source class")
            && backend.contains("autoroute workload evidence incomplete")
            && backend.contains("ChunkMetadata.source_type")
            && backend.contains("install.sh --calibrate")
            && !backend
                .contains("autoroute cache miss outside calibration mode; using safe default")
            && !backend.contains("unwrap_or(\"unknown\")")
            && !backend.contains("return fallback;"),
        "runtime autoroute must fail loud on cache miss unless explicit calibration mode is set"
    );
    assert!(
        backend.contains("binary_version")
            && backend.contains("git_hash")
            && backend.contains("build_features")
            && backend.contains("cli_features")
            && backend.contains("scanner_features")
            && backend.contains("sources_features")
            && backend.contains("verifier_features")
            && backend.contains("current_scanner_dependency_features")
            && backend.contains("current_sources_dependency_features")
            && backend.contains("current_verifier_dependency_features")
            && backend.contains("rules_digest")
            && backend.contains("cfg!(feature = $name)")
            && backend.contains("push_feature!(\"gpu\")")
            && backend.contains("push_feature!(\"simd\")")
            && backend.contains("cpu_model")
            && backend.contains("detect_cpu_model")
            && backend.contains("CPU model string is unavailable")
            && backend.contains("CPU core topology is unavailable")
            && backend.contains("system memory size is unavailable")
            && backend.contains("GPU runtime backend identity is unavailable")
            && backend.contains("GPU driver/runtime identity is unavailable")
            && backend.contains("physical_cores")
            && backend.contains("logical_cores")
            && backend.contains("total_memory_mb")
            && backend.contains("gpu_runtime_backend")
            && backend.contains("gpu_driver_runtime_identity")
            && backend.contains("decode_density_bucket")
            && backend.contains("AUTOROUTE_DECODE_DENSITY_SAMPLE_BYTES")
            && backend.contains("AUTOROUTE_DECODE_MIN_ENCODED_RUN")
            && backend.contains("sample_bytes")
            && backend.contains("calibration_sample_bytes")
            && backend.contains("insufficient_calibration_sample")
            && backend.contains("correctness_digest")
            && backend.contains("calibrated_at_unix_ms")
            && backend.contains("simd_ms")
            && backend.contains("gpu_ms")
            && backend.contains("simd_timing")
            && backend.contains("cpu_timing")
            && backend.contains("gpu_timing")
            && backend.contains("gpu_cold_ns")
            && backend.contains("gpu_warm_ms")
            && backend.contains("gpu_warm_timing")
            && backend.contains("gpu_route_ns")
            && backend.contains("gpu_cold_warm_route_evidence")
            && backend.contains("trials_ns")
            && backend.contains("confidence_interval_95_ns")
            && backend.contains("selected_backend_has_non_overlapping_confidence")
            && backend.contains("selected_margin_ns")
            && backend.contains("trial == 0")
            && backend.contains("from_trial_ns(self.trials_ns.clone())")
            && backend.contains("Some(expected) => self == &expected")
            && backend.contains("config_digest")
            && backend.contains("source_class_hash")
            && backend.contains("StableHasher::new(\"autoroute-source-class\")")
            && backend.contains("StableHasher::new(\"autoroute-correctness-digest\")")
            && backend.contains("AUTOROUTE_CACHE_VERSION: u32 = 18")
            && backend.contains("AUTOROUTE_CALIBRATION_TRIALS: usize = 7")
            && backend.contains("trials"),
        "autoroute cache must persist binary identity, build feature identity, exact host identity, and measured calibration evidence"
    );
    assert!(
        backend.contains("AUTOROUTE_CALIBRATION_TRIALS")
            && backend.contains("measure_reference_simd")
            && backend.contains("measure_candidate_backend")
            && !backend.contains("sample_batch(")
            && !backend.contains("MAX_SAMPLE_CHUNKS")
            && !backend.contains("MAX_SAMPLE_BYTES")
            && backend.contains("crate::atomic_file::write_bytes(path, &serialized)")
            && atomic_file.contains("tempfile::NamedTempFile::new_in(parent)")
            && atomic_file.contains("tmp.as_file().sync_all()")
            && atomic_file.contains("tmp.persist(path)")
            && backend.contains("backend rejected by autoroute parity check")
            && backend.contains("autoroute cache ignored")
            && backend.contains("scan config digest mismatch")
            && backend.contains("rules digest mismatch")
            && backend.contains("build feature set mismatch")
            && backend.contains("decision.backend != selected_backend.label()")
            && backend.contains("non-canonical backend label")
            && backend.contains("selected backend is missing timing evidence")
            && backend.contains("selected backend is not the fastest persisted timing evidence")
            && backend.contains("not statistically separated")
            && backend.contains("cache decision has mismatched GPU cold/warm route evidence")
            && backend.contains("backend rejected by autoroute GPU degrade check")
            && backend.contains("cache decision is missing a calibration timestamp")
            && backend.contains("duplicate autoroute workload decision")
            && backend.contains("autoroute cache contains no workload decisions")
            && !backend.contains("load_autoroute_cache(path, detector_digest, &host_profile).ok()")
            && !backend.contains("std::fs::rename(&tmp, path)")
            && !backend.contains("path.with_extension(format!(\"tmp.\""),
        "autoroute calibration must use repeated parity-checked full-batch trials, sync and atomically persist cache replacement, and must not silently ignore invalid existing cache state"
    );
    assert!(
        run.contains("backend prewarm skipped during autoroute calibration")
            && run.contains("autoroute_calibration")
            && backend.contains("gpu_route_ms")
            && backend.contains("cold_ns.max(warm_timing.best_ns)")
            && backend.contains("route_candidates"),
        "autoroute calibration must preserve and validate GPU cold/warm state instead of selecting by warmed best timing only"
    );
    assert!(
        scanner_engine.contains("gpu_degrade_count")
            && scanner_gpu_region_dispatch.contains("gpu_degrade_count")
            && scanner_backend_triggered.contains("gpu_degrade_count")
            && backend.contains("scanner.runtime_status().gpu_degrade_count")
            && backend.contains("gpu_degrade_count_before")
            && backend.contains("gpu_degrade_count_after"),
        "autoroute must reject GPU calibration trials that loudly degrade to CPU/SIMD instead of caching them as GPU evidence"
    );
    assert!(
        dispatch.contains("autoroute_config_digest(&self.effective_config)")
            && dispatch.contains("MeasuredBackendRouter::new(")
            && dispatch.contains("hw_caps")
            && dispatch.contains("pattern_count")
            && dispatch.contains("config_digest")
            && dispatch.contains("self.detector_rules_digest.clone()")
            && dispatch.contains("&self.detector_spec_hash")
            && fused.contains("self.detector_rules_digest.clone()")
            && scanner_hw.contains("gpu_runtime_identity")
            && scanner_gpu.contains("gpu_runtime_identity")
            && scanner_gpu_backend.contains("runtime_identity")
            && scanner_gpu_backend.contains("adapter_info.driver")
            && dispatch.contains("scanner.as_ref()")
            && config.contains(
                "pub(crate) use effective::{autoroute_config_digest, render_effective_config}"
            )
            && effective_config.contains(
                "pub(crate) fn autoroute_config_digest(resolved: &ResolvedScanConfig) -> u64"
            )
            && !config.contains("hash_autoroute_runtime_env")
            && !config.contains("KEYHOG_SHARD_TARGET")
            && !effective_config.contains("KEYHOG_SHARD_TARGET")
            && effective_config.contains("per_chunk_timeout_ms")
            && effective_config.contains("StableHasher::new(\"autoroute-config-digest\")")
            && effective_config.contains("hash_scanner_tuning")
            && stable_hash.contains("blake3::Hasher")
            && stable_hash.contains("field_name")
            && stable_hash.contains("finish_u64")
            && effective_config.contains("tuning_hs_shard_target")
            && effective_config.contains("tuning_gpu_recall_floor")
            && effective_config.contains("detector_min_confidence")
            && effective_config.contains("disabled_detectors")
            && calibration_config.contains("StableHasher::new(\"calibration-store-digest\")")
            && !backend.contains("DefaultHasher")
            && !effective_config.contains("DefaultHasher")
            && !calibration_config.contains("DefaultHasher")
            && !config.contains("DefaultHasher"),
        "autoroute cache identity must include the fully resolved scan config and runtime backend knobs through stable BLAKE3 hashing, not Rust DefaultHasher state"
    );
    assert!(
        orchestrator_mod.contains("cached_autoroute_router_for_default_config")
            && orchestrator_mod.contains("resolved_scan_config_for_scanner")
            && orchestrator_mod.contains("autoroute_config_digest")
            && orchestrator_mod.contains("compute_spec_hash(detectors)")
            && orchestrator_mod.contains("detector_spec_hash")
            && orchestrator_mod.contains("detector_rules_digest")
            && orchestrator_mod.contains("compile_default_scan_runtime")
            && watch.contains("compile_default_scan_runtime")
            && watch.contains("scan_runtime.scan_chunk(&chunk)")
            && watch.contains("source_type: \"filesystem\"")
            && daemon_server.contains("compile_default_scan_runtime")
            && daemon_server.contains("scan_runtime.into_parts()")
            && daemon_server.contains("router: Arc<crate::orchestrator::CachedBackendRouter>")
            && daemon_server.contains("router.choose(")
            && (daemon_server.contains("scan_with_backend(&chunk, backend)")
                || daemon_server.contains("scan_chunks_with_backend(&chunks, backend)"))
            && daemon_server.contains("source_type: \"stdin\"")
            && (daemon_server.contains("source_type: \"filesystem\"")
                || daemon_server.contains("FilesystemSource::new"))
            && scan_system.contains("compile_default_scan_runtime")
            && scan_system.contains("scan_streaming_source(")
            && streaming.contains("scan_runtime.scan_chunk(&chunk)")
            && installer_release.contains("scan_with_backend(&chunk, ScanBackend::CpuFallback)")
            && !watch.contains("scanner.scan(&chunk)")
            && !daemon_server.contains("scanner.scan(&chunk)")
            && !scan_system.contains("scanner.scan(&chunk)")
            && !streaming.contains("scanner.scan(&chunk)")
            && !installer_release.contains("scanner.scan(&chunk)"),
        "daemon, watch, scan-system, and installer release self-test paths must not use CompiledScanner's heuristic default scan path"
    );
    assert!(
        install_sh.contains("prime_autoroute_cache")
            && install_sh.contains("--calibrate")
            && install_sh.contains(
                "Modes:  (default) install/upgrade   --repair   --diagnose   --calibrate   --uninstall"
            )
            && install_sh.contains("Autoroute calibration")
            && install_sh.contains("kib_sizes=\"4 64\"")
            && install_sh.contains("mib_sizes=\"1 8 32\"")
            && install_sh.contains("many_file_counts=\"4 16 32\"")
            && install_sh.contains("elapsed_ms_since")
            && install_sh.contains("PASS %s (%sms)")
            && install_sh.contains("FAIL %s (%sms)")
            && install_sh.contains("total=0")
            && install_sh.contains("total=$((total + 3))")
            && install_sh.contains("empty stdin workload")
            && install_sh.contains("stdin 64 KiB workload")
            && install_sh.contains("run_autoroute_stdin_probe")
            && install_sh.contains("scan --autoroute-calibrate --stdin")
            && install_sh.contains("make_calibration_tree_kib")
            && install_sh.contains("for file_count in $many_file_counts")
            && install_sh.contains("${file_count} x 4 KiB files workload")
            && install_sh.contains("many-${file_count}x4k")
            && install_sh.contains("decode-heavy 256 KiB workload")
            && install_sh.contains("make_decode_heavy_calibration_probe_kib")
            && install_sh.contains("plain_calibration_block")
            && install_sh.contains("decode_heavy_calibration_block")
            && install_sh.contains("git_calibration=1")
            && install_sh.contains("make_calibration_git_repo")
            && install_sh.contains("run_autoroute_git_history_probe")
            && install_sh.contains("run_autoroute_git_blobs_probe")
            && install_sh.contains("run_autoroute_git_diff_probe")
            && install_sh.contains("git history 4 KiB source workload")
            && install_sh.contains("git blobs head/history source workload")
            && install_sh.contains("git diff 12 KiB source workload")
            && install_sh.contains("docker_calibration=1")
            && install_sh.contains("docker_daemon_ready")
            && install_sh.contains("make_calibration_docker_image")
            && install_sh.contains("run_autoroute_docker_image_probe")
            && install_sh.contains("docker image 4 KiB source workload")
            && install_sh.contains("web_calibration=1")
            && install_sh.contains("make_calibration_web_fixture")
            && install_sh.contains("start_calibration_web_server")
            && install_sh.contains("run_autoroute_url_probe")
            && install_sh.contains("web URL 4 KiB source workload")
            && install_sh.contains("--git-history")
            && install_sh.contains("--git-blobs")
            && install_sh.contains("--git-diff")
            && install_sh.contains("--git-diff-path")
            && install_sh.contains("--url")
            && install_sh.contains("--docker-image")
            && install_sh.contains("git was not found on PATH")
            && install_sh.contains("python3/python was not found on PATH")
            && install_sh.contains("docker was not found on PATH")
            && install_sh.contains("Docker daemon is not responding")
            && install_sh.contains("--autoroute-calibrate")
            && !install_sh.contains("KEYHOG_AUTOROUTE_CALIBRATE")
            && install_sh.contains("--batch-pipeline")
            && !install_sh.contains("KEYHOG_BATCH_PIPELINE")
            && install_sh.contains("--autoroute-gpu")
            && !install_sh.contains("KEYHOG_GPU_AUTOROUTE")
            && install_sh.contains("failed=0")
            && install_sh.contains("return 1")
            && install_sh.contains("persisted auto routing was not updated")
            && !install_sh.contains("dd if=/dev/zero")
            && !install_sh.contains("existing records remain in place"),
        "install.sh must run a visible multi-workload autoroute calibration phase with representative plain and decode-heavy workloads, and failures must fail the install/calibrate command"
    );
    assert!(
        install_ps1.contains("Invoke-AutorouteCalibration")
            && install_ps1.contains("-Calibrate")
            && install_ps1.contains("Autoroute calibration")
            && install_ps1.contains("TotalMilliseconds")
            && install_ps1.contains("PASS {0} ({1}ms)")
            && install_ps1.contains("FAIL {0} ({1}ms)")
            && install_ps1.contains("@(4, 64)")
            && install_ps1.contains("@(1, 8, 32)")
            && install_ps1.contains("@(4, 16, 32)")
            && install_ps1.contains("empty stdin workload")
            && install_ps1.contains("stdin 64 KiB workload")
            && install_ps1.contains("Mode = 'stdin'")
            && install_ps1.contains("'scan', '--stdin'")
            && install_ps1.contains("RedirectStandardInput")
            && install_ps1.contains("New-CalibrationTreeKiB")
            && install_ps1.contains("foreach ($fileCount in @(4, 16, 32))")
            && install_ps1.contains("${fileCount} x 4 KiB files workload")
            && install_ps1.contains("many-${fileCount}x4k")
            && install_ps1.contains("decode-heavy 256 KiB workload")
            && install_ps1.contains("New-DecodeHeavyCalibrationProbeKiB")
            && install_ps1.contains("New-PlainCalibrationBlock")
            && install_ps1.contains("New-DecodeHeavyCalibrationBlock")
            && install_ps1.contains("$gitCalibration = $true")
            && install_ps1.contains("New-CalibrationGitRepository")
            && install_ps1.contains("git history 4 KiB source workload")
            && install_ps1.contains("git blobs head/history source workload")
            && install_ps1.contains("git diff 12 KiB source workload")
            && install_ps1.contains("$dockerCalibration = $true")
            && install_ps1.contains("Test-DockerDaemonResponsive")
            && install_ps1.contains("New-CalibrationDockerImage")
            && install_ps1.contains("docker image 4 KiB source workload")
            && install_ps1.contains("$webCalibration = $true")
            && install_ps1.contains("New-CalibrationWebFixture")
            && install_ps1.contains("Start-CalibrationWebServer")
            && install_ps1.contains("web URL 4 KiB source workload")
            && install_ps1.contains("'git-history'")
            && install_ps1.contains("'git-blobs'")
            && install_ps1.contains("'git-diff'")
            && install_ps1.contains("'url'")
            && install_ps1.contains("'docker-image'")
            && install_ps1.contains("'--git-history'")
            && install_ps1.contains("'--git-blobs'")
            && install_ps1.contains("'--git-diff'")
            && install_ps1.contains("'--git-diff-path'")
            && install_ps1.contains("'--url'")
            && install_ps1.contains("'--docker-image'")
            && install_ps1.contains("git was not found on PATH")
            && install_ps1.contains("docker was not found on PATH")
            && install_ps1.contains("Docker daemon is not responding")
            && install_ps1.contains("'--autoroute-calibrate'")
            && !install_ps1.contains("KEYHOG_AUTOROUTE_CALIBRATE")
            && install_ps1.contains("'--batch-pipeline'")
            && !install_ps1.contains("KEYHOG_BATCH_PIPELINE")
            && install_ps1.contains("'--autoroute-gpu'")
            && !install_ps1.contains("KEYHOG_GPU_AUTOROUTE")
            && install_ps1.contains("$failed = $false")
            && install_ps1.contains("return $false")
            && install_ps1.contains("persisted auto routing was not updated")
            && !install_ps1.contains("'a' * 1024")
            && !install_ps1.contains("'a' * 1048576")
            && !install_ps1.contains("existing records remain in place"),
        "install.ps1 must run a visible multi-workload autoroute calibration phase with representative plain and decode-heavy workloads, and failures must fail the install/calibrate command"
    );
    assert!(
        readme_text.contains("visible autoroute")
            && readme_text.contains("calibration phase")
            && readme_text.contains("Normal scans")
            && readme_text.contains("do not benchmark candidates")
            && readme_text.contains("repeated parity-checked trials")
            && readme_text.contains("Invalid existing cache records are rejected")
            && readme_text.contains("resolved scan-config digest")
            && readme_text.contains("batch-pipeline route")
            && readme_text.contains("explicit calibration controls")
            && readme_text.contains("install.sh --calibrate")
            && readme_text.contains("install.ps1 -Calibrate")
            && env_ref_text.contains("visible calibration phase")
            && env_ref_text.contains("keyhog scan --autoroute-calibrate")
            && env_ref_text.contains("Normal scans never benchmark on cache miss")
            && env_ref_text.contains("fastest-correct decisions")
            && !env_ref_text.contains("KEYHOG_AUTOROUTE_CALIBRATE"),
        "README and env reference must state the persistent install-time autoroute calibration contract"
    );
}
