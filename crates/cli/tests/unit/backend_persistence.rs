use super::*;
use crate::orchestrator::dispatch::backend::host::{host_identity_digest, render_host_profile};
use crate::orchestrator::dispatch::backend::runtime_health::{
    inspect_runtime_route_faults, persist_runtime_route_fault, RuntimeHealthIdentity,
};
use crate::orchestrator::dispatch::backend::store::inspection::inspect_autoroute_cache;
use crate::orchestrator::dispatch::backend::workload::{
    autoroute_stable_bucket, render_workload_key, source_class_id,
    SourceMixtureEntry, SourceMixtureKey,
};
use keyhog_scanner::ScanBackend;

const DETECTOR_DIGEST: u64 = 0x1234_5678_9abc_def0;
const RULES_DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn cpu_host() -> AutorouteHostProfile {
    AutorouteHostProfile {
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
        cpu_model: Some("test-cpu".to_string()),
        physical_cores: 8,
        logical_cores: 16,
        has_avx2: true,
        has_avx512: false,
        has_neon: false,
        hyperscan_available: true,
        hyperscan_runtime_identity: Some("hyperscan-test-runtime-5.4.2".to_string()),
        gpu_name: None,
        gpu_runtime_backend: None,
        gpu_driver_runtime_identity: None,
        gpu_batch_input_limit_bytes: None,
        gpu_is_software: false,
        total_memory_mb: Some(65_536),
        eligible_backends: vec![
            ScanBackend::CpuFallback.label().to_string(),
            ScanBackend::SimdCpu.label().to_string(),
        ],
    }
}

fn gpu_host(device: &str, runtime: &str) -> AutorouteHostProfile {
    let mut host = cpu_host();
    host.gpu_name = Some(device.to_string());
    let identity = format!("gpu-wgpu-region-presence:{runtime}:{device}");
    host.gpu_runtime_backend = Some(identity.clone());
    host.gpu_driver_runtime_identity = Some(identity);
    host.gpu_batch_input_limit_bytes = Some(512 * 1024 * 1024);
    host.eligible_backends = vec![
        ScanBackend::CpuFallback.label().to_string(),
        ScanBackend::GpuWgpu.label().to_string(),
        ScanBackend::SimdCpu.label().to_string(),
    ];
    host
}

fn workload(bytes: u64) -> WorkloadKey {
    let bytes_bucket = autoroute_stable_bucket(bytes);
    WorkloadKey {
        bytes_bucket,
        chunks_bucket: autoroute_stable_bucket(1),
        max_file_bucket: bytes_bucket,
        pattern_bucket: autoroute_stable_bucket(1),
        decode_admitted: false,
        source_mixture: SourceMixtureKey {
            entries: vec![SourceMixtureEntry {
                source_class_digest: source_class_id("filesystem"),
                has_full_size: true,
            }],
        },
    }
}

fn decisions(bytes: u64, host: &AutorouteHostProfile) -> HashMap<WorkloadKey, AutorouteDecision> {
    let gpu_ms = host
        .eligible_backends
        .iter()
        .any(|label| label == ScanBackend::GpuWgpu.label())
        .then_some(24);
    HashMap::from([(
        workload(bytes),
        AutorouteDecision::new(ScanBackend::SimdCpu, bytes, 1, 12, Some(20), gpu_ms),
    )])
}

/// Regression: an unreadable live cache must fail closed without publishing replacement state.
#[test]
fn unreadable_existing_cache_aborts_merge_without_replacement_state() {
    let directory = tempfile::tempdir().expect("create unreadable cache stand-in");
    let result = read_mergeable_configs(directory.path(), DETECTOR_DIGEST, RULES_DIGEST);
    let error = match result {
        Ok(_) => panic!("an unreadable existing cache must not become replacement input"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("existing cache"), "diagnostic: {error}");
    assert!(
        error.contains("no cache bytes were replaced"),
        "diagnostic must make the preservation contract explicit: {error}"
    );
    assert!(
        directory.path().is_dir(),
        "failed merge must leave the existing filesystem object untouched"
    );
}

/// Regression: staging a calibration generation must leave the live cache unchanged until publication.
#[test]
fn staged_generation_does_not_touch_live_cache_until_publish() {
    let directory = tempfile::tempdir().expect("autoroute transaction directory");
    let live = directory.path().join("autoroute.json");
    let staged = directory.path().join("staged.json");
    let host = cpu_host();
    save_autoroute_cache(
        &live,
        DETECTOR_DIGEST,
        RULES_DIGEST,
        0xc001,
        &host,
        &decisions(4 * 1024, &host),
    )
    .expect("seed live cache");
    let baseline = std::fs::read(&live).expect("read live baseline");

    let transaction = StagedAutorouteCache::begin(&live, &staged).expect("begin staged generation");
    save_autoroute_cache(
        transaction.staged_path(),
        DETECTOR_DIGEST,
        RULES_DIGEST,
        0xc002,
        &host,
        &decisions(8 * 1024, &host),
    )
    .expect("write completed probe into staged cache");
    assert_eq!(
        std::fs::read(&live).expect("read untouched live cache"),
        baseline,
        "successful intermediate probes must not publish partial evidence"
    );

    transaction
        .publish(&BTreeSet::new())
        .expect("publish complete generation");
    load_autoroute_cache(&live, DETECTOR_DIGEST, RULES_DIGEST, 0xc001, &host)
        .expect("original config survives staged merge");
    load_autoroute_cache(&live, DETECTOR_DIGEST, RULES_DIGEST, 0xc002, &host)
        .expect("completed staged config publishes atomically");
}

/// Regression: optimistic publication must preserve a concurrent live-cache update instead of overwriting it.
#[test]
fn concurrent_live_update_prevents_staged_generation_from_overwriting_it() {
    let directory = tempfile::tempdir().expect("autoroute conflict directory");
    let live = directory.path().join("autoroute.json");
    let staged = directory.path().join("staged.json");
    let host = cpu_host();
    save_autoroute_cache(
        &live,
        DETECTOR_DIGEST,
        RULES_DIGEST,
        0xd001,
        &host,
        &decisions(4 * 1024, &host),
    )
    .expect("seed live cache");

    let transaction = StagedAutorouteCache::begin(&live, &staged).expect("begin staged generation");
    save_autoroute_cache(
        transaction.staged_path(),
        DETECTOR_DIGEST,
        RULES_DIGEST,
        0xd002,
        &host,
        &decisions(8 * 1024, &host),
    )
    .expect("write staged generation");
    save_autoroute_cache(
        &live,
        DETECTOR_DIGEST,
        RULES_DIGEST,
        0xd003,
        &host,
        &decisions(16 * 1024, &host),
    )
    .expect("simulate concurrent live calibration");
    let concurrent_bytes = std::fs::read(&live).expect("read concurrent live update");

    let error = transaction
        .publish(&BTreeSet::new())
        .expect_err("stale staged baseline must not overwrite a concurrent writer")
        .to_string();
    assert!(error.contains("changed while calibration was running"));
    assert_eq!(
        std::fs::read(&live).expect("read preserved live update"),
        concurrent_bytes,
        "publish conflict must leave the live cache byte-identical"
    );
    load_autoroute_cache(&live, DETECTOR_DIGEST, RULES_DIGEST, 0xd003, &host)
        .expect("concurrent config remains usable");
    assert!(
        load_autoroute_cache(&live, DETECTOR_DIGEST, RULES_DIGEST, 0xd002, &host).is_err(),
        "staged-only config must not leak into the live cache on conflict"
    );
}

/// Regression: optimistic publication must preserve runtime faults recorded after calibration staging began.
#[test]
fn concurrent_runtime_fault_prevents_staged_generation_from_clearing_it() {
    let directory = tempfile::tempdir().expect("autoroute health conflict directory");
    let live = directory.path().join("autoroute.json");
    let staged = directory.path().join("staged.json");
    let host = cpu_host();
    let route_workload = workload(4 * 1024);
    save_autoroute_cache(
        &live,
        DETECTOR_DIGEST,
        RULES_DIGEST,
        0xe001,
        &host,
        &decisions(4 * 1024, &host),
    )
    .expect("seed live cache");
    let live_baseline = std::fs::read(&live).expect("read live baseline");

    let transaction = StagedAutorouteCache::begin(&live, &staged).expect("begin staged generation");
    save_autoroute_cache(
        transaction.staged_path(),
        DETECTOR_DIGEST,
        RULES_DIGEST,
        0xe002,
        &host,
        &decisions(8 * 1024, &host),
    )
    .expect("write staged generation");
    let identity = RuntimeHealthIdentity::new(&live, 0xe001, host_identity_digest(&host));
    persist_runtime_route_fault(
        &identity,
        &route_workload,
        ScanBackend::SimdCpu.label(),
        "injected runtime failure during calibration",
    )
    .expect("persist concurrent runtime fault");

    let error = transaction
        .publish(&BTreeSet::from([(
            format!("{:016x}", 0xe001_u64),
            host_identity_digest(&host),
            render_workload_key(&route_workload),
        )]))
        .expect_err("concurrent runtime fault must block stale publication")
        .to_string();
    assert!(error.contains("runtime health"));
    assert_eq!(
        std::fs::read(&live).expect("read preserved cache"),
        live_baseline,
        "a concurrent fault must leave the live calibration byte-identical"
    );
}

/// Regression: a completed sweep may clear faults only for routes whose evidence it actually refreshed.
#[test]
fn completed_generation_clears_only_faults_for_routes_measured_by_the_sweep() {
    let directory = tempfile::tempdir().expect("autoroute health filtering directory");
    let live = directory.path().join("autoroute.json");
    let staged = directory.path().join("staged.json");
    let host = cpu_host();
    let measured_workload = workload(4 * 1024);
    let unrelated_workload = workload(8 * 1024);
    let mut both_decisions = decisions(4 * 1024, &host);
    both_decisions.extend(decisions(8 * 1024, &host));
    save_autoroute_cache(
        &live,
        DETECTOR_DIGEST,
        RULES_DIGEST,
        0xe101,
        &host,
        &both_decisions,
    )
    .expect("seed live cache");
    let identity = RuntimeHealthIdentity::new(&live, 0xe101, host_identity_digest(&host));
    for (workload, reason) in [
        (&measured_workload, "remeasured route fault"),
        (&unrelated_workload, "unrelated route fault"),
    ] {
        persist_runtime_route_fault(&identity, workload, ScanBackend::SimdCpu.label(), reason)
            .expect("persist route fault");
    }

    let transaction = StagedAutorouteCache::begin(&live, &staged).expect("begin staged generation");
    save_autoroute_cache(
        transaction.staged_path(),
        DETECTOR_DIGEST,
        RULES_DIGEST,
        0xe101,
        &host,
        &decisions(4 * 1024, &host),
    )
    .expect("remeasure one route in staged generation");
    transaction
        .publish(&BTreeSet::from([(
            format!("{:016x}", 0xe101_u64),
            host_identity_digest(&host),
            render_workload_key(&measured_workload),
        )]))
        .expect("publish staged generation and matching health update");

    let faults = inspect_runtime_route_faults(&live).expect("inspect filtered health");
    assert_eq!(faults.len(), 1);
    assert_eq!(faults[0].workload, unrelated_workload);
    assert_eq!(faults[0].reason, "unrelated route fault");
}

/// Regression: GPU policy variants must coexist and replay the exact host regardless of write order.
#[test]
fn gpu_policy_configs_coexist_and_replay_exact_hosts_in_both_write_orders() {
    let gpu = gpu_host("NVIDIA RTX 5090", "cuda-580.95");
    let cpu = cpu_host();
    let configs = [
        (0xa001, &gpu),
        (0xa002, &gpu),
        (0xa003, &cpu),
        (0xa004, &cpu),
    ];

    for reverse in [false, true] {
        let directory = tempfile::tempdir().expect("autoroute policy cache directory");
        let path = directory.path().join("autoroute.json");
        let ordered = if reverse {
            configs.iter().rev().copied().collect::<Vec<_>>()
        } else {
            configs.to_vec()
        };
        for (config_digest, host) in ordered {
            save_autoroute_cache(
                &path,
                DETECTOR_DIGEST,
                RULES_DIGEST,
                config_digest,
                host,
                &decisions(8 * 1024 * 1024, host),
            )
            .expect("each GPU policy config must persist");
        }

        let cache: AutorouteCache = serde_json::from_slice(
            &std::fs::read(&path).expect("read multi-policy autoroute cache"),
        )
        .expect("deserialize multi-policy autoroute cache");
        assert_eq!(cache.version, AUTOROUTE_CACHE_VERSION);
        assert_eq!(cache.configs.len(), configs.len());
        assert!(
            serde_json::to_value(&cache)
                .expect("serialize cache shape")
                .get("host")
                .is_none(),
            "schema must not retain a cache-global projected host"
        );

        for (config_digest, host) in configs {
            let loaded =
                load_autoroute_cache(&path, DETECTOR_DIGEST, RULES_DIGEST, config_digest, host)
                    .expect("config must replay under its exact projected host");
            assert_eq!(loaded.len(), 1);
        }

        let auto_under_disabled =
            load_autoroute_cache(&path, DETECTOR_DIGEST, RULES_DIGEST, 0xa001, &cpu)
                .expect_err("GPU-auto evidence must not replay under disabled-GPU host identity");
        assert!(auto_under_disabled
            .to_string()
            .contains("host profile mismatch"));
        let disabled_under_auto =
            load_autoroute_cache(&path, DETECTOR_DIGEST, RULES_DIGEST, 0xa003, &gpu)
                .expect_err("disabled-GPU evidence must not replay under GPU-auto host identity");
        assert!(disabled_under_auto
            .to_string()
            .contains("host profile mismatch"));

        let inspection = inspect_autoroute_cache(Some(&path));
        assert_eq!(inspection.configs.len(), configs.len());
        assert_eq!(
            inspection.host, None,
            "a cache with distinct projected hosts must not publish a misleading global host"
        );
        for config in inspection.configs {
            assert!(
                !config.host.trim().is_empty(),
                "inspection must render host identity for config {}",
                config.config_digest
            );
        }
    }
}

/// Regression: cache inspection must retain the common-host projection expected by v31 JSON consumers.
#[test]
fn inspection_projects_a_common_host_for_v31_json_consumers() {
    let directory = tempfile::tempdir().expect("autoroute common-host directory");
    let path = directory.path().join("autoroute.json");
    let host = gpu_host("NVIDIA RTX 5090", "cuda-580.95");

    for config_digest in [0xa101, 0xa102] {
        save_autoroute_cache(
            &path,
            DETECTOR_DIGEST,
            RULES_DIGEST,
            config_digest,
            &host,
            &decisions(8 * 1024 * 1024, &host),
        )
        .expect("persist same-host config");
    }

    let inspection = inspect_autoroute_cache(Some(&path));
    assert_eq!(inspection.configs.len(), 2);
    assert_eq!(
        inspection.host.as_deref(),
        Some(render_host_profile(&host).as_str()),
        "the deprecated root projection remains exact when every config shares one host"
    );
}

/// Regression: hosts sharing one configuration must retain independent calibration generations.
#[test]
fn same_config_hosts_coexist_and_recalibrate_independently() {
    let directory = tempfile::tempdir().expect("autoroute multi-host directory");
    let path = directory.path().join("autoroute.json");
    let old_gpu = gpu_host("NVIDIA RTX 5090", "cuda-580.95");
    let mut new_gpu = old_gpu.clone();
    new_gpu.total_memory_mb = Some(131_072);
    assert_eq!(
        render_host_profile(&old_gpu),
        render_host_profile(&new_gpu),
        "the exact persistence key must not depend on the lossy display label"
    );
    assert_ne!(
        host_identity_digest(&old_gpu),
        host_identity_digest(&new_gpu),
        "the inspection identity must include every exact host field"
    );
    let cpu = cpu_host();
    let shared_config = 0xb001;
    let unrelated_config = 0xb002;

    save_autoroute_cache(
        &path,
        DETECTOR_DIGEST,
        RULES_DIGEST,
        shared_config,
        &old_gpu,
        &decisions(8 * 1024 * 1024, &old_gpu),
    )
    .expect("seed first host generation");
    save_autoroute_cache(
        &path,
        DETECTOR_DIGEST,
        RULES_DIGEST,
        unrelated_config,
        &cpu,
        &decisions(8 * 1024 * 1024, &cpu),
    )
    .expect("seed unrelated CPU config generation");
    let second_host = save_autoroute_cache(
        &path,
        DETECTOR_DIGEST,
        RULES_DIGEST,
        shared_config,
        &new_gpu,
        &decisions(16 * 1024 * 1024, &new_gpu),
    )
    .expect("persist second host generation for the same config");
    assert_eq!(second_host, AutorouteCacheSaveOutcome::Merged);

    let unrelated =
        load_autoroute_cache(&path, DETECTOR_DIGEST, RULES_DIGEST, unrelated_config, &cpu)
            .expect("unrelated config must survive same-config host additions");
    assert!(unrelated.contains_key(&workload(8 * 1024 * 1024)));

    let first = load_autoroute_cache(
        &path,
        DETECTOR_DIGEST,
        RULES_DIGEST,
        shared_config,
        &old_gpu,
    )
    .expect("first host generation must remain replayable");
    assert_eq!(first.len(), 1);
    assert!(first.contains_key(&workload(8 * 1024 * 1024)));

    let second = load_autoroute_cache(
        &path,
        DETECTOR_DIGEST,
        RULES_DIGEST,
        shared_config,
        &new_gpu,
    )
    .expect("second host generation must replay independently");
    assert_eq!(second.len(), 1);
    assert!(second.contains_key(&workload(16 * 1024 * 1024)));

    save_autoroute_cache(
        &path,
        DETECTOR_DIGEST,
        RULES_DIGEST,
        shared_config,
        &old_gpu,
        &HashMap::new(),
    )
    .expect_err("missing decisions cannot mutate either host generation");

    save_autoroute_cache(
        &path,
        DETECTOR_DIGEST,
        RULES_DIGEST,
        shared_config,
        &old_gpu,
        &decisions(32 * 1024 * 1024, &old_gpu),
    )
    .expect("recalibrate first host without replacing second host");

    let first = load_autoroute_cache(
        &path,
        DETECTOR_DIGEST,
        RULES_DIGEST,
        shared_config,
        &old_gpu,
    )
    .expect("recalibrated first host must replay its merged rows");
    assert_eq!(first.len(), 2);
    assert!(first.contains_key(&workload(8 * 1024 * 1024)));
    assert!(first.contains_key(&workload(32 * 1024 * 1024)));

    let second = load_autoroute_cache(
        &path,
        DETECTOR_DIGEST,
        RULES_DIGEST,
        shared_config,
        &new_gpu,
    )
    .expect("recalibrating first host must preserve second host");
    assert_eq!(second.len(), 1);
    assert!(second.contains_key(&workload(16 * 1024 * 1024)));

    save_autoroute_cache(
        &path,
        DETECTOR_DIGEST,
        RULES_DIGEST,
        shared_config,
        &new_gpu,
        &decisions(64 * 1024 * 1024, &new_gpu),
    )
    .expect("recalibrate second host without replacing first host");

    let second = load_autoroute_cache(
        &path,
        DETECTOR_DIGEST,
        RULES_DIGEST,
        shared_config,
        &new_gpu,
    )
    .expect("recalibrated second host must replay its merged rows");
    assert_eq!(second.len(), 2);
    assert!(second.contains_key(&workload(16 * 1024 * 1024)));
    assert!(second.contains_key(&workload(64 * 1024 * 1024)));

    let first = load_autoroute_cache(
        &path,
        DETECTOR_DIGEST,
        RULES_DIGEST,
        shared_config,
        &old_gpu,
    )
    .expect("recalibrating second host must preserve first host");
    assert_eq!(first.len(), 2);
    assert!(first.contains_key(&workload(8 * 1024 * 1024)));
    assert!(first.contains_key(&workload(32 * 1024 * 1024)));

    let cache: AutorouteCache =
        serde_json::from_slice(&std::fs::read(&path).expect("read multi-host cache"))
            .expect("deserialize multi-host cache");
    assert_eq!(cache.configs.len(), 3);
    assert_eq!(
        cache
            .configs
            .iter()
            .filter(|config| config.config_digest == shared_config)
            .count(),
        2
    );

    let inspection = inspect_autoroute_cache(Some(&path));
    assert_eq!(inspection.configs.len(), 3);
    assert_eq!(inspection.host, None);
    let shared_inspection = inspection
        .configs
        .iter()
        .filter(|config| config.config_digest == format!("{shared_config:016x}"))
        .collect::<Vec<_>>();
    assert_eq!(shared_inspection.len(), 2);
    assert_ne!(
        shared_inspection[0].host_identity, shared_inspection[1].host_identity,
        "inspection must retain two exact hosts even when display labels collide"
    );
}

/// Regression: the retired cache-global host schema must be rejected rather than silently misread.
#[test]
fn cache_global_host_schema_is_rejected_without_migration() {
    let directory = tempfile::tempdir().expect("old autoroute schema directory");
    let path = directory.path().join("autoroute.json");
    let host = gpu_host("NVIDIA RTX 5090", "cuda-580.95");
    let config_digest = 0xc001;
    save_autoroute_cache(
        &path,
        DETECTOR_DIGEST,
        RULES_DIGEST,
        config_digest,
        &host,
        &decisions(8 * 1024 * 1024, &host),
    )
    .expect("seed current autoroute schema");

    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read current autoroute schema"))
            .expect("parse current autoroute schema");
    document["version"] = serde_json::json!(AUTOROUTE_CACHE_VERSION - 1);
    document["host"] = serde_json::to_value(&host).expect("serialize old global host");
    for config in document["configs"]
        .as_array_mut()
        .expect("current schema configs")
    {
        config
            .as_object_mut()
            .expect("current schema config object")
            .remove("host");
    }
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&document).expect("serialize old autoroute schema"),
    )
    .expect("write old autoroute schema");

    let error = load_autoroute_cache(&path, DETECTOR_DIGEST, RULES_DIGEST, config_digest, &host)
        .expect_err("cache-global host schema must not migrate silently");
    let message = error.to_string();
    assert!(message.contains("unsupported autoroute cache version"));
    assert!(message.contains(&(AUTOROUTE_CACHE_VERSION - 1).to_string()));
}
