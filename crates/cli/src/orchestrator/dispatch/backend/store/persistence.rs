//! Locked, atomic persistence and multi-configuration cache merging.

use std::collections::{BTreeMap, HashMap};

use super::super::evidence::AutorouteDecision;
use super::super::host::AutorouteHostProfile;
use super::super::workload::{
    validate_workload_source_mixture, workload_evidence_digest, WorkloadKey,
};
use super::super::AUTOROUTE_CACHE_VERSION;

/// Operator-relevant effect of a successful cache save.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AutorouteCacheSaveOutcome {
    Fresh,
    Merged,
    Replaced { reason: String },
}

struct MergeableConfigs {
    configs: Vec<AutorouteConfigDecisions>,
    outcome: AutorouteCacheSaveOutcome,
}
use super::artifact_identity::current_executable_sha256;
use super::codec::{
    parse_autoroute_cache, read_autoroute_cache_file, CacheParseError, AUTOROUTE_CACHE_FILE_BYTES,
};
use super::schema::{
    AutorouteBuildFeatures, AutorouteCache, AutorouteConfigDecisions, PersistedAutorouteDecision,
};
use super::validation::{
    validate_cache_global_identity, validate_cache_structure, validate_decision_route_evidence,
    validate_decision_workload_binding,
};

pub(crate) fn load_autoroute_cache(
    path: &std::path::Path,
    detector_digest: u64,
    rules_digest: &str,
    config_digest: u64,
    host_profile: &AutorouteHostProfile,
) -> Result<HashMap<WorkloadKey, AutorouteDecision>, Box<dyn std::error::Error + Send + Sync>> {
    let data = read_autoroute_cache_file(path)?;
    let cache = match parse_autoroute_cache(&data) {
        Ok(cache) => cache,
        Err(error) => return Err(error.diagnostic().into()),
    };
    host_profile.require_exact_identity()?;
    validate_cache_global_identity(&cache, detector_digest, rules_digest)?;
    validate_cache_structure(&cache)?;
    let matching_config_count = cache
        .configs
        .iter()
        .filter(|config| config.config_digest == config_digest)
        .count();
    if matching_config_count == 0 {
        return Err(format!(
            "scan config digest mismatch; cache is for a different resolved scan config \
             (this binary/corpus has {} calibrated config(s), none matching config \
             digest {config_digest:016x}); calibrate this scan config",
            cache.configs.len()
        )
        .into());
    }
    let Some(config) = cache
        .configs
        .iter()
        .find(|config| config.matches_generation(config_digest, host_profile))
    else {
        return Err(format!(
            "host profile mismatch for scan config {config_digest:016x}; the cache has \
             {matching_config_count} generation(s) for different hardware or accelerator \
             peers. Calibrate this scan config on the current host"
        )
        .into());
    };
    Ok(config
        .decisions
        .iter()
        .map(|row| (row.workload.clone(), row.decision.clone()))
        .collect())
}

pub(crate) fn save_autoroute_cache(
    path: &std::path::Path,
    detector_digest: u64,
    rules_digest: &str,
    config_digest: u64,
    host_profile: &AutorouteHostProfile,
    decisions: &HashMap<WorkloadKey, AutorouteDecision>,
) -> Result<AutorouteCacheSaveOutcome, Box<dyn std::error::Error + Send + Sync>> {
    host_profile.require_exact_identity()?;
    let expected_backends = host_profile.candidate_backend_set()?;
    if decisions.is_empty() {
        return Err("autoroute cache contains no workload decisions".into());
    }
    for (key, decision) in decisions {
        validate_workload_source_mixture(key).map_err(|error| {
            format!("autoroute cache save rejected an invalid source mixture: {error}")
        })?;
        validate_decision_route_evidence(decision, &expected_backends)?;
        validate_decision_workload_binding(key, decision)?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _write_lock = keyhog_core::StateFileWriteLock::acquire(path)?;

    let mergeable = read_mergeable_configs(path, detector_digest, rules_digest)?;
    let mut configs = mergeable.configs;
    let outcome = mergeable.outcome;
    let mut merged = BTreeMap::new();
    if let Some(prior) = configs
        .iter()
        .find(|config| config.matches_generation(config_digest, host_profile))
    {
        merged.extend(
            prior
                .decisions
                .iter()
                .map(|row| (row.workload.clone(), row.decision.clone())),
        );
    }
    merged.extend(
        decisions
            .iter()
            .map(|(key, decision)| (key.clone(), decision.clone())),
    );
    configs.retain(|config| !config.matches_generation(config_digest, host_profile));
    configs.push(AutorouteConfigDecisions {
        config_digest,
        host: host_profile.clone(),
        decisions: merged
            .into_iter()
            .map(|(workload, decision)| PersistedAutorouteDecision {
                workload_digest: workload_evidence_digest(&workload),
                workload,
                decision,
            })
            .collect(),
    });
    configs.sort_by(|left, right| {
        left.config_digest
            .cmp(&right.config_digest)
            .then_with(|| left.host.cmp(&right.host))
    });

    let cache = AutorouteCache {
        version: AUTOROUTE_CACHE_VERSION,
        binary_version: env!("CARGO_PKG_VERSION").to_string(),
        git_hash: keyhog_core::git_hash().to_string(),
        executable_sha256: current_executable_sha256()?.to_string(),
        build_features: AutorouteBuildFeatures::current(),
        detector_digest,
        rules_digest: rules_digest.to_string(),
        configs,
    };
    validate_cache_structure(&cache)?;
    let serialized = serde_json::to_vec_pretty(&cache)?;
    if serialized.len() as u64 > AUTOROUTE_CACHE_FILE_BYTES {
        return Err(format!(
            "autoroute cache would be {} bytes, exceeding the {} byte read limit; \
             select a fresh cache path and recalibrate the active scan configurations",
            serialized.len(),
            AUTOROUTE_CACHE_FILE_BYTES
        )
        .into());
    }
    crate::atomic_file::write_bytes(path, &serialized)?;
    Ok(outcome)
}

fn read_mergeable_configs(
    path: &std::path::Path,
    detector_digest: u64,
    rules_digest: &str,
) -> Result<MergeableConfigs, Box<dyn std::error::Error + Send + Sync>> {
    let data = match read_autoroute_cache_file(path) {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(MergeableConfigs {
                configs: Vec::new(),
                outcome: AutorouteCacheSaveOutcome::Fresh,
            });
        }
        Err(error) => {
            return Err(format!(
                "cannot merge autoroute calibration because the existing cache at {} is unreadable: {error}; no cache bytes were replaced. Fix the path permissions or storage error and retry",
                path.display()
            )
            .into());
        }
    };
    let cache = match parse_autoroute_cache(&data) {
        Ok(cache) => cache,
        Err(error @ CacheParseError::Version { .. }) => {
            tracing::info!(
                target: "keyhog::routing",
                path = %path.display(),
                diagnostic = %error.diagnostic(),
                expected_version = AUTOROUTE_CACHE_VERSION,
                "existing autoroute cache is an older schema; superseding it with this build's calibration"
            );
            return Ok(replacement(error.diagnostic()));
        }
        Err(error @ CacheParseError::NotJson(_)) => {
            tracing::warn!(
                target: "keyhog::routing",
                path = %path.display(),
                diagnostic = %error.diagnostic(),
                "existing autoroute cache is not valid cache JSON; replacing it with a fresh calibration"
            );
            return Ok(replacement(error.diagnostic()));
        }
        Err(error @ CacheParseError::Payload(_)) => {
            tracing::warn!(
                target: "keyhog::routing",
                path = %path.display(),
                diagnostic = %error.diagnostic(),
                "existing autoroute cache failed to deserialize; replacing it with a fresh calibration"
            );
            return Ok(replacement(error.diagnostic()));
        }
    };
    if let Err(error) = validate_cache_global_identity(&cache, detector_digest, rules_digest) {
        tracing::info!(
            target: "keyhog::routing",
            path = %path.display(),
            %error,
            "existing autoroute cache is for a different build or corpus; superseding it with this build's calibration"
        );
        return Ok(replacement(format!(
            "existing cache identity does not match this build or detector corpus: {error}"
        )));
    }
    if let Err(error) = validate_cache_structure(&cache) {
        tracing::warn!(
            target: "keyhog::routing",
            path = %path.display(),
            %error,
            "existing autoroute cache has invalid structure or decision evidence; replacing it with a fresh calibration"
        );
        return Ok(replacement(format!(
            "existing cache structure or route evidence is invalid: {error}"
        )));
    }
    Ok(MergeableConfigs {
        configs: cache.configs,
        outcome: AutorouteCacheSaveOutcome::Merged,
    })
}

fn replacement(reason: String) -> MergeableConfigs {
    MergeableConfigs {
        configs: Vec::new(),
        outcome: AutorouteCacheSaveOutcome::Replaced { reason },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::dispatch::backend::host::{host_identity_digest, render_host_profile};
    use crate::orchestrator::dispatch::backend::store::inspection::inspect_autoroute_cache;
    use crate::orchestrator::dispatch::backend::workload::{
        autoroute_stable_bucket, source_class_id, Phase1AdmissionKey, SourceMixtureEntry,
        SourceMixtureKey,
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
            phase1: Phase1AdmissionKey {
                alphabet_rejected_chunks_bucket: 0,
                alphabet_rejected_bytes_bucket: 0,
                bigram_rejected_chunks_bucket: 0,
                bigram_rejected_bytes_bucket: 0,
                admitted_chunks_bucket: autoroute_stable_bucket(1),
                admitted_bytes_bucket: bytes_bucket,
            },
            decode_kind_mask: 0,
            decode_candidate_count_bucket: 0,
            decode_candidate_bytes_bucket: 0,
            decode_unknown: false,
            source_mixture: SourceMixtureKey {
                entries: vec![SourceMixtureEntry {
                    source_class_digest: source_class_id("filesystem"),
                    has_full_size: true,
                    chunk_ratio: 1,
                    payload_ratio: 1,
                    max_span_bucket: bytes_bucket,
                }],
            },
        }
    }

    fn decisions(
        bytes: u64,
        host: &AutorouteHostProfile,
    ) -> HashMap<WorkloadKey, AutorouteDecision> {
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
                    .expect_err(
                        "GPU-auto evidence must not replay under disabled-GPU host identity",
                    );
            assert!(auto_under_disabled
                .to_string()
                .contains("host profile mismatch"));
            let disabled_under_auto =
                load_autoroute_cache(&path, DETECTOR_DIGEST, RULES_DIGEST, 0xa003, &gpu)
                    .expect_err(
                        "disabled-GPU evidence must not replay under GPU-auto host identity",
                    );
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

        let error =
            load_autoroute_cache(&path, DETECTOR_DIGEST, RULES_DIGEST, config_digest, &host)
                .expect_err("cache-global host schema must not migrate silently");
        let message = error.to_string();
        assert!(message.contains("unsupported autoroute cache version"));
        assert!(message.contains(&(AUTOROUTE_CACHE_VERSION - 1).to_string()));
    }
}
