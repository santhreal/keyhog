//! Locked, atomic persistence and multi-configuration cache merging.

use anyhow::{anyhow, Context, Result as AnyhowResult};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use super::super::evidence::AutorouteDecision;
use super::super::host::AutorouteHostProfile;
use super::super::runtime_health::{
    filtered_runtime_health_snapshot, runtime_health_path, runtime_health_snapshot,
    write_runtime_health_snapshot,
};
use super::super::workload::{
    validate_workload_source_mixture, workload_evidence_digest, WorkloadKey,
};
use super::super::AUTOROUTE_CACHE_VERSION;
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
    execution_pack_generation:
        Option<crate::execution_pack_install::ExecutionPackGenerationBinding>,
}

/// One complete autoroute sweep staged away from the live cache.
///
/// Calibration can write hundreds of exact workload rows. Keeping those writes
/// on a private path prevents a failed late probe from publishing a hybrid of
/// new and old evidence. Publication compares both live cache and route-health
/// bytes captured at begin time while holding their canonical state-file locks,
/// so a concurrent writer or newly quarantined route is never overwritten.
pub(crate) struct StagedAutorouteCache {
    live_path: PathBuf,
    staged_path: PathBuf,
    baseline: Option<Vec<u8>>,
    runtime_health_path: PathBuf,
    runtime_health_baseline: Option<Vec<u8>>,
}

impl StagedAutorouteCache {
    pub(crate) fn begin(live_path: &Path, staged_path: &Path) -> AnyhowResult<Self> {
        if live_path == staged_path {
            anyhow::bail!("autoroute staging path must differ from the live cache path");
        }
        match std::fs::symlink_metadata(staged_path) {
            Ok(_) => {
                anyhow::bail!(
                    "autoroute staging path {} already exists; refusing to overwrite an unrelated artifact",
                    staged_path.display()
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).context(format!(
                    "inspecting autoroute staging path {}",
                    staged_path.display()
                ));
            }
        }
        let _write_lock = keyhog_core::StateFileWriteLock::acquire(live_path)
            .map_err(|error| anyhow!("{error}"))
            .with_context(|| {
                format!(
                    "acquiring autoroute cache write lock for {}",
                    live_path.display()
                )
            })?;
        let runtime_health_path = runtime_health_path(live_path);
        let _runtime_health_lock = keyhog_core::StateFileWriteLock::acquire(&runtime_health_path)
            .map_err(|error| anyhow!("{error}"))
            .with_context(|| {
                format!(
                    "acquiring autoroute runtime-health write lock for {}",
                    runtime_health_path.display()
                )
            })?;
        let baseline = read_optional_cache_bytes(live_path)
            .map_err(|error| anyhow!("{error}"))
            .with_context(|| format!("reading live autoroute cache {}", live_path.display()))?;
        let runtime_health_baseline = runtime_health_snapshot(live_path)
            .map_err(|error| anyhow!("cannot stage autoroute runtime health: {error}"))?;
        if let Some(bytes) = baseline.as_deref() {
            crate::atomic_file::write_bytes(staged_path, bytes).with_context(|| {
                format!("seeding staged autoroute cache {}", staged_path.display())
            })?;
        }
        Ok(Self {
            live_path: live_path.to_path_buf(),
            staged_path: staged_path.to_path_buf(),
            baseline,
            runtime_health_path,
            runtime_health_baseline,
        })
    }

    pub(crate) fn staged_path(&self) -> &Path {
        &self.staged_path
    }

    pub(crate) fn publish(
        self,
        measured_routes: &BTreeSet<(String, String, String)>,
    ) -> AnyhowResult<()> {
        let staged_bytes = read_autoroute_cache_file(&self.staged_path).with_context(|| {
            format!(
                "cannot publish autoroute calibration because staged cache {} is unreadable; the live cache was not changed",
                self.staged_path.display()
            )
        })?;
        let staged_cache = parse_autoroute_cache(&staged_bytes).map_err(|error| {
            anyhow!(
                "staged autoroute calibration is invalid: {}; the live cache was not changed",
                error.diagnostic()
            )
        })?;
        validate_cache_global_identity(
            &staged_cache,
            staged_cache.detector_digest,
            &staged_cache.rules_digest,
        )
        .map_err(|error| {
            anyhow!(
                "staged autoroute calibration identity is invalid: {error}; the live cache was not changed"
            )
        })?;
        validate_cache_structure(&staged_cache).map_err(|error| {
            anyhow!(
                "staged autoroute calibration structure is invalid: {error}; the live cache was not changed"
            )
        })?;
        let filtered_runtime_health = filtered_runtime_health_snapshot(
            &self.runtime_health_path,
            self.runtime_health_baseline.as_deref(),
            measured_routes,
        )
        .map_err(|error| {
            anyhow!(
                "cannot publish autoroute calibration because runtime health cannot be updated safely: {error}; the live cache was not changed"
            )
        })?;

        let _write_lock = keyhog_core::StateFileWriteLock::acquire(&self.live_path)
            .map_err(|error| anyhow!("{error}"))?;
        let _runtime_health_lock =
            keyhog_core::StateFileWriteLock::acquire(&self.runtime_health_path)
                .map_err(|error| anyhow!("{error}"))?;
        let current =
            read_optional_cache_bytes(&self.live_path).map_err(|error| anyhow!("{error}"))?;
        let current_runtime_health = runtime_health_snapshot(&self.live_path)
            .map_err(|error| anyhow!("cannot verify autoroute runtime health: {error}"))?;
        if current != self.baseline || current_runtime_health != self.runtime_health_baseline {
            anyhow::bail!(
                "autoroute cache or runtime health at {} changed while calibration was running; the completed staged generation was not published and the concurrent live update was preserved. Rerun `keyhog calibrate-autoroute`",
                self.live_path.display()
            );
        }
        crate::atomic_file::write_bytes(&self.live_path, &staged_bytes).with_context(|| {
            format!(
                "publishing staged autoroute cache to {}",
                self.live_path.display()
            )
        })?;
        if let Some(bytes) = filtered_runtime_health.as_deref() {
            write_runtime_health_snapshot(&self.runtime_health_path, bytes).map_err(|error| {
                anyhow!(
                    "the complete autoroute generation was published, but its measured runtime-health faults could not be cleared: {error}; scans remain conservatively quarantined until calibration is rerun"
                )
            })?;
        }
        Ok(())
    }
}

fn read_optional_cache_bytes(
    path: &Path,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    match read_autoroute_cache_file(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

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
pub(crate) fn load_execution_pack_generation_binding(
    path: &Path,
) -> AnyhowResult<Option<crate::execution_pack_install::ExecutionPackGenerationBinding>> {
    let bytes = read_autoroute_cache_file(path)
        .with_context(|| format!("reading autoroute cache {}", path.display()))?;
    let cache = parse_autoroute_cache(&bytes)
        .map_err(|error| anyhow!("invalid autoroute cache: {}", error.diagnostic()))?;
    validate_cache_structure(&cache)
        .map_err(|error| anyhow!("invalid autoroute cache: {error}"))?;
    Ok(cache.execution_pack_generation)
}

pub(crate) fn bind_autoroute_cache_to_execution_packs(
    path: &Path,
    binding: crate::execution_pack_install::ExecutionPackGenerationBinding,
) -> AnyhowResult<()> {
    let _write_lock = keyhog_core::StateFileWriteLock::acquire(path)
        .map_err(|error| anyhow!("{error}"))
        .with_context(|| format!("locking staged autoroute cache {}", path.display()))?;
    let bytes = read_autoroute_cache_file(path)
        .with_context(|| format!("reading staged autoroute cache {}", path.display()))?;
    let mut cache = parse_autoroute_cache(&bytes).map_err(|error| {
        anyhow!(
            "cannot bind execution packs to autoroute cache: {}",
            error.diagnostic()
        )
    })?;
    if let Some(existing) = cache.execution_pack_generation.as_ref() {
        if existing != &binding {
            anyhow::bail!(
                "autoroute cache is already bound to a different execution-pack generation; rebuild packs and recalibrate transactionally"
            );
        }
    }
    let pack_keys = binding
        .packs
        .iter()
        .map(|pack| (pack.policy.as_str(), pack.backend.as_str()))
        .collect::<BTreeSet<_>>();
    for config in &cache.configs {
        for row in &config.decisions {
            let mut backends = vec![row.decision.backend.as_str()];
            backends.extend(
                row.decision
                    .calibration_points
                    .iter()
                    .flat_map(|point| point.route_timings.iter())
                    .map(|timing| timing.backend.as_str()),
            );
            for backend in backends {
                let pack_backend = execution_pack_backend_name(backend).ok_or_else(|| {
                    anyhow!("autoroute decision names unknown backend {backend:?}; refusing pack binding")
                })?;
                for policy in ["default", "fast", "deep", "precision"] {
                    if !pack_keys.contains(&(policy, pack_backend)) {
                        anyhow::bail!(
                            "autoroute backend {backend} has no exact {policy}/{pack_backend} execution pack; rebuild packs before calibration"
                        );
                    }
                }
            }
        }
    }
    cache.execution_pack_generation = Some(binding);
    validate_cache_structure(&cache)
        .map_err(|error| anyhow!("pack-bound autoroute cache is invalid: {error}"))?;
    let serialized =
        serde_json::to_vec(&cache).context("serializing pack-bound autoroute cache")?;
    if serialized.len() as u64 > AUTOROUTE_CACHE_FILE_BYTES {
        anyhow::bail!(
            "pack-bound autoroute cache is {} bytes, above the {} byte cap",
            serialized.len(),
            AUTOROUTE_CACHE_FILE_BYTES
        );
    }
    crate::atomic_file::write_bytes(path, &serialized)
        .with_context(|| format!("writing pack-bound autoroute cache {}", path.display()))
}

fn execution_pack_backend_name(route_backend: &str) -> Option<&'static str> {
    match route_backend {
        "cpu-fallback" => Some("cpu"),
        "simd-regex" => Some("simd"),
        "gpu-cuda-region-presence" => Some("gpu-cuda"),
        "gpu-wgpu-region-presence" => Some("gpu-wgpu"),
        "gpu-metal-region-presence" => Some("gpu-metal"),
        _ => None,
    }
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
    let execution_pack_generation = mergeable.execution_pack_generation;
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
        gpu_sidecar_digest: super::artifact_identity::current_gpu_sidecar_sha256(),
        execution_pack_generation,
        configs,
    };
    validate_cache_structure(&cache)?;
    let serialized = serde_json::to_vec(&cache)?;
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
                execution_pack_generation: None,
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
        execution_pack_generation: cache.execution_pack_generation,
        outcome: AutorouteCacheSaveOutcome::Merged,
    })
}

fn replacement(reason: String) -> MergeableConfigs {
    MergeableConfigs {
        configs: Vec::new(),
        execution_pack_generation: None,
        outcome: AutorouteCacheSaveOutcome::Replaced { reason },
    }
}

#[cfg(test)]
mod contention;

#[cfg(test)]
#[path = "../../../../../tests/unit/backend_persistence.rs"]
mod tests;
