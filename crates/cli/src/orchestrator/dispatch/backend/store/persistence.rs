//! Locked, atomic persistence and multi-configuration cache merging.

use std::collections::{BTreeMap, HashMap};

use super::super::evidence::AutorouteDecision;
use super::super::host::AutorouteHostProfile;
use super::super::workload::{validate_workload_source_mixture, WorkloadKey};
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
use super::schema::{AutorouteBuildFeatures, AutorouteCache, AutorouteConfigDecisions};
use super::validation::{
    validate_cache_shared_identity, validate_cache_structure, validate_decision_route_evidence,
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
        Err(CacheParseError::NotJson(error)) => {
            return Err(format!("autoroute cache is not valid cache JSON: {error}").into());
        }
        Err(CacheParseError::Version { found }) => {
            return Err(format!(
                "unsupported autoroute cache version {found} (this build expects {}); \
                 re-run calibration to regenerate it",
                AUTOROUTE_CACHE_VERSION
            )
            .into());
        }
        Err(CacheParseError::Payload(error)) => return Err(error.into()),
    };
    host_profile.require_exact_identity()?;
    validate_cache_shared_identity(&cache, detector_digest, rules_digest, host_profile)?;
    validate_cache_structure(&cache)?;
    let Some(config) = cache
        .configs
        .iter()
        .find(|config| config.config_digest == config_digest)
    else {
        return Err(format!(
            "scan config digest mismatch; cache is for a different resolved scan config \
             (this binary/host/corpus has {} calibrated config(s), none matching config \
             digest {config_digest:016x}); calibrate this scan config",
            cache.configs.len()
        )
        .into());
    };
    Ok(config.decisions.iter().cloned().collect())
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
    if decisions.is_empty() {
        return Err("autoroute cache contains no workload decisions".into());
    }
    for (key, decision) in decisions {
        validate_workload_source_mixture(key).map_err(|error| {
            format!("autoroute cache save rejected an invalid source mixture: {error}")
        })?;
        validate_decision_route_evidence(decision)?;
        validate_decision_workload_binding(key, decision)?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _write_lock = keyhog_core::StateFileWriteLock::acquire(path)?;

    let mergeable = read_mergeable_configs(path, detector_digest, rules_digest, host_profile);
    let mut configs = mergeable.configs;
    let mut merged = BTreeMap::new();
    if let Some(prior) = configs
        .iter()
        .find(|config| config.config_digest == config_digest)
    {
        merged.extend(prior.decisions.iter().cloned());
    }
    merged.extend(
        decisions
            .iter()
            .map(|(key, decision)| (key.clone(), decision.clone())),
    );
    configs.retain(|config| config.config_digest != config_digest);
    configs.push(AutorouteConfigDecisions {
        config_digest,
        decisions: merged.into_iter().collect(),
    });
    configs.sort_by_key(|config| config.config_digest);

    let cache = AutorouteCache {
        version: AUTOROUTE_CACHE_VERSION,
        binary_version: env!("CARGO_PKG_VERSION").to_string(),
        git_hash: keyhog_core::git_hash().to_string(),
        executable_sha256: current_executable_sha256()?.to_string(),
        build_features: AutorouteBuildFeatures::current(),
        detector_digest,
        rules_digest: rules_digest.to_string(),
        host: host_profile.clone(),
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
    Ok(mergeable.outcome)
}

fn read_mergeable_configs(
    path: &std::path::Path,
    detector_digest: u64,
    rules_digest: &str,
    host_profile: &AutorouteHostProfile,
) -> MergeableConfigs {
    if !path.exists() {
        return MergeableConfigs {
            configs: Vec::new(),
            outcome: AutorouteCacheSaveOutcome::Fresh,
        };
    }
    let data = match read_autoroute_cache_file(path) {
        Ok(data) => data,
        Err(error) => {
            tracing::warn!(
                target: "keyhog::routing",
                path = %path.display(),
                %error,
                "existing autoroute cache is unreadable; replacing it with a fresh calibration (any other presets in it are lost)"
            );
            return replacement(format!("existing cache is unreadable: {error}"));
        }
    };
    let cache = match parse_autoroute_cache(&data) {
        Ok(cache) => cache,
        Err(CacheParseError::Version { found }) => {
            tracing::info!(
                target: "keyhog::routing",
                path = %path.display(),
                found_version = found,
                expected_version = AUTOROUTE_CACHE_VERSION,
                "existing autoroute cache is an older schema; superseding it with this build's calibration"
            );
            return replacement(format!(
                "cache schema {found} is incompatible with schema {AUTOROUTE_CACHE_VERSION}"
            ));
        }
        Err(CacheParseError::NotJson(error)) => {
            tracing::warn!(
                target: "keyhog::routing",
                path = %path.display(),
                %error,
                "existing autoroute cache is not valid cache JSON; replacing it with a fresh calibration"
            );
            return replacement(format!("existing cache is not valid cache JSON: {error}"));
        }
        Err(CacheParseError::Payload(error)) => {
            tracing::warn!(
                target: "keyhog::routing",
                path = %path.display(),
                %error,
                "existing autoroute cache failed to deserialize; replacing it with a fresh calibration"
            );
            return replacement(format!(
                "existing cache payload failed to deserialize: {error}"
            ));
        }
    };
    if let Err(error) =
        validate_cache_shared_identity(&cache, detector_digest, rules_digest, host_profile)
    {
        tracing::info!(
            target: "keyhog::routing",
            path = %path.display(),
            %error,
            "existing autoroute cache is for a different build/host/corpus; superseding it with this build's calibration"
        );
        return replacement(format!(
            "existing cache identity does not match this build, host, or detector corpus: {error}"
        ));
    }
    if let Err(error) = validate_cache_structure(&cache) {
        tracing::warn!(
            target: "keyhog::routing",
            path = %path.display(),
            %error,
            "existing autoroute cache has invalid structure or decision evidence; replacing it with a fresh calibration"
        );
        return replacement(format!(
            "existing cache structure or route evidence is invalid: {error}"
        ));
    }
    MergeableConfigs {
        configs: cache.configs,
        outcome: AutorouteCacheSaveOutcome::Merged,
    }
}

fn replacement(reason: String) -> MergeableConfigs {
    MergeableConfigs {
        configs: Vec::new(),
        outcome: AutorouteCacheSaveOutcome::Replaced { reason },
    }
}
