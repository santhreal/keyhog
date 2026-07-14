//! Read-only, operator-facing projection of persisted autoroute evidence.

use serde::Serialize;

use super::artifact_identity::current_executable_sha256;
use super::codec::{
    autoroute_cache_file_presence, parse_autoroute_cache, read_autoroute_cache_file,
    CacheParseError,
};
use super::schema::AutorouteBuildFeatures;
use super::validation::{current_unix_time_ms, validate_cache_structure_at};
use crate::orchestrator::dispatch::backend::host::{host_identity_digest, render_host_profile};
use crate::orchestrator::dispatch::backend::workload::render_workload_key;
use crate::orchestrator::dispatch::backend::AUTOROUTE_CACHE_VERSION;

#[cfg(test)]
mod tests;

/// Operator-facing view of the persisted autoroute cache (one JSON object).
#[derive(Debug, Default, Serialize)]
pub(crate) struct AutorouteCacheInspection {
    pub(crate) path: Option<String>,
    /// Whether this build has multiple compiled scan backends and therefore
    /// needs persisted evidence to select among them.
    pub(crate) calibration_required: bool,
    /// The only possible route when calibration is not required.
    pub(crate) direct_backend: Option<&'static str>,
    pub(crate) present: bool,
    /// Set when this build needs the requested cache but it is disabled, or
    /// when a present cache is unreadable, incompatible, or corrupt.
    pub(crate) error: Option<String>,
    pub(crate) version: Option<u32>,
    pub(crate) binary_version: Option<String>,
    pub(crate) git_hash: Option<String>,
    pub(crate) executable_sha256: Option<String>,
    pub(crate) identity_matches_build: Option<bool>,
    pub(crate) identity_mismatch_reason: Option<String>,
    /// Compatibility projection for consumers of schema v31 inspection JSON.
    /// `configs[].host` is authoritative. This is present only when every
    /// persisted config has the same projected host identity.
    pub(crate) host: Option<String>,
    pub(crate) detector_digest: Option<String>,
    pub(crate) rules_digest: Option<String>,
    pub(crate) inspected_at_unix_ms: Option<u128>,
    pub(crate) configs: Vec<AutorouteConfigInspection>,
}

/// One exact resolved scan-config and host generation's calibrated decisions.
#[derive(Debug, Serialize)]
pub(crate) struct AutorouteConfigInspection {
    pub(crate) config_digest: String,
    pub(crate) host_identity: String,
    pub(crate) host: String,
    pub(crate) eligible_backends: Vec<String>,
    pub(crate) decision_count: usize,
    pub(crate) decisions: Vec<AutorouteDecisionInspection>,
}

/// One calibrated workload decision. Numeric fields are projections derived
/// from primary timing evidence; the cache stores no denormalized copies.
#[derive(Debug, Serialize)]
pub(crate) struct AutorouteDecisionInspection {
    pub(crate) workload: String,
    pub(crate) calibrated_at_unix_ms: u128,
    pub(crate) calibration_age_ms: u128,
    /// Cold-aware backend for an in-process one-shot scan.
    pub(crate) backend: String,
    pub(crate) sample_bytes: u64,
    pub(crate) sample_chunks: usize,
    pub(crate) candidate_receipts: Vec<AutorouteCandidateReceiptInspection>,
    pub(crate) simd_ms: u128,
    pub(crate) cpu_ms: Option<u128>,
    pub(crate) gpu_cuda_ms: Option<u128>,
    pub(crate) gpu_cuda_warm_ms: Option<u128>,
    pub(crate) gpu_wgpu_ms: Option<u128>,
    pub(crate) gpu_wgpu_warm_ms: Option<u128>,
    /// Whether the one-shot route's 95% confidence interval is entirely below
    /// every competitor. When false, medians decide among non-dominated routes.
    pub(crate) confidence_separated: bool,
    pub(crate) selection_basis: &'static str,
    /// One-shot representative-time margin to the next candidate.
    pub(crate) selected_margin_ns: Option<u128>,
    /// Warm backend derived for a preinitialized persistent daemon.
    pub(crate) daemon_backend: String,
    pub(crate) daemon_confidence_separated: bool,
    pub(crate) daemon_selection_basis: &'static str,
    pub(crate) daemon_selected_margin_ns: Option<u128>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AutorouteCandidateReceiptInspection {
    pub(crate) backend: String,
    pub(crate) correctness_digest: String,
    pub(crate) completed_trials: usize,
    pub(crate) evidence_digest: String,
}

fn selection_basis(confidence_separated: bool) -> &'static str {
    if confidence_separated {
        "separated-95pct-confidence"
    } else {
        "lowest-measured-median-among-overlapping-confidence"
    }
}

/// Inspect without requiring the current detector/host/config inputs. Cheap
/// build drift and the full persisted structure are validated; scan-time load
/// additionally validates the live host, detector, rules, and config identity.
pub(crate) fn inspect_autoroute_cache(path: Option<&std::path::Path>) -> AutorouteCacheInspection {
    inspect_autoroute_cache_for_build(path, keyhog_scanner::hw_probe::multiple_backends_compiled())
}

fn inspect_autoroute_cache_for_build(
    path: Option<&std::path::Path>,
    multiple_backends_compiled: bool,
) -> AutorouteCacheInspection {
    let mut out = AutorouteCacheInspection {
        path: path.map(|path| path.display().to_string()),
        calibration_required: multiple_backends_compiled,
        direct_backend: (!multiple_backends_compiled)
            .then_some(keyhog_scanner::hw_probe::ScanBackend::CpuFallback.label()),
        ..AutorouteCacheInspection::default()
    };

    let Some(path) = path else {
        if multiple_backends_compiled {
            out.error = Some(
                "autoroute cache is disabled (--autoroute-cache off / [system].autoroute_cache = \
                 off); auto scans require an explicit --backend in this configuration"
                    .to_string(),
            );
        }
        return out;
    };
    match autoroute_cache_file_presence(path) {
        Ok(true) => {}
        Ok(false) => return out,
        Err(error) => {
            out.error = Some(format!(
                "autoroute cache path cannot be inspected: {error}. Fix path permissions or parent storage and retry"
            ));
            return out;
        }
    }

    let data = match read_autoroute_cache_file(path) {
        Ok(data) => data,
        Err(error) => {
            out.present = true;
            out.error = Some(format!("autoroute cache is unreadable: {error}"));
            return out;
        }
    };
    out.present = true;

    let cache = match parse_autoroute_cache(&data) {
        Ok(cache) => cache,
        Err(CacheParseError::NotJson(error)) => {
            out.error = Some(format!("autoroute cache is not valid cache JSON: {error}"));
            return out;
        }
        Err(CacheParseError::Version { found }) => {
            out.version = Some(found);
            out.error = Some(format!(
                "cache schema version {found} is incompatible with this build (expects \
                 {AUTOROUTE_CACHE_VERSION}); re-run calibration to regenerate it"
            ));
            return out;
        }
        Err(CacheParseError::Payload(error)) => {
            out.version = Some(AUTOROUTE_CACHE_VERSION);
            out.error = Some(format!(
                "autoroute cache payload did not deserialize: {error}"
            ));
            return out;
        }
    };
    out.version = Some(cache.version);
    out.binary_version = Some(cache.binary_version.clone());
    out.git_hash = Some(cache.git_hash.clone());
    out.executable_sha256 = Some(cache.executable_sha256.clone());
    out.detector_digest = Some(format!("{:016x}", cache.detector_digest));
    out.rules_digest = Some(cache.rules_digest.clone());
    let mut drift = Vec::new();
    if cache.binary_version != env!("CARGO_PKG_VERSION") {
        drift.push(format!(
            "binary version {} != current {}",
            cache.binary_version,
            env!("CARGO_PKG_VERSION")
        ));
    }
    if cache.git_hash != keyhog_core::git_hash() {
        drift.push(format!(
            "git hash {} != current {}",
            cache.git_hash,
            keyhog_core::git_hash()
        ));
    }
    match current_executable_sha256() {
        Ok(current) if cache.executable_sha256 != current => drift.push(format!(
            "executable sha256 {} != current {}",
            cache.executable_sha256, current
        )),
        Ok(_) => {}
        Err(error) => drift.push(format!("current executable identity unavailable: {error}")),
    }
    let current_features = AutorouteBuildFeatures::current();
    if cache.build_features != current_features {
        drift.push(format!(
            "build features {} != current {}",
            cache.build_features.describe(),
            current_features.describe()
        ));
    }
    out.identity_matches_build = Some(drift.is_empty());
    if !drift.is_empty() {
        out.identity_mismatch_reason = Some(drift.join("; "));
    }

    let inspected_at_unix_ms = match current_unix_time_ms() {
        Ok(timestamp) => timestamp,
        Err(error) => {
            out.error = Some(format!("autoroute cache time validation failed: {error}"));
            return out;
        }
    };
    out.inspected_at_unix_ms = Some(inspected_at_unix_ms);
    if let Err(error) = validate_cache_structure_at(&cache, inspected_at_unix_ms) {
        out.error = Some(format!(
            "autoroute cache is structurally invalid: {error}; re-run calibration"
        ));
        return out;
    }

    let common_host = cache.configs.first().map(|config| &config.host);
    if common_host.is_some()
        && cache
            .configs
            .iter()
            .all(|config| Some(&config.host) == common_host)
    {
        out.host = common_host.map(render_host_profile);
    }

    for config in &cache.configs {
        let mut decisions = Vec::with_capacity(config.decisions.len());
        for row in &config.decisions {
            let key = &row.workload;
            let decision = &row.decision;
            let Some(daemon_backend) = decision.resolved_persistent_backend() else {
                out.error = Some(
                    "autoroute cache decision has no persistent-daemon route evidence; \
                     re-run calibration"
                        .to_string(),
                );
                out.configs.clear();
                return out;
            };
            let confidence_separated = decision.has_separated_fastest_route();
            let daemon_confidence_separated = decision.has_separated_fastest_persistent_route();
            decisions.push(AutorouteDecisionInspection {
                workload: render_workload_key(key),
                calibrated_at_unix_ms: decision.calibrated_at_unix_ms,
                calibration_age_ms: inspected_at_unix_ms - decision.calibrated_at_unix_ms,
                backend: decision.backend.clone(),
                sample_bytes: decision.sample_bytes,
                sample_chunks: decision.sample_chunks,
                candidate_receipts: decision
                    .candidate_receipts
                    .iter()
                    .map(|receipt| AutorouteCandidateReceiptInspection {
                        backend: receipt.backend.clone(),
                        correctness_digest: format!("{:016x}", receipt.correctness_digest),
                        completed_trials: receipt.completed_trials,
                        evidence_digest: format!("{:016x}", receipt.evidence_digest),
                    })
                    .collect(),
                simd_ms: decision.simd_ms(),
                cpu_ms: decision.cpu_ms(),
                gpu_cuda_ms: decision
                    .gpu_cold_warm_route_for(keyhog_scanner::ScanBackend::GpuCuda)
                    .map(|(_, _, route_ns)| route_ns / 1_000_000),
                gpu_cuda_warm_ms: decision
                    .gpu_cold_warm_route_for(keyhog_scanner::ScanBackend::GpuCuda)
                    .map(|(_, warm, _)| warm.median_ms()),
                gpu_wgpu_ms: decision
                    .gpu_cold_warm_route_for(keyhog_scanner::ScanBackend::GpuWgpu)
                    .map(|(_, _, route_ns)| route_ns / 1_000_000),
                gpu_wgpu_warm_ms: decision
                    .gpu_cold_warm_route_for(keyhog_scanner::ScanBackend::GpuWgpu)
                    .map(|(_, warm, _)| warm.median_ms()),
                confidence_separated,
                selection_basis: selection_basis(confidence_separated),
                selected_margin_ns: decision.selected_margin_ns(),
                daemon_backend: daemon_backend.label().to_string(),
                daemon_confidence_separated,
                daemon_selection_basis: selection_basis(daemon_confidence_separated),
                daemon_selected_margin_ns: decision.persistent_selected_margin_ns(),
            });
        }
        decisions.sort_by(|left, right| left.workload.cmp(&right.workload));
        out.configs.push(AutorouteConfigInspection {
            config_digest: format!("{:016x}", config.config_digest),
            host_identity: host_identity_digest(&config.host),
            host: render_host_profile(&config.host),
            eligible_backends: config.host.eligible_backends.clone(),
            decision_count: config.decisions.len(),
            decisions,
        });
    }
    out.configs.sort_by(|left, right| {
        left.config_digest
            .cmp(&right.config_digest)
            .then_with(|| left.host_identity.cmp(&right.host_identity))
    });
    out
}
