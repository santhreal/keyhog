//! Read-only, operator-facing projection of persisted autoroute evidence.

use serde::Serialize;

use super::artifact_identity::current_executable_sha256;
use super::codec::{parse_autoroute_cache, read_autoroute_cache_file, CacheParseError};
use super::schema::AutorouteBuildFeatures;
use super::validation::validate_cache_structure;
use crate::orchestrator::dispatch::backend::host::render_host_profile;
use crate::orchestrator::dispatch::backend::workload::render_workload_key;
use crate::orchestrator::dispatch::backend::AUTOROUTE_CACHE_VERSION;

/// Operator-facing view of the persisted autoroute cache (one JSON object).
#[derive(Debug, Default, Serialize)]
pub(crate) struct AutorouteCacheInspection {
    pub(crate) path: Option<String>,
    pub(crate) present: bool,
    /// Set when the cache exists but is unusable (disabled / unreadable / wrong
    /// schema version / corrupt). A real scan fails closed on the same input.
    pub(crate) error: Option<String>,
    pub(crate) version: Option<u32>,
    pub(crate) binary_version: Option<String>,
    pub(crate) git_hash: Option<String>,
    pub(crate) executable_sha256: Option<String>,
    pub(crate) identity_matches_build: Option<bool>,
    pub(crate) identity_mismatch_reason: Option<String>,
    pub(crate) host: Option<String>,
    pub(crate) detector_digest: Option<String>,
    pub(crate) rules_digest: Option<String>,
    pub(crate) configs: Vec<AutorouteConfigInspection>,
}

/// One resolved scan-config digest's calibrated workload decisions.
#[derive(Debug, Serialize)]
pub(crate) struct AutorouteConfigInspection {
    pub(crate) config_digest: String,
    pub(crate) decision_count: usize,
    pub(crate) decisions: Vec<AutorouteDecisionInspection>,
}

/// One calibrated workload decision. Numeric fields are projections derived
/// from primary timing evidence; the cache stores no denormalized copies.
#[derive(Debug, Serialize)]
pub(crate) struct AutorouteDecisionInspection {
    pub(crate) workload: String,
    /// Cold-aware backend for an in-process one-shot scan.
    pub(crate) backend: String,
    pub(crate) sample_bytes: u64,
    pub(crate) sample_chunks: usize,
    pub(crate) simd_ms: u128,
    pub(crate) cpu_ms: Option<u128>,
    /// One-shot GPU representative: max(first dispatch, warm median).
    pub(crate) gpu_ms: Option<u128>,
    /// Persistent-daemon GPU representative: warm median.
    pub(crate) gpu_warm_ms: Option<u128>,
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
    let mut out = AutorouteCacheInspection {
        path: path.map(|path| path.display().to_string()),
        ..AutorouteCacheInspection::default()
    };

    let Some(path) = path else {
        out.error = Some(
            "autoroute cache is disabled (--autoroute-cache off / [system].autoroute_cache = \
             off); auto scans require an explicit --backend in this configuration"
                .to_string(),
        );
        return out;
    };
    if !path.exists() {
        return out;
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
    out.host = Some(render_host_profile(&cache.host));

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

    if let Err(error) = validate_cache_structure(&cache) {
        out.error = Some(format!(
            "autoroute cache is structurally invalid: {error}; re-run calibration"
        ));
        return out;
    }

    for config in &cache.configs {
        let mut decisions = Vec::with_capacity(config.decisions.len());
        for (key, decision) in &config.decisions {
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
                backend: decision.backend.clone(),
                sample_bytes: decision.sample_bytes,
                sample_chunks: decision.sample_chunks,
                simd_ms: decision.simd_ms(),
                cpu_ms: decision.cpu_ms(),
                gpu_ms: decision.gpu_ms(),
                gpu_warm_ms: decision.gpu_warm_ms(),
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
            decision_count: config.decisions.len(),
            decisions,
        });
    }
    out.configs
        .sort_by(|left, right| left.config_digest.cmp(&right.config_digest));
    out
}
