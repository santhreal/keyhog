//! Single trust boundary for cache identity, structure, and routing evidence.

use std::collections::HashSet;

use super::super::evidence::{gpu_cold_warm_route_evidence, AutorouteDecision};
use super::super::host::AutorouteHostProfile;
use super::super::workload::render_workload_key;
use super::super::AUTOROUTE_CALIBRATION_TRIALS;
use super::artifact_identity::current_executable_sha256;
use super::schema::{AutorouteBuildFeatures, AutorouteCache};

pub(super) fn validate_cache_shared_identity(
    cache: &AutorouteCache,
    detector_digest: u64,
    rules_digest: &str,
    host_profile: &AutorouteHostProfile,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if cache.binary_version != env!("CARGO_PKG_VERSION")
        || cache.git_hash != keyhog_core::git_hash()
    {
        return Err("binary identity mismatch; cache is for a different keyhog build".into());
    }
    if cache.executable_sha256 != current_executable_sha256()? {
        return Err("executable digest mismatch; cache is for a different keyhog artifact".into());
    }
    let current_build_features = AutorouteBuildFeatures::current();
    if cache.build_features != current_build_features {
        return Err(format!(
            "build feature set mismatch; cache is for a different keyhog feature set \
             (cache cli features: {}; current cli features: {})",
            cache.build_features.describe(),
            current_build_features.describe()
        )
        .into());
    }
    if cache.detector_digest != detector_digest {
        return Err("detector digest mismatch; cache is for a different corpus".into());
    }
    if cache.rules_digest != rules_digest {
        return Err("rules digest mismatch; cache is for a different detector rule set".into());
    }
    if &cache.host != host_profile {
        return Err("host profile mismatch; cache is for different hardware".into());
    }
    Ok(())
}

pub(super) fn validate_cache_structure(
    cache: &AutorouteCache,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if cache.configs.is_empty() {
        return Err("autoroute cache contains no calibrated configurations".into());
    }
    let mut seen_config_digests = HashSet::with_capacity(cache.configs.len());
    for config in &cache.configs {
        if !seen_config_digests.insert(config.config_digest) {
            return Err(format!(
                "autoroute cache contains duplicate config digest {:016x}",
                config.config_digest
            )
            .into());
        }
        if config.decisions.is_empty() {
            return Err(format!(
                "autoroute cache config {:016x} contains no workload decisions",
                config.config_digest
            )
            .into());
        }
        let mut seen_workloads = HashSet::with_capacity(config.decisions.len());
        for (key, decision) in &config.decisions {
            if !seen_workloads.insert(*key) {
                return Err(format!(
                    "autoroute cache config {:016x} contains duplicate autoroute workload decision for {}",
                    config.config_digest,
                    render_workload_key(key)
                )
                .into());
            }
            validate_decision_route_evidence(decision)?;
        }
    }
    Ok(())
}

pub(super) fn validate_decision_route_evidence(
    decision: &AutorouteDecision,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if decision.sample_chunks == 0 || decision.sample_bytes == 0 {
        return Err("cache decision is missing calibration sample evidence".into());
    }
    if decision.correctness_digest == 0 {
        return Err("cache decision is missing correctness digest".into());
    }
    let Some(selected_backend) = decision.backend() else {
        return Err(format!(
            "cache contains unsupported backend decision {:?}",
            decision.backend
        )
        .into());
    };
    if decision.backend != selected_backend.label() {
        return Err(format!(
            "cache contains non-canonical backend label {:?}; expected {:?}",
            decision.backend,
            selected_backend.label()
        )
        .into());
    }
    if decision.trials != AUTOROUTE_CALIBRATION_TRIALS {
        return Err(format!(
            "cache decision records {} calibration trials; expected exactly {AUTOROUTE_CALIBRATION_TRIALS}",
            decision.trials
        )
        .into());
    }
    if decision.calibrated_at_unix_ms == 0 {
        return Err("cache decision is missing a calibration timestamp".into());
    }
    if !decision
        .simd_timing
        .is_valid_for_trials(AUTOROUTE_CALIBRATION_TRIALS)
    {
        return Err("cache decision has invalid SIMD timing evidence".into());
    }
    if decision
        .cpu_timing
        .as_ref()
        .is_some_and(|timing| !timing.is_valid_for_trials(AUTOROUTE_CALIBRATION_TRIALS))
    {
        return Err("cache decision has invalid CPU timing evidence".into());
    }
    if decision
        .gpu_timing
        .as_ref()
        .is_some_and(|timing| !timing.is_valid_for_trials(AUTOROUTE_CALIBRATION_TRIALS))
    {
        return Err("cache decision has invalid GPU timing evidence".into());
    }
    if decision
        .gpu_timing
        .as_ref()
        .is_some_and(|timing| gpu_cold_warm_route_evidence(timing).is_none())
    {
        return Err("cache decision has invalid GPU cold/warm timing evidence".into());
    }
    let Some(selected_timing) = decision.timing_for_backend(selected_backend) else {
        return Err("selected backend is missing timing evidence".into());
    };
    if !selected_timing.is_valid_for_trials(AUTOROUTE_CALIBRATION_TRIALS) {
        return Err("selected backend timing evidence is invalid".into());
    }
    let Some(resolved) = decision.resolved_routing_backend() else {
        return Err("cache decision has no route timing evidence".into());
    };
    if selected_backend != resolved {
        if decision.has_separated_fastest_route() {
            return Err("selected backend is not the fastest persisted timing evidence".into());
        }
        return Err("selected backend does not match measured-median resolution among statistically non-dominated routes".into());
    }
    Ok(())
}
