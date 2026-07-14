//! Single trust boundary for cache identity, structure, and routing evidence.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use super::super::evidence::{gpu_cold_warm_route_evidence, AutorouteDecision};
use super::super::workload::{
    autoroute_stable_bucket, render_workload_key, validate_workload_source_mixture,
    workload_evidence_digest, WorkloadKey,
};
use super::super::AUTOROUTE_CALIBRATION_TRIALS;
use super::artifact_identity::current_executable_sha256;
use super::schema::{AutorouteBuildFeatures, AutorouteCache};

pub(super) fn validate_cache_global_identity(
    cache: &AutorouteCache,
    detector_digest: u64,
    rules_digest: &str,
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
    Ok(())
}

pub(super) fn validate_cache_structure(
    cache: &AutorouteCache,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    validate_cache_structure_at(cache, current_unix_time_ms()?)
}

pub(super) fn validate_cache_structure_at(
    cache: &AutorouteCache,
    current_unix_ms: u128,
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
        config.host.require_exact_identity().map_err(|error| {
            format!(
                "autoroute cache config {:016x} has incomplete host identity: {error}",
                config.config_digest
            )
        })?;
        if config.decisions.is_empty() {
            return Err(format!(
                "autoroute cache config {:016x} contains no workload decisions",
                config.config_digest
            )
            .into());
        }
        let mut seen_workloads = HashSet::with_capacity(config.decisions.len());
        for row in &config.decisions {
            let key = &row.workload;
            let decision = &row.decision;
            validate_workload_source_mixture(key).map_err(|error| {
                format!(
                    "autoroute cache config {:016x} contains an invalid source mixture: {error}",
                    config.config_digest
                )
            })?;
            validate_decision_route_evidence_at(decision, current_unix_ms)?;
            validate_decision_workload_binding(key, decision)?;
            if row.workload_digest != workload_evidence_digest(key) {
                return Err(format!(
                    "autoroute cache config {:016x} contains workload evidence bound to a different workload key",
                    config.config_digest
                )
                .into());
            }
            if !seen_workloads.insert(key.clone()) {
                return Err(format!(
                    "autoroute cache config {:016x} contains duplicate autoroute workload decision for {}",
                    config.config_digest,
                    render_workload_key(key)
                )
                .into());
            }
        }
    }
    Ok(())
}

pub(super) fn validate_decision_workload_binding(
    key: &WorkloadKey,
    decision: &AutorouteDecision,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sample_chunks = u64::try_from(decision.sample_chunks)
        .map_err(|_| "cache decision sample chunk count exceeds the supported u64 range")?;
    if autoroute_stable_bucket(sample_chunks) != key.chunks_bucket
        || autoroute_stable_bucket(decision.sample_bytes) != key.bytes_bucket
    {
        return Err(format!(
            "cache decision sample evidence ({sample_chunks} chunks, {} bytes) does not match workload bands (chunks_log2={}, bytes_log2={})",
            decision.sample_bytes, key.chunks_bucket, key.bytes_bucket
        )
        .into());
    }
    Ok(())
}

pub(super) fn validate_decision_route_evidence(
    decision: &AutorouteDecision,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    validate_decision_route_evidence_at(decision, current_unix_time_ms()?)
}

fn validate_decision_route_evidence_at(
    decision: &AutorouteDecision,
    current_unix_ms: u128,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if decision.sample_chunks == 0 || decision.sample_bytes == 0 {
        return Err("cache decision is missing calibration sample evidence".into());
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
    for (driver, timing) in [
        ("CUDA", decision.gpu_cuda_timing.as_ref()),
        ("WGPU", decision.gpu_wgpu_timing.as_ref()),
    ] {
        if timing.is_some_and(|timing| !timing.is_valid_for_trials(AUTOROUTE_CALIBRATION_TRIALS)) {
            return Err(format!("cache decision has invalid {driver} timing evidence").into());
        }
        if timing.is_some_and(|timing| gpu_cold_warm_route_evidence(timing).is_none()) {
            return Err(
                format!("cache decision has invalid {driver} cold/warm timing evidence").into(),
            );
        }
    }
    let expected_receipt_backends = [
        (keyhog_scanner::ScanBackend::SimdCpu, true),
        (
            keyhog_scanner::ScanBackend::CpuFallback,
            decision.cpu_timing.is_some(),
        ),
        (
            keyhog_scanner::ScanBackend::GpuCuda,
            decision.gpu_cuda_timing.is_some(),
        ),
        (
            keyhog_scanner::ScanBackend::GpuWgpu,
            decision.gpu_wgpu_timing.is_some(),
        ),
    ]
    .into_iter()
    .filter(|(_, present)| *present)
    .map(|(backend, _)| backend.label())
    .collect::<HashSet<_>>();
    if decision.candidate_receipts.len() != expected_receipt_backends.len() {
        return Err("cache decision candidate receipt set does not match timing evidence".into());
    }
    let mut seen_receipts = HashSet::with_capacity(decision.candidate_receipts.len());
    let mut reference_digest = None;
    for receipt in &decision.candidate_receipts {
        let Some(backend) = keyhog_scanner::hw_probe::parse_backend_str(&receipt.backend) else {
            return Err(format!(
                "cache decision has a candidate receipt for unsupported backend {:?}",
                receipt.backend
            )
            .into());
        };
        if receipt.backend != backend.label()
            || !expected_receipt_backends.contains(receipt.backend.as_str())
        {
            return Err(format!(
                "cache decision has an unexpected or non-canonical candidate receipt for {:?}",
                receipt.backend
            )
            .into());
        }
        if !seen_receipts.insert(receipt.backend.as_str()) {
            return Err(format!(
                "cache decision has duplicate candidate receipt for {}",
                receipt.backend
            )
            .into());
        }
        if receipt.correctness_digest == 0 {
            return Err(format!(
                "cache decision candidate receipt for {} is missing correctness digest",
                receipt.backend
            )
            .into());
        }
        if receipt.completed_trials != AUTOROUTE_CALIBRATION_TRIALS {
            return Err(format!(
                "cache decision candidate receipt for {} records {} completed trials; expected {AUTOROUTE_CALIBRATION_TRIALS}",
                receipt.backend, receipt.completed_trials
            )
            .into());
        }
        match reference_digest {
            Some(digest) if digest != receipt.correctness_digest => {
                return Err(format!(
                    "cache decision candidate receipt for {} does not match the reference correctness digest",
                    receipt.backend
                )
                .into());
            }
            None => reference_digest = Some(receipt.correctness_digest),
            _ => {}
        }
        let Some(timing) = decision.timing_for_backend(backend) else {
            return Err(format!(
                "cache decision candidate receipt for {} has no timing evidence",
                receipt.backend
            )
            .into());
        };
        if receipt.evidence_digest == 0
            || receipt.evidence_digest != receipt.expected_evidence_digest(backend, timing)
        {
            return Err(format!(
                "cache decision candidate receipt for {} does not match its timing evidence",
                receipt.backend
            )
            .into());
        }
    }
    if decision.calibrated_at_unix_ms == 0 {
        return Err("cache decision is missing a calibration timestamp".into());
    }
    if decision.calibrated_at_unix_ms > current_unix_ms {
        return Err(format!(
            "cache decision calibration timestamp {} is {} ms in the future relative to the system clock at {}; correct the system clock and re-run calibration",
            decision.calibrated_at_unix_ms,
            decision.calibrated_at_unix_ms - current_unix_ms,
            current_unix_ms
        )
        .into());
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

pub(super) fn current_unix_time_ms() -> Result<u128, Box<dyn std::error::Error + Send + Sync>> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|_| {
            "system clock predates the Unix epoch; correct the system clock and re-run calibration"
                .into()
        })
}
