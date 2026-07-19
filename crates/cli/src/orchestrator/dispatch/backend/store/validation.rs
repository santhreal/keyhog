//! Single trust boundary for cache identity, structure, and routing evidence.

use std::collections::{BTreeSet, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use keyhog_scanner::ScanBackend;

use super::super::evidence::{
    gpu_cold_warm_route_evidence, simd_cold_warm_route_evidence, AutorouteCalibrationPoint,
    AutorouteDecision, MeasuredRoute, MAX_AUTOROUTE_MEASURED_POINTS,
};
use super::super::workload::{
    autoroute_stable_bucket, render_workload_key, validate_measurement_shape_evidence,
    validate_workload_source_mixture, workload_evidence_digest, WorkloadKey,
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
    let mut seen_generations = HashSet::with_capacity(cache.configs.len());
    for config in &cache.configs {
        if !seen_generations.insert((config.config_digest, &config.host)) {
            return Err(format!(
                "autoroute cache contains duplicate config and host generation for digest {:016x}",
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
        let expected_backends = config.host.candidate_backend_set().map_err(|error| {
            format!(
                "autoroute cache config {:016x} has invalid candidate census: {error}",
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
            validate_decision_route_evidence_at(decision, current_unix_ms, &expected_backends)?;
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
    for point in &decision.calibration_points {
        validate_point_workload_binding(key, point)?;
    }
    Ok(())
}

fn validate_point_workload_binding(
    key: &WorkloadKey,
    point: &AutorouteCalibrationPoint,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sample_chunks = u64::try_from(point.sample_chunks)
        .map_err(|_| "cache decision sample chunk count exceeds the supported u64 range")?;
    if autoroute_stable_bucket(sample_chunks) != key.chunks_bucket
        || autoroute_stable_bucket(point.sample_bytes) != key.bytes_bucket
    {
        return Err(format!(
            "cache decision sample evidence ({sample_chunks} chunks, {} bytes) does not match workload bands (chunks_log2={}, bytes_log2={})",
            point.sample_bytes, key.chunks_bucket, key.bytes_bucket
        )
        .into());
    }
    Ok(())
}

pub(super) fn validate_decision_route_evidence(
    decision: &AutorouteDecision,
    expected_backends: &BTreeSet<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    validate_decision_route_evidence_at(decision, current_unix_time_ms()?, expected_backends)
}

fn validate_decision_route_evidence_at(
    decision: &AutorouteDecision,
    current_unix_ms: u128,
    expected_backends: &BTreeSet<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if decision.calibration_points.is_empty() {
        return Err("cache decision contains no measured calibration points".into());
    }
    if decision.calibration_points.len() > MAX_AUTOROUTE_MEASURED_POINTS {
        return Err(format!(
            "autoroute decision contains {} calibration points; maximum is {}",
            decision.calibration_points.len(),
            MAX_AUTOROUTE_MEASURED_POINTS
        )
        .into());
    }
    let Some(selected_route) = decision.measured_route() else {
        return Err(format!(
            "cache contains unsupported backend decision {:?}",
            decision.backend
        )
        .into());
    };
    if decision.backend != selected_route.backend.label() {
        return Err(format!(
            "cache contains non-canonical backend label {:?}; expected {:?}",
            decision.backend,
            selected_route.backend.label()
        )
        .into());
    }
    let mut measured_points = HashSet::with_capacity(decision.calibration_points.len());
    for point in &decision.calibration_points {
        validate_measurement_shape_evidence(&point.measurement_shape)?;
        if !measured_points.insert(point.measurement_shape.shape_digest) {
            return Err(format!(
                "autoroute decision contains duplicate measurement-shape evidence {}",
                keyhog_core::hex_encode(&point.measurement_shape.shape_digest)
            )
            .into());
        }
        validate_point_route_evidence_at(
            point,
            selected_route,
            current_unix_ms,
            expected_backends,
        )?;
    }
    let Some(resolved) = decision.resolved_routing_route() else {
        return Err(
            "cache decision has no confidence-separated fastest one-shot route across every measured point"
                .into(),
        );
    };
    if selected_route != resolved {
        return Err("selected route is not the fastest persisted timing evidence".into());
    }
    if selected_route.backend != ScanBackend::CpuFallback
        && decision
            .resolved_recovery_route(selected_route.backend, false)
            .is_none()
    {
        return Err(
            "cache accelerated decision has no unanimous fastest remaining one-shot recovery route"
                .into(),
        );
    }
    let Some(persistent_route) = decision.resolved_persistent_route() else {
        return Err(
            "cache decision has no confidence-separated fastest daemon route across every measured point"
                .into(),
        );
    };
    if persistent_route.backend != ScanBackend::CpuFallback
        && decision
            .resolved_recovery_route(persistent_route.backend, true)
            .is_none()
    {
        return Err(
            "cache accelerated decision has no unanimous fastest remaining daemon recovery route"
                .into(),
        );
    }
    Ok(())
}

fn validate_point_route_evidence_at(
    point: &AutorouteCalibrationPoint,
    selected_route: MeasuredRoute,
    current_unix_ms: u128,
    expected_backends: &BTreeSet<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if point.sample_chunks == 0 || point.sample_bytes == 0 {
        return Err("cache decision is missing calibration sample evidence".into());
    }
    if point.trials != AUTOROUTE_CALIBRATION_TRIALS {
        return Err(format!(
            "cache decision records {} calibration trials; expected exactly {AUTOROUTE_CALIBRATION_TRIALS}",
            point.trials
        )
        .into());
    }
    if point.timing_for_route(selected_route).is_none() {
        return Err("selected execution route is missing timing evidence".into());
    }
    let mut timing_routes = BTreeSet::new();
    let mut previous_timing_route = None;
    for entry in &point.route_timings {
        let Some(route) = entry.measured_route() else {
            return Err(format!(
                "cache decision has timing evidence for unsupported backend {:?}",
                entry.backend
            )
            .into());
        };
        if entry.backend != route.backend.label()
            || !expected_backends.contains(entry.backend.as_str())
        {
            return Err(format!(
                "cache decision has unexpected or non-canonical timing evidence for {:?}",
                entry.backend
            )
            .into());
        }
        let timing_route = (
            entry.backend.clone(),
            entry.phase2_plain_localizer,
            entry.phase2_keyword_localizer,
        );
        if !timing_routes.insert(timing_route.clone()) {
            return Err(format!(
                "cache decision has duplicate timing evidence for {} plain_localizer={} keyword_localizer={}",
                entry.backend,
                entry.phase2_plain_localizer,
                entry.phase2_keyword_localizer
            )
            .into());
        }
        if previous_timing_route
            .as_ref()
            .is_some_and(|previous| previous >= &timing_route)
        {
            return Err(format!(
                "cache decision route timings are not in canonical backend/plain/keyword order at {:?}",
                timing_route
            )
            .into());
        }
        previous_timing_route = Some(timing_route.clone());
        if !entry
            .timing
            .is_valid_for_trials(AUTOROUTE_CALIBRATION_TRIALS)
        {
            return Err(format!(
                "cache decision has invalid timing evidence for {} plain_localizer={} keyword_localizer={}",
                entry.backend,
                entry.phase2_plain_localizer,
                entry.phase2_keyword_localizer
            )
            .into());
        }
        if route.backend.is_gpu() && gpu_cold_warm_route_evidence(&entry.timing).is_none() {
            return Err(format!(
                "cache decision has invalid cold/warm timing evidence for {} plain_localizer={} keyword_localizer={}",
                entry.backend,
                entry.phase2_plain_localizer,
                entry.phase2_keyword_localizer
            )
            .into());
        }
        if route.backend == keyhog_scanner::ScanBackend::SimdCpu
            && simd_cold_warm_route_evidence(&entry.timing).is_none()
        {
            return Err(format!(
                "cache decision has invalid SIMD cold/warm timing evidence for plain_localizer={} keyword_localizer={}",
                entry.phase2_plain_localizer, entry.phase2_keyword_localizer
            )
            .into());
        }
    }
    let expected_routes = expected_backends
        .iter()
        .flat_map(|backend| {
            [false, true].into_iter().flat_map(move |plain| {
                [false, true].map(move |keyword| (backend.clone(), plain, keyword))
            })
        })
        .collect::<BTreeSet<_>>();
    if timing_routes != expected_routes {
        return Err(format!(
            "cache decision timing set does not match eligible backend census (expected {:?}, found {:?})",
            expected_routes, timing_routes
        )
        .into());
    }
    let receipt_routes = point
        .candidate_receipts
        .iter()
        .map(|receipt| {
            (
                receipt.backend.clone(),
                receipt.phase2_plain_localizer,
                receipt.phase2_keyword_localizer,
            )
        })
        .collect::<BTreeSet<_>>();
    if receipt_routes != expected_routes || receipt_routes.len() != point.candidate_receipts.len() {
        return Err(format!(
            "cache decision receipt set does not match eligible backend census (expected {:?}, found {:?})",
            expected_routes, receipt_routes
        )
        .into());
    }
    let mut seen_receipts = HashSet::with_capacity(point.candidate_receipts.len());
    let mut previous_receipt_route = None;
    let mut reference_digest = None;
    for receipt in &point.candidate_receipts {
        let Some(backend) = keyhog_scanner::hw_probe::parse_backend_str(&receipt.backend) else {
            return Err(format!(
                "cache decision has a candidate receipt for unsupported backend {:?}",
                receipt.backend
            )
            .into());
        };
        if receipt.backend != backend.label()
            || !expected_backends.contains(receipt.backend.as_str())
        {
            return Err(format!(
                "cache decision has an unexpected or non-canonical candidate receipt for {:?}",
                receipt.backend
            )
            .into());
        }
        let receipt_route = (
            receipt.backend.as_str(),
            receipt.phase2_plain_localizer,
            receipt.phase2_keyword_localizer,
        );
        if !seen_receipts.insert(receipt_route) {
            return Err(format!(
                "cache decision has duplicate candidate receipt for {}",
                receipt.backend
            )
            .into());
        }
        if previous_receipt_route
            .as_ref()
            .is_some_and(|previous| previous >= &receipt_route)
        {
            return Err(format!(
                "cache decision candidate receipts are not in canonical backend/plain/keyword order at {:?}",
                receipt_route
            )
            .into());
        }
        previous_receipt_route = Some(receipt_route);
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
        let route = MeasuredRoute {
            backend,
            phase2_plain_localizer: receipt.phase2_plain_localizer,
            phase2_keyword_localizer: receipt.phase2_keyword_localizer,
        };
        let Some(timing) = point.timing_for_route(route) else {
            return Err(format!(
                "cache decision candidate receipt for {} has no timing evidence",
                receipt.backend
            )
            .into());
        };
        if receipt.evidence_digest == 0
            || receipt.evidence_digest != receipt.expected_evidence_digest(route, timing)
        {
            return Err(format!(
                "cache decision candidate receipt for {} does not match its timing evidence",
                receipt.backend
            )
            .into());
        }
    }
    if point.calibrated_at_unix_ms == 0 {
        return Err("cache decision is missing a calibration timestamp".into());
    }
    if point.calibrated_at_unix_ms > current_unix_ms {
        return Err(format!(
            "cache decision calibration timestamp {} is {} ms in the future relative to the system clock at {}; correct the system clock and re-run calibration",
            point.calibrated_at_unix_ms,
            point.calibrated_at_unix_ms - current_unix_ms,
            current_unix_ms
        )
        .into());
    }
    let Some(selected_timing) = point.timing_for_route(selected_route) else {
        return Err("selected execution route is missing timing evidence".into());
    };
    if !selected_timing.is_valid_for_trials(AUTOROUTE_CALIBRATION_TRIALS) {
        return Err("selected execution-route timing evidence is invalid".into());
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
