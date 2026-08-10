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
use super::artifact_identity::{current_executable_sha256, current_gpu_sidecar_sha256};
use super::schema::{AutorouteBuildFeatures, AutorouteCache, AutorouteGpuArtifactBinding};

fn gpu_artifact_binding_matches(
    cache: &AutorouteCache,
    current_sidecar_sha256: Option<&str>,
) -> bool {
    match &cache.gpu_artifact_binding {
        Some(AutorouteGpuArtifactBinding::RuntimeCompiled {
            executable_sha256,
            rules_digest,
        }) => {
            current_sidecar_sha256.is_none()
                && executable_sha256 == &cache.executable_sha256
                && rules_digest == &cache.rules_digest
        }
        Some(AutorouteGpuArtifactBinding::InstalledSidecar { sha256 }) => {
            current_sidecar_sha256 == Some(sha256.as_str())
        }
        None => false,
    }
}

fn gpu_artifact_identity_matches(cache: &AutorouteCache) -> bool {
    let current_sidecar = current_gpu_sidecar_sha256();
    gpu_artifact_binding_matches(cache, current_sidecar.as_deref())
}

pub(crate) fn decision_requires_gpu_artifact_identity(decision: &AutorouteDecision) -> bool {
    decision.backend.starts_with("gpu")
        || decision
            .resolved_persistent_backend()
            .is_some_and(ScanBackend::is_gpu)
        || decision.calibration_points.iter().any(|point| {
            point
                .candidate_receipts
                .iter()
                .any(|receipt| receipt.backend.starts_with("gpu"))
                || point
                    .route_timings
                    .iter()
                    .any(|timing| timing.backend.starts_with("gpu"))
        })
}

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
            if decision_requires_gpu_artifact_identity(decision)
                && !gpu_artifact_identity_matches(cache)
            {
                return Err(format!(
                    "autoroute cache config {:016x} decision for {} has invalid GPU artifact identity binding",
                    config.config_digest,
                    render_workload_key(key)
                )
                .into());
            }
            validate_ordered_device_route_bindings(
                key,
                decision,
                &cache.rules_digest,
                config.config_digest,
            )?;
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

pub(in crate::orchestrator::dispatch::backend) fn validate_ordered_device_route_bindings(
    key: &WorkloadKey,
    decision: &AutorouteDecision,
    rules_digest: &str,
    config_digest: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let workload_identity = render_workload_key(key);
    let config_identity = format!("{config_digest:016x}");
    for point in &decision.calibration_points {
        for timing in &point.route_timings {
            let Some(route) = &timing.ordered_device_route else {
                continue;
            };
            if route.workload_identity != workload_identity {
                return Err(
                    "ordered GPU device route is bound to a different workload class".into(),
                );
            }
            if route.detector_digest != rules_digest {
                return Err(
                    "ordered GPU device route is bound to a different detector rule set".into(),
                );
            }
            if route.config_digest != config_identity {
                return Err(
                    "ordered GPU device route is bound to a different scan configuration".into(),
                );
            }
        }
    }
    Ok(())
}
pub(in crate::orchestrator::dispatch::backend) fn validate_decision_route_evidence(
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
    validate_ordered_device_set_stability(decision)?;
    let Some(resolved) = decision.resolved_routing_route() else {
        return Err(
            "cache decision has no confidence-supported one-shot route across every measured point"
                .into(),
        );
    };
    if selected_route != resolved {
        return Err("selected route is not supported by the persisted timing evidence".into());
    }
    if selected_route.backend != ScanBackend::CpuFallback
        && decision
            .resolved_recovery_route(selected_route.backend, false)
            .is_none()
    {
        return Err(
            "cache accelerated decision has no confidence-supported remaining one-shot recovery route"
                .into(),
        );
    }
    let Some(persistent_route) = decision.resolved_persistent_route() else {
        return Err(format!(
            "cache decision has no confidence-supported daemon route across every measured point; evidence: {}",
            decision.confidence_diagnostic(true),
        )
        .into());
    };
    if persistent_route.backend != ScanBackend::CpuFallback
        && decision
            .resolved_recovery_route(persistent_route.backend, true)
            .is_none()
    {
        return Err(
            "cache accelerated decision has no confidence-supported remaining daemon recovery route"
                .into(),
        );
    }
    Ok(())
}

pub(in crate::orchestrator::dispatch::backend) fn validate_ordered_device_set_stability(
    decision: &AutorouteDecision,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let baseline = decision
        .calibration_points
        .first()
        .ok_or("cache decision contains no measured calibration points")?;
    for baseline_timing in &baseline.route_timings {
        let route = baseline_timing
            .measured_route()
            .ok_or("cache decision contains an unsupported measured route")?;
        for point in &decision.calibration_points[1..] {
            let candidate = point
                .route_timing_for_route(route)
                .ok_or("cache decision changes its measured route census across points")?;
            match (
                baseline_timing.ordered_device_route.as_ref(),
                candidate.ordered_device_route.as_ref(),
            ) {
                (None, None) => {}
                (Some(left), Some(right)) if left.has_same_device_set_identity(right) => {}
                (Some(_), Some(_)) => {
                    return Err(format!(
                        "cache decision changes ordered GPU device-set identity across measured points for {}",
                        route.backend.label()
                    )
                    .into());
                }
                _ => {
                    return Err(format!(
                        "cache decision mixes single-device and ordered multi-device evidence across measured points for {}",
                        route.backend.label()
                    )
                    .into());
                }
            }
        }
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
    let mut timing_routes = BTreeSet::new();
    let mut previous_timing_route = None;
    let mut gpu_shapes = std::collections::BTreeMap::<String, (String, u64, u64)>::new();
    let mut gpu_device_routes = std::collections::BTreeMap::<String, Option<String>>::new();
    for entry in &point.route_timings {
        let route = entry
            .measured_route()
            .ok_or("cache decision has timing evidence for an unsupported backend")?;
        if entry.backend != route.backend.label()
            || !expected_backends.contains(entry.backend.as_str())
        {
            return Err("cache decision has unexpected or non-canonical timing evidence".into());
        }
        if !(1..=4).contains(&route.gpu_pipeline_depth) {
            return Err("cache decision has an invalid pipeline depth".into());
        }
        let peer_identity_present = entry
            .peer_identity
            .as_deref()
            .is_some_and(|identity| !identity.trim().is_empty());
        if route.backend.is_gpu() != peer_identity_present {
            return Err(
                "GPU timing evidence must bind exactly one acquired GPU peer identity".into(),
            );
        }
        if route.backend.is_gpu() {
            let capability = entry
                .gpu_dispatch_capability
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .ok_or("GPU timing evidence is missing dispatch capability")?;
            let input_capacity = entry
                .gpu_slot_input_capacity_bytes
                .filter(|capacity| *capacity > 0)
                .ok_or("GPU timing evidence is missing per-slot input capacity")?;
            let match_capacity = entry
                .gpu_slot_match_capacity
                .filter(|capacity| *capacity > 0)
                .ok_or("GPU timing evidence is missing per-slot match capacity")?;
            match capability {
                "async-submit-retire" => {}
                "synchronous" | "timed-resident" if route.gpu_pipeline_depth == 1 => {}
                "synchronous" | "timed-resident" => {
                    return Err("synchronous GPU capability cannot use a deep pipeline".into())
                }
                _ => return Err("cache decision has unsupported GPU dispatch capability".into()),
            }
            let depth = u64::from(route.gpu_pipeline_depth);
            let shape = (
                capability.to_string(),
                input_capacity
                    .checked_mul(depth)
                    .ok_or("GPU aggregate input capacity overflows u64")?,
                u64::from(match_capacity)
                    .checked_mul(depth)
                    .ok_or("GPU aggregate match capacity overflows u64")?,
            );
            match gpu_shapes.get(&entry.backend) {
                None => {
                    if route.gpu_pipeline_depth != 1 {
                        return Err(
                            "GPU pipeline evidence is missing its depth-one baseline".into()
                        );
                    }
                    gpu_shapes.insert(entry.backend.clone(), shape);
                }
                Some((baseline_capability, baseline_input, baseline_matches)) => {
                    if baseline_capability != capability
                        || shape.1 > *baseline_input
                        || baseline_input - shape.1 >= depth
                        || shape.2 > *baseline_matches
                        || baseline_matches - shape.2 >= depth
                    {
                        return Err(
                            "GPU pipeline depths do not derive from one aggregate input/replay budget"
                                .into(),
                        );
                    }
                }
            }
        } else if route.gpu_pipeline_depth != 1
            || entry.gpu_dispatch_capability.is_some()
            || entry.gpu_slot_input_capacity_bytes.is_some()
            || entry.gpu_slot_match_capacity.is_some()
        {
            return Err("host timing evidence contains GPU pipeline state".into());
        }
        let device_route_digest = if let Some(device_route) = &entry.ordered_device_route {
            device_route.validate().map_err(|error| {
                format!(
                    "cache decision has invalid ordered device-set evidence for {}: {error}",
                    entry.backend
                )
            })?;
            if device_route.devices.len() < 2 {
                return Err(format!(
                    "cache decision ordered device-set evidence for {} contains fewer than two devices",
                    entry.backend
                )
                .into());
            }
            if device_route
                .devices
                .iter()
                .any(|device| device.api.scan_backend() != route.backend)
            {
                return Err(format!(
                    "cache decision ordered device set does not use {} on every device",
                    entry.backend
                )
                .into());
            }
            let expected_peer_identity =
                format!("ordered-device-set:{}", device_route.authenticated_digest);
            if entry.peer_identity.as_deref() != Some(expected_peer_identity.as_str()) {
                return Err(format!(
                    "cache decision ordered device set for {} is not authenticated by its peer identity",
                    entry.backend
                )
                .into());
            }
            Some(device_route.authenticated_digest.clone())
        } else {
            if entry
                .peer_identity
                .as_deref()
                .is_some_and(|identity| identity.starts_with("ordered-device-set:"))
            {
                return Err(format!(
                    "cache decision ordered device-set identity for {} has no authenticated route body",
                    entry.backend
                )
                .into());
            }
            None
        };
        if route.backend.is_gpu() {
            match gpu_device_routes.get(&entry.backend) {
                Some(expected) if expected != &device_route_digest => {
                    return Err(format!(
                        "cache decision mixes ordered device sets for {} across route variants",
                        entry.backend
                    )
                    .into());
                }
                None => {
                    gpu_device_routes.insert(entry.backend.clone(), device_route_digest);
                }
                Some(_) => {}
            }
        }
        let timing_route = (
            entry.backend.clone(),
            entry.phase2_plain_localizer,
            entry.phase2_keyword_localizer,
            entry.gpu_pipeline_depth,
        );
        if !timing_routes.insert(timing_route.clone())
            || previous_timing_route
                .as_ref()
                .is_some_and(|previous| previous >= &timing_route)
        {
            return Err(
                "cache decision route timings are not in canonical backend/plain/keyword order"
                    .into(),
            );
        }
        previous_timing_route = Some(timing_route);
        if !entry
            .timing
            .is_valid_for_trials(AUTOROUTE_CALIBRATION_TRIALS)
        {
            return Err(format!(
                "cache decision has invalid timing evidence for {} plain_localizer={} keyword_localizer={} gpu_pipeline_depth={}",
                route.backend.label(),
                route.phase2_plain_localizer,
                route.phase2_keyword_localizer,
                route.gpu_pipeline_depth,
            )
            .into());
        }
        if route.backend.is_gpu() && gpu_cold_warm_route_evidence(&entry.timing).is_none() {
            return Err("cache decision has invalid GPU cold/warm timing evidence".into());
        }
        if route.backend == keyhog_scanner::ScanBackend::SimdCpu
            && simd_cold_warm_route_evidence(&entry.timing).is_none()
        {
            return Err("cache decision has invalid SIMD cold/warm timing evidence".into());
        }
    }
    if !timing_routes
        .iter()
        .any(|(backend, _, _, _)| backend == selected_route.backend.label())
    {
        return Err("selected execution route is missing timing evidence".into());
    }
    let mut expected_routes = BTreeSet::new();
    for backend_label in expected_backends {
        let backend = keyhog_scanner::hw_probe::parse_backend_str(backend_label)
            .ok_or("eligible backend census contains an unsupported backend")?;
        let depths: &[u8] = if backend.is_gpu() {
            let (capability, _, _) = gpu_shapes.get(backend_label).ok_or(
                "cache decision timing set does not match eligible backend census: eligible GPU backend is missing pipeline evidence",
            )?;
            if capability == "async-submit-retire" {
                &[1, 2, 3, 4]
            } else {
                &[1]
            }
        } else {
            &[1]
        };
        for plain in [false, true] {
            for keyword in [false, true] {
                for depth in depths {
                    expected_routes.insert((backend_label.clone(), plain, keyword, *depth));
                }
            }
        }
    }
    if timing_routes != expected_routes {
        return Err(
            "cache decision timing set does not match eligible backend census; backend/depth census includes every pipeline variant"
                .into(),
        );
    }
    let receipt_routes = point
        .candidate_receipts
        .iter()
        .map(|receipt| {
            (
                receipt.backend.clone(),
                receipt.phase2_plain_localizer,
                receipt.phase2_keyword_localizer,
                receipt.gpu_pipeline_depth,
            )
        })
        .collect::<BTreeSet<_>>();
    if receipt_routes != expected_routes || receipt_routes.len() != point.candidate_receipts.len() {
        return Err(
            "cache decision receipt set does not match eligible backend census (including pipeline-depth variants)"
                .into(),
        );
    }
    let mut seen_receipts = HashSet::with_capacity(point.candidate_receipts.len());
    let mut previous_receipt_route = None;
    let mut reference_digest = None;
    for receipt in &point.candidate_receipts {
        let backend = keyhog_scanner::hw_probe::parse_backend_str(&receipt.backend)
            .ok_or("candidate receipt has an unsupported backend")?;
        let receipt_route = (
            receipt.backend.as_str(),
            receipt.phase2_plain_localizer,
            receipt.phase2_keyword_localizer,
            receipt.gpu_pipeline_depth,
        );
        if !seen_receipts.insert(receipt_route)
            || previous_receipt_route
                .as_ref()
                .is_some_and(|previous| previous >= &receipt_route)
        {
            return Err(
                "candidate receipts are not in canonical backend/plain/keyword order".into(),
            );
        }
        previous_receipt_route = Some(receipt_route);
        if receipt.correctness_digest == 0 {
            return Err("candidate receipt is missing correctness digest".into());
        }
        if receipt.completed_trials != AUTOROUTE_CALIBRATION_TRIALS {
            return Err("candidate receipt has incomplete trial evidence".into());
        }
        match reference_digest {
            Some(digest) if digest != receipt.correctness_digest => {
                return Err(
                    "candidate receipt does not match the reference correctness digest".into(),
                )
            }
            None => reference_digest = Some(receipt.correctness_digest),
            _ => {}
        }
        let route = MeasuredRoute {
            backend,
            phase2_plain_localizer: receipt.phase2_plain_localizer,
            phase2_keyword_localizer: receipt.phase2_keyword_localizer,
            gpu_pipeline_depth: receipt.gpu_pipeline_depth,
        };
        let timing_entry = point
            .route_timing_for_route(route)
            .ok_or("candidate receipt has no matching timing evidence")?;
        if receipt.peer_identity != timing_entry.peer_identity
            || receipt.gpu_dispatch_capability != timing_entry.gpu_dispatch_capability
            || receipt.gpu_slot_input_capacity_bytes != timing_entry.gpu_slot_input_capacity_bytes
            || receipt.gpu_slot_match_capacity != timing_entry.gpu_slot_match_capacity
        {
            return Err(
                "candidate receipt is not bound to its timing peer identity or pipeline evidence"
                    .into(),
            );
        }
        if receipt.evidence_digest == 0
            || receipt.evidence_digest
                != receipt.expected_evidence_digest(route, &timing_entry.timing)
        {
            return Err("candidate receipt does not match its timing evidence".into());
        }
    }
    if point.calibrated_at_unix_ms == 0 {
        return Err("cache decision is missing a calibration timestamp".into());
    }
    if point.calibrated_at_unix_ms > current_unix_ms {
        return Err(
            "cache decision calibration timestamp is in the future relative to the system clock; correct the system clock and re-run calibration"
                .into(),
        );
    }
    let selected_timing = point
        .timing_for_route(selected_route)
        .ok_or("selected execution route is missing timing evidence")?;
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
#[cfg(test)]
#[path = "../../../../../tests/unit/backend_store_validation.rs"]
mod tests;
