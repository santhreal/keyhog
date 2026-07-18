//! Install-time autoroute (backend-selection) calibration measurement.
//!
//! Disambiguation: "calibration" in this module means measuring which scan
//! *backend* (SIMD / scalar CPU / GPU) is the fastest measured-correct choice
//! for a workload class, then persisting that decision. It is the
//! `calibrate-autoroute` / `--autoroute-calibrate` subsystem documented in
//! `docs/src/reference/autoroute-calibration.md`.
//!
//! It is NOT the Bayesian *confidence* calibration in
//! [`keyhog_core::calibration`] (the `keyhog calibrate --tp/--fp` per-detector
//! Beta(α, β) store). This module never reads or writes confidence scores; the
//! two systems share only the English word "calibration".

use keyhog_core::Chunk;
use keyhog_scanner::hw_probe::ScanBackend;
use keyhog_scanner::{CompiledScanner, Phase1AdmissionPlan};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::evidence::{
    canonical_match_digest, canonical_matches, canonical_matches_equal_reference,
    differing_canonical_match_fields, gpu_cold_warm_route_evidence, simd_cold_warm_route_evidence,
    AutorouteDecision, BackendTimingEvidence, CanonicalMatch, MeasuredRoute, RouteTimingEvidence,
};
use super::workload::MeasurementShapeEvidence;
use super::{is_gpu_backend, AutorouteRoutingError, AUTOROUTE_CALIBRATION_TRIALS};

pub(super) fn calibrate_fastest_correct_backend(
    scanner: &CompiledScanner,
    _pattern_count: usize,
    sample: &[Chunk],
    measurement_shape: MeasurementShapeEvidence,
    eligible_backend_labels: &[String],
    admission_plan: Option<&Phase1AdmissionPlan>,
) -> Result<AutorouteDecision, AutorouteRoutingError> {
    let sample_bytes = calibration_sample_bytes(sample)?;

    let reference_route = MeasuredRoute {
        backend: ScanBackend::CpuFallback,
        phase2_plain_localizer: false,
        phase2_keyword_localizer: false,
    };
    let reference_matches =
        establish_scalar_reference(scanner, sample, admission_plan, reference_route);
    let reference_key = canonical_matches(&reference_matches);

    let candidate_backends = eligible_backend_labels
        .iter()
        .map(|label| {
            keyhog_scanner::hw_probe::parse_backend_str(label).ok_or_else(|| {
                AutorouteRoutingError::calibration_not_persisted(format!(
                    "eligible backend census contains unsupported label {label:?}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if candidate_backends.contains(&ScanBackend::SimdCpu) {
        scanner.initialize_simd_backend().map_err(|error| {
            AutorouteRoutingError::candidate_backend_rejected(
                ScanBackend::SimdCpu,
                format!("Hyperscan initialization failed: {error}"),
            )
        })?;
    }
    let gpu_candidate_allowed = candidate_backends.iter().any(|backend| backend.is_gpu());
    if gpu_candidate_allowed {
        scanner
            .prepare_autoroute_calibration_gpu_artifact()
            .map_err(AutorouteRoutingError::calibration_not_persisted)?;
    }

    let mut candidate_routes = candidate_backends
        .into_iter()
        .flat_map(|backend| {
            [false, true]
                .into_iter()
                .flat_map(move |phase2_plain_localizer| {
                    [false, true].map(move |phase2_keyword_localizer| MeasuredRoute {
                        backend,
                        phase2_plain_localizer,
                        phase2_keyword_localizer,
                    })
                })
        })
        .collect::<Vec<_>>();
    let rotation =
        calibration_candidate_rotation(sample_bytes, sample.len(), candidate_routes.len());
    candidate_routes.rotate_left(rotation);

    let calibrated_at_unix_ms = current_unix_time_ms().map_err(|error| {
        AutorouteRoutingError::calibration_not_persisted(format!(
            "system clock is before the UNIX epoch ({error})"
        ))
    })?;
    let correctness_digest = canonical_match_digest(&canonical_matches(&reference_matches));

    let measured_routes = measure_candidate_routes(
        scanner,
        sample,
        &candidate_routes,
        &reference_key,
        admission_plan,
    )?;
    let route_timings = route_timings_with_cold_cost(scanner, measured_routes)?;
    if !route_timings
        .iter()
        .any(|entry| entry.measured_route() == Some(reference_route))
    {
        return Err(AutorouteRoutingError::calibration_not_persisted(
            "calibration candidate plan omitted the scalar correctness reference backend",
        ));
    }

    let mut decision = AutorouteDecision::from_peer_timing_evidence(
        ScanBackend::CpuFallback,
        sample_bytes,
        sample.len(),
        measurement_shape,
        correctness_digest,
        calibrated_at_unix_ms,
        route_timings,
    );
    let Some(resolved) = decision.resolved_routing_route() else {
        return Err(AutorouteRoutingError::calibration_not_persisted(format!(
            "calibration timing is inconclusive: no backend route's 95% confidence interval lies below every eligible peer backend; reduce competing host load and rerun calibration; evidence: {}",
            decision.confidence_diagnostic(false),
        )));
    };
    decision.backend = resolved.backend.label().to_string();
    decision.phase2_plain_localizer = resolved.phase2_plain_localizer;
    decision.phase2_keyword_localizer = resolved.phase2_keyword_localizer;

    tracing::info!(
        target: "keyhog::routing",
        backend = resolved.backend.label(),
        phase2_plain_localizer = resolved.phase2_plain_localizer,
        phase2_keyword_localizer = resolved.phase2_keyword_localizer,
        sample_chunks = sample.len(),
        sample_bytes,
        simd_baseline_ms = decision.simd_baseline_ms(),
        cpu_baseline_ms = decision.cpu_baseline_ms(),
        gpu_considered = gpu_candidate_allowed,
        cuda_baseline_ms = decision.baseline_timing_for_backend(ScanBackend::GpuCuda).map(BackendTimingEvidence::median_ms),
        wgpu_baseline_ms = decision.baseline_timing_for_backend(ScanBackend::GpuWgpu).map(BackendTimingEvidence::median_ms),
        trials = AUTOROUTE_CALIBRATION_TRIALS,
        "autoroute calibrated backend decision"
    );
    Ok(decision)
}

fn route_timings_with_cold_cost(
    scanner: &CompiledScanner,
    measured_routes: Vec<(MeasuredRoute, BackendTimingEvidence)>,
) -> Result<Vec<RouteTimingEvidence>, AutorouteRoutingError> {
    let mut route_timings = Vec::with_capacity(measured_routes.len());
    for (route, mut measured) in measured_routes {
        let backend = route.backend;
        if backend == ScanBackend::SimdCpu {
            let initialization_ns = scanner.simd_initialization_ns().ok_or_else(|| {
                AutorouteRoutingError::candidate_backend_rejected(
                    backend,
                    "Hyperscan materialized without initialization timing evidence",
                )
            })?;
            measured = measured.add_to_first_trial(initialization_ns);
            if simd_cold_warm_route_evidence(&measured).is_none() {
                return Err(AutorouteRoutingError::candidate_backend_rejected(
                    backend,
                    "Hyperscan cold/warm route evidence was incomplete or invalid",
                ));
            }
        }
        if is_gpu_backend(backend) {
            let backend_cold_ns = scanner
                .autoroute_calibration_gpu_backend_cold_ns(backend)
                .ok_or_else(|| {
                    AutorouteRoutingError::candidate_backend_rejected(
                        backend,
                        "GPU phase-2 program preparation evidence was missing",
                    )
                })?;
            let immutable_cold_ns = scanner
                .autoroute_calibration_gpu_shared_cold_ns()
                .saturating_add(backend_cold_ns);
            measured = measured.add_to_first_trial(immutable_cold_ns);
            if gpu_cold_warm_route_evidence(&measured).is_none() {
                return Err(AutorouteRoutingError::candidate_backend_rejected(
                    backend,
                    "GPU cold/warm route evidence was incomplete or invalid",
                ));
            }
        }
        route_timings.push(RouteTimingEvidence::new(route, measured));
    }
    Ok(route_timings)
}

pub(super) fn calibration_sample_bytes(sample: &[Chunk]) -> Result<u64, AutorouteRoutingError> {
    let sample_bytes: u64 = sample.iter().map(|c| c.data.len() as u64).sum();
    if sample.is_empty() || sample_bytes == 0 {
        return Err(AutorouteRoutingError::insufficient_calibration_sample(
            sample.len(),
            sample_bytes,
        ));
    }
    Ok(sample_bytes)
}

pub(super) fn calibration_candidate_rotation(
    sample_bytes: u64,
    sample_chunks: usize,
    candidates: usize,
) -> usize {
    if candidates <= 1 {
        return 0;
    }
    let size_band = 64_u32.saturating_sub(sample_bytes.leading_zeros()) as usize;
    size_band.wrapping_add(sample_chunks) % candidates
}

fn establish_scalar_reference(
    scanner: &CompiledScanner,
    sample: &[Chunk],
    admission_plan: Option<&Phase1AdmissionPlan>,
    route: MeasuredRoute,
) -> Vec<Vec<keyhog_core::RawMatch>> {
    // Establish the canonical finding set outside the rotated timed plan. The
    // always-present scalar engine is independent of optional accelerator
    // compilation and therefore remains the correctness oracle.
    scanner.clear_fragment_cache();
    let reference = scan_calibration_backend(scanner, sample, route, admission_plan);
    scanner.clear_fragment_cache();
    reference
}

#[cfg(test)]
pub(super) fn calibration_mismatch_field_names(
    reference: &[Vec<keyhog_core::RawMatch>],
    trial: &[Vec<keyhog_core::RawMatch>],
) -> Vec<&'static str> {
    differing_canonical_match_fields(&canonical_matches(reference), &canonical_matches(trial))
}

fn measure_candidate_routes(
    scanner: &CompiledScanner,
    sample: &[Chunk],
    routes: &[MeasuredRoute],
    reference_key: &[CanonicalMatch<'_>],
    admission_plan: Option<&Phase1AdmissionPlan>,
) -> Result<Vec<(MeasuredRoute, BackendTimingEvidence)>, AutorouteRoutingError> {
    if routes.is_empty() {
        return Err(AutorouteRoutingError::calibration_not_persisted(
            "eligible backend census produced no execution routes",
        ));
    }
    let mut measurements = routes
        .iter()
        .copied()
        .map(|route| (route, Vec::with_capacity(AUTOROUTE_CALIBRATION_TRIALS)))
        .collect::<Vec<_>>();

    // Capture every GPU route's real cold dispatch independently. CPU routes
    // receive one untimed route-specific warmup. After cold capture, warm every
    // GPU route without resetting another peer so all interleaved samples below
    // measure equivalent ready state.
    for (route, durations) in &mut measurements {
        if route.backend.is_gpu() {
            scanner
                .reset_autoroute_calibration_gpu_workload()
                .map_err(AutorouteRoutingError::calibration_not_persisted)?;
            durations.push(measure_candidate_trial(
                scanner,
                sample,
                *route,
                reference_key,
                admission_plan,
                1,
            )?);
        } else {
            let _ =
                measure_candidate_trial(scanner, sample, *route, reference_key, admission_plan, 0)?;
        }
    }
    for (route, _) in measurements
        .iter()
        .filter(|(route, _)| route.backend.is_gpu())
    {
        let _ = measure_candidate_trial(scanner, sample, *route, reference_key, admission_plan, 0)?;
    }

    // Rotate the route order every round. Sequentially measuring all trials for
    // one backend lets thermal, boost, and unrelated host drift masquerade as a
    // backend advantage; interleaving makes every peer observe the same drift.
    for round in 0..AUTOROUTE_CALIBRATION_TRIALS {
        for offset in 0..measurements.len() {
            let index = (round + offset) % measurements.len();
            let (route, durations) = &mut measurements[index];
            if durations.len() >= AUTOROUTE_CALIBRATION_TRIALS {
                continue;
            }
            let trial = durations.len() + 1;
            durations.push(measure_candidate_trial(
                scanner,
                sample,
                *route,
                reference_key,
                admission_plan,
                trial,
            )?);
        }
    }
    scanner.clear_fragment_cache();

    measurements
        .into_iter()
        .map(|(route, durations)| {
            BackendTimingEvidence::from_durations(durations)
                .map(|timing| (route, timing))
                .ok_or_else(|| {
                    AutorouteRoutingError::candidate_backend_rejected(
                        route.backend,
                        "candidate timing evidence had no recorded trials",
                    )
                })
        })
        .collect()
}

fn measure_candidate_trial(
    scanner: &CompiledScanner,
    sample: &[Chunk],
    route: MeasuredRoute,
    reference_key: &[CanonicalMatch<'_>],
    admission_plan: Option<&Phase1AdmissionPlan>,
    trial: usize,
) -> Result<Duration, AutorouteRoutingError> {
    let backend = route.backend;
    let reported_trial = trial.max(1);
    scanner.clear_fragment_cache();
    let gpu_degrade_count_before = if is_gpu_backend(backend) {
        Some(scanner.runtime_status().gpu_degrade_count)
    } else {
        None
    };
    let (matches, dur) = timed(|| scan_calibration_backend(scanner, sample, route, admission_plan));
    if let Some(before) = gpu_degrade_count_before {
        let after = scanner.runtime_status().gpu_degrade_count;
        if after != before {
            tracing::error!(
                target: "keyhog::routing",
                backend = backend.label(),
                gpu_degrade_count_before = before,
                gpu_degrade_count_after = after,
                "backend rejected by autoroute GPU degrade check"
            );
            scanner.clear_fragment_cache();
            return Err(AutorouteRoutingError::candidate_backend_rejected(
                backend,
                format!("GPU degrade count changed from {before} to {after} during calibration"),
            ));
        }
    }
    if let Err(error) =
        calibration_candidate_parity_result(backend, reported_trial, &matches, reference_key)
    {
        let trial_key = canonical_matches(&matches);
        let only_in_reference_count =
            sorted_calibration_difference_count(reference_key, &trial_key);
        let only_in_trial_count = sorted_calibration_difference_count(&trial_key, reference_key);
        let differing_fields = differing_canonical_match_fields(reference_key, &trial_key);
        if backend == ScanBackend::CpuFallback {
            tracing::error!(
                target: "keyhog::routing",
                backend = backend.label(),
                trial = reported_trial,
                reference_match_count = reference_key.len(),
                trial_match_count = trial_key.len(),
                only_in_reference_count,
                only_in_trial_count,
                differing_fields = ?differing_fields,
                "reference backend produced inconsistent calibration results; autoroute calibration aborted"
            );
        } else {
            tracing::error!(
                target: "keyhog::routing",
                backend = backend.label(),
                trial = reported_trial,
                reference_match_count = reference_key.len(),
                trial_match_count = trial_key.len(),
                only_in_reference_count,
                only_in_trial_count,
                differing_fields = ?differing_fields,
                "backend rejected by autoroute parity check"
            );
        }
        scanner.clear_fragment_cache();
        return Err(error);
    }
    Ok(dur)
}

fn sorted_calibration_difference_count<T: Ord>(left: &[T], right: &[T]) -> usize {
    let mut missing_occurrences = 0usize;
    let mut left_index = 0usize;
    let mut right_index = 0usize;
    while left_index < left.len() {
        let record = &left[left_index];
        let left_end = run_end(left, left_index);
        while right_index < right.len() && &right[right_index] < record {
            right_index = run_end(right, right_index);
        }
        let right_count = if right.get(right_index) == Some(record) {
            run_end(right, right_index) - right_index
        } else {
            0
        };
        let missing = (left_end - left_index).saturating_sub(right_count);
        if missing == 0 {
            left_index = left_end;
            continue;
        }
        missing_occurrences = missing_occurrences.saturating_add(missing);
        left_index = left_end;
    }
    missing_occurrences
}

fn run_end<T: Eq>(records: &[T], start: usize) -> usize {
    let mut end = start + 1;
    while end < records.len() && records[end] == records[start] {
        end += 1;
    }
    end
}

pub(super) fn calibration_candidate_parity_result(
    backend: ScanBackend,
    trial: usize,
    matches: &[Vec<keyhog_core::RawMatch>],
    reference_key: &[CanonicalMatch<'_>],
) -> Result<(), AutorouteRoutingError> {
    if canonical_matches_equal_reference(matches, reference_key) {
        return Ok(());
    }
    if backend == ScanBackend::CpuFallback {
        return Err(AutorouteRoutingError::inconsistent_reference_backend(trial));
    }
    Err(AutorouteRoutingError::candidate_backend_rejected(
        backend,
        "candidate findings diverged from the scalar reference",
    ))
}

/// Run every calibration candidate through the same backend-dispatch boundary
/// used by in-process batches and daemon requests. The boundary selects the
/// coalesced Hyperscan implementation and the ordinary CPU or GPU batch path.
fn scan_calibration_backend(
    scanner: &CompiledScanner,
    sample: &[Chunk],
    route: MeasuredRoute,
    admission_plan: Option<&Phase1AdmissionPlan>,
) -> Vec<Vec<keyhog_core::RawMatch>> {
    scanner.scan_coalesced_with_backend_admission_and_route(
        sample,
        route.backend,
        admission_plan,
        route.execution_route(),
    )
}

fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let out = f();
    (out, start.elapsed())
}

fn current_unix_time_ms() -> Result<u128, std::time::SystemTimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibration_difference_reports_exact_multiset_count() {
        let mut left = vec!["record-00".to_string(); 4];
        left.extend((1..37).map(|index| format!("record-{index:02}")));
        let right = vec!["record-00".to_string()];

        assert_eq!(sorted_calibration_difference_count(&left, &right), 39);
    }
}
