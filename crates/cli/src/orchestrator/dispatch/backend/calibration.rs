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
use keyhog_scanner::telemetry::ScannerCoverageSnapshot;
use keyhog_scanner::{CompiledScanner, Phase1AdmissionPlan};
#[cfg(feature = "gpu")]
use std::time::Instant;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::evidence::{
    canonical_match_differences, canonical_match_digest, canonical_matches,
    canonical_matches_equal_reference, differing_canonical_match_fields,
    gpu_cold_warm_route_evidence, simd_cold_warm_route_evidence, AutorouteDecision,
    BackendTimingEvidence, CanonicalMatch, MeasuredRoute, RouteTimingEvidence,
};
use super::workload::MeasurementShapeEvidence;
use super::{is_gpu_backend, AutorouteRoutingError, AUTOROUTE_CALIBRATION_TRIALS};

const MIN_WARM_TRIAL_WINDOW: Duration = Duration::from_millis(10);
const MAX_WARM_TRIAL_REPETITIONS: u32 = 1_024;

#[cfg(any(test, feature = "ci-lean"))]
const TEST_TIMING_FIXTURE_ENV: &str = "KEYHOG_CI_AUTOROUTE_TIMING_FIXTURE";
#[cfg(any(test, feature = "ci-lean"))]
const TEST_TIMING_FIXTURE_AUTH_ENV: &str = "KEYHOG_CI_AUTOROUTE_FIXTURE_AUTH";
#[cfg(any(test, feature = "ci-lean"))]
const TEST_TIMING_FIXTURE_AUTH: &str = "bench-backend-parity-v1";

#[cfg(any(test, feature = "ci-lean"))]
fn apply_test_timing_fixture(
    route_timings: &mut [RouteTimingEvidence],
) -> Result<(), AutorouteRoutingError> {
    let Some(fixture) = std::env::var_os(TEST_TIMING_FIXTURE_ENV) else {
        return Ok(());
    };
    if std::env::var(TEST_TIMING_FIXTURE_AUTH_ENV).as_deref() != Ok(TEST_TIMING_FIXTURE_AUTH) {
        return Err(AutorouteRoutingError::calibration_not_persisted(format!(
            "test-only autoroute timing fixture authorization failed; \
             {TEST_TIMING_FIXTURE_AUTH_ENV} must equal {TEST_TIMING_FIXTURE_AUTH:?}"
        )));
    }
    let fixture = fixture.to_string_lossy();
    for entry in route_timings {
        let route = entry.measured_route().ok_or_else(|| {
            AutorouteRoutingError::calibration_not_persisted(
                "test timing fixture encountered an invalid measured route",
            )
        })?;
        let trials_ns = match fixture.as_ref() {
            // Constant, widely separated peers make both one-shot and warm
            // route confidence deterministic while real scans still establish
            // parity receipts and finding identity before this test-only swap.
            "confidence-separated-v1" => {
                let trial_ns = if route.backend == ScanBackend::CpuFallback {
                    1_000_000
                } else {
                    10_000_000
                };
                vec![trial_ns; AUTOROUTE_CALIBRATION_TRIALS]
            }
            // Distinct medians with overlapping intervals model noisy host
            // evidence. Nothing separates, so calibration resolves the dead
            // heat to the lowest-complexity backend and records that the route
            // is permitted by the evidence rather than proved by it.
            "overlapping-v1" => {
                if AUTOROUTE_CALIBRATION_TRIALS != 7 {
                    return Err(AutorouteRoutingError::calibration_not_persisted(
                        "overlapping-v1 timing fixture requires exactly seven calibration trials",
                    ));
                }
                if route.backend == ScanBackend::CpuFallback {
                    vec![
                        18_000_000, 20_000_000, 20_000_000, 20_000_000, 20_000_000, 20_000_000,
                        22_000_000,
                    ]
                } else {
                    vec![
                        19_000_000, 16_000_000, 18_000_000, 18_000_000, 18_000_000, 18_000_000,
                        22_000_000,
                    ]
                }
            }
            _ => {
                return Err(AutorouteRoutingError::calibration_not_persisted(format!(
                    "unsupported {TEST_TIMING_FIXTURE_ENV} value {fixture:?}; expected \
                         confidence-separated-v1 or overlapping-v1"
                )));
            }
        };
        entry.timing = BackendTimingEvidence::from_trial_ns(trials_ns).ok_or_else(|| {
            AutorouteRoutingError::calibration_not_persisted(
                "test timing fixture could not construct timing evidence",
            )
        })?;
    }
    eprintln!(
        "WARN: applying explicit test-only autoroute timing fixture {fixture:?}; \
         real candidate scans, parity receipts, and confidence selection were retained"
    );
    Ok(())
}

fn eligible_pipeline_depths(
    scanner: &CompiledScanner,
    backend: ScanBackend,
) -> Result<Vec<u8>, AutorouteRoutingError> {
    if !backend.is_gpu() {
        return Ok(vec![1]);
    }
    #[cfg(feature = "gpu")]
    {
        scanner
            .eligible_gpu_resident_pipeline_depths(backend)
            .map_err(|error| AutorouteRoutingError::candidate_backend_rejected(backend, error))
    }
    #[cfg(not(feature = "gpu"))]
    {
        let _ = scanner;
        Err(AutorouteRoutingError::candidate_backend_rejected(
            backend,
            "GPU route is present in calibration without the CLI GPU feature",
        ))
    }
}

pub(super) fn calibrate_fastest_correct_backend(
    scanner: &CompiledScanner,
    _pattern_count: usize,
    sample: &[Chunk],
    measurement_shape: MeasurementShapeEvidence,
    eligible_backend_labels: &[String],
    admission_plan: Option<&Phase1AdmissionPlan>,
    workload_identity: &str,
    detector_digest: &str,
    config_digest: &str,
) -> Result<AutorouteDecision, AutorouteRoutingError> {
    let sample_bytes = calibration_sample_bytes(sample)?;

    let reference_route = MeasuredRoute {
        backend: ScanBackend::CpuFallback,
        phase2_plain_localizer: false,
        phase2_keyword_localizer: false,
        gpu_pipeline_depth: 1,
    };
    let reference = establish_scalar_reference(scanner, sample, admission_plan, reference_route)?;
    let reference_coverage = reference.coverage;
    let reference_matches = reference.matches;
    let reference_key = canonical_matches(&reference_matches);
    if !reference_coverage.is_empty() {
        // Calibration continues over a coverage shape every candidate must
        // reproduce, so the comparison stays sound. It is still an operator
        // fact: the persisted route was measured on a sample that this resolved
        // configuration does not fully cover, and the real scan will not cover
        // it either.
        eprintln!(
            "keyhog: WARNING: autoroute calibration sample {} is not fully covered by this scan \
             configuration ({}); every candidate must reproduce exactly this coverage, and the \
             persisted route therefore describes only the bytes this configuration actually \
             scans",
            keyhog_core::hex_encode(&measurement_shape.shape_digest),
            render_coverage_gaps(reference_coverage)
        );
    }

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

    let mut candidate_routes = Vec::new();
    for backend in candidate_backends {
        let depths = eligible_pipeline_depths(scanner, backend)?;
        for gpu_pipeline_depth in depths {
            for phase2_plain_localizer in [false, true] {
                for phase2_keyword_localizer in [false, true] {
                    candidate_routes.push(MeasuredRoute {
                        backend,
                        phase2_plain_localizer,
                        phase2_keyword_localizer,
                        gpu_pipeline_depth,
                    });
                }
            }
        }
    }
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
        reference_coverage,
    )?;
    let route_timings = route_timings_with_cold_cost(
        scanner,
        measured_routes,
        sample,
        &reference_key,
        workload_identity,
        detector_digest,
        config_digest,
    )?;
    #[cfg(any(test, feature = "ci-lean"))]
    let route_timings = {
        let mut route_timings = route_timings;
        apply_test_timing_fixture(&mut route_timings)?;
        route_timings
    };
    if !route_timings
        .iter()
        .any(|entry| entry.measured_route() == Some(reference_route))
    {
        return Err(AutorouteRoutingError::calibration_not_persisted(
            "calibration candidate plan omitted the scalar correctness reference backend",
        ));
    }

    let compiled_default_route = scanner.default_execution_route();
    let mut decision = AutorouteDecision::from_peer_timing_evidence(
        ScanBackend::CpuFallback,
        sample_bytes,
        sample.len(),
        measurement_shape,
        correctness_digest,
        calibrated_at_unix_ms,
        route_timings,
        compiled_default_route.phase2_plain_localizer,
        compiled_default_route.phase2_keyword_localizer,
    );
    let Some(resolved) = decision.resolved_routing_route() else {
        return Err(AutorouteRoutingError::calibration_not_persisted(format!(
            "calibration timing does not resolve one route: the measured points disagree about which backend to run, or no candidate produced usable timing evidence; reduce competing host load and rerun calibration; evidence: {}",
            decision.confidence_diagnostic(false),
        )));
    };
    let confidence_separated = decision.has_confidence_supported_route();
    decision.backend = resolved.backend.label().to_string();
    decision.phase2_plain_localizer = resolved.phase2_plain_localizer;
    decision.phase2_keyword_localizer = resolved.phase2_keyword_localizer;
    decision.gpu_pipeline_depth = resolved.gpu_pipeline_depth;

    let keyword_triggers = admission_plan.map(Phase1AdmissionPlan::phase2_keyword_triggers);
    tracing::info!(
        target: "keyhog::routing",
        backend = resolved.backend.label(),
        phase2_plain_localizer = resolved.phase2_plain_localizer,
        phase2_keyword_localizer = resolved.phase2_keyword_localizer,
        gpu_pipeline_depth = resolved.gpu_pipeline_depth,
        confidence_separated,
        selection_basis = if confidence_separated {
            "peer-separated-95pct-confidence"
        } else {
            "unseparated-dead-heat-lowest-complexity-backend"
        },
        sample_chunks = sample.len(),
        sample_bytes,
        keyword_trigger_chunks = ?keyword_triggers.map(|summary| summary.keyword_trigger_chunks),
        keyword_trigger_bytes = ?keyword_triggers.map(|summary| summary.keyword_trigger_bytes),
        keyword_trigger_count = ?keyword_triggers.map(|summary| summary.keyword_trigger_count),
        simd_baseline_ms = decision.simd_baseline_ms(),
        cpu_baseline_ms = decision.cpu_baseline_ms(),
        gpu_considered = gpu_candidate_allowed,
        cuda_baseline_ms = decision.baseline_timing_for_backend(ScanBackend::GpuCuda).map(BackendTimingEvidence::median_ms),
        metal_baseline_ms = decision.baseline_timing_for_backend(ScanBackend::GpuMetal).map(BackendTimingEvidence::median_ms),
        wgpu_baseline_ms = decision.baseline_timing_for_backend(ScanBackend::GpuWgpu).map(BackendTimingEvidence::median_ms),
        trials = AUTOROUTE_CALIBRATION_TRIALS,
        "autoroute calibrated backend decision"
    );
    Ok(decision)
}

fn route_timings_with_cold_cost(
    scanner: &CompiledScanner,
    measured_routes: Vec<(MeasuredRoute, BackendTimingEvidence)>,
    sample: &[Chunk],
    reference_key: &[CanonicalMatch<'_>],
    workload_identity: &str,
    detector_digest: &str,
    config_digest: &str,
) -> Result<Vec<RouteTimingEvidence>, AutorouteRoutingError> {
    #[cfg(not(feature = "gpu"))]
    let _ = (
        sample,
        reference_key,
        workload_identity,
        detector_digest,
        config_digest,
    );
    let mut route_timings = Vec::with_capacity(measured_routes.len());
    for (route, mut measured) in measured_routes {
        let backend = route.backend;
        #[cfg(feature = "gpu")]
        let ordered_device_measurement = if backend.is_gpu() {
            measure_ordered_gpu_device_route(
                scanner,
                sample,
                route,
                reference_key,
                workload_identity,
                detector_digest,
                config_digest,
            )?
        } else {
            None
        };
        #[cfg(feature = "gpu")]
        if let Some((_, timing)) = &ordered_device_measurement {
            measured = timing.clone();
        }
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
        if is_gpu_backend(backend) && {
            #[cfg(feature = "gpu")]
            {
                ordered_device_measurement.is_none()
            }
            #[cfg(not(feature = "gpu"))]
            {
                true
            }
        } {
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
        let peer_identity = if backend.is_gpu() {
            #[cfg(feature = "gpu")]
            if let Some((device_route, _)) = &ordered_device_measurement {
                Some(format!(
                    "ordered-device-set:{}",
                    device_route.authenticated_digest
                ))
            } else {
                Some(
                    scanner
                        .acquired_gpu_peer_identity(backend)
                        .map_err(|error| {
                            AutorouteRoutingError::candidate_backend_rejected(backend, error)
                        })?,
                )
            }
            #[cfg(not(feature = "gpu"))]
            {
                return Err(AutorouteRoutingError::candidate_backend_rejected(
                    backend,
                    "GPU timing evidence cannot be built without the CLI GPU feature",
                ));
            }
        } else {
            None
        };
        let gpu_pipeline = if backend.is_gpu() {
            #[cfg(feature = "gpu")]
            {
                let capability =
                    scanner
                        .gpu_resident_dispatch_capability(backend)
                        .map_err(|error| {
                            AutorouteRoutingError::candidate_backend_rejected(backend, error)
                        })?;
                let eligible_depths = scanner
                    .eligible_gpu_resident_pipeline_depths(backend)
                    .map_err(|error| {
                        AutorouteRoutingError::candidate_backend_rejected(backend, error)
                    })?;
                if !eligible_depths.contains(&route.gpu_pipeline_depth) {
                    return Err(AutorouteRoutingError::candidate_backend_rejected(
                        backend,
                        format!(
                            "pipeline depth {} is not eligible for resident capability {capability}",
                            route.gpu_pipeline_depth
                        ),
                    ));
                }
                let (input_capacity, match_capacity) = scanner
                    .gpu_resident_pipeline_slot_capacities(route.gpu_pipeline_depth)
                    .map_err(|error| {
                        AutorouteRoutingError::candidate_backend_rejected(backend, error)
                    })?;
                Some((
                    capability.to_string(),
                    u64::try_from(input_capacity).map_err(|_| {
                        AutorouteRoutingError::candidate_backend_rejected(
                            backend,
                            "GPU resident slot input capacity exceeds u64",
                        )
                    })?,
                    match_capacity,
                ))
            }
            #[cfg(not(feature = "gpu"))]
            {
                return Err(AutorouteRoutingError::candidate_backend_rejected(
                    backend,
                    "GPU timing evidence cannot be built without the CLI GPU feature",
                ));
            }
        } else {
            None
        };
        let timing = RouteTimingEvidence::new_with_peer_identity(
            route,
            measured,
            peer_identity,
            gpu_pipeline,
        );
        #[cfg(feature = "gpu")]
        let timing = match ordered_device_measurement {
            Some((device_route, _)) => timing
                .bind_ordered_device_route(device_route)
                .map_err(AutorouteRoutingError::calibration_not_persisted)?,
            None => timing,
        };
        route_timings.push(timing);
    }
    Ok(route_timings)
}

#[cfg(feature = "gpu")]
fn measure_ordered_gpu_device_route(
    scanner: &CompiledScanner,
    sample: &[Chunk],
    measured_route: MeasuredRoute,
    reference_key: &[CanonicalMatch<'_>],
    workload_identity: &str,
    detector_digest: &str,
    config_digest: &str,
) -> Result<
    Option<(
        keyhog_scanner::gpu::device_set::OrderedGpuDeviceRoute,
        BackendTimingEvidence,
    )>,
    AutorouteRoutingError,
> {
    use keyhog_scanner::gpu::device_set::{
        CalibratedGpuDevice, DeviceTimingEvidence, OrderedGpuDeviceRoute,
    };

    const MAX_PROCESS_RESIDENT_BYTES: u64 = 4 << 30;
    let backend = measured_route.backend;
    let census = keyhog_scanner::gpu::enumerate_gpu_device_census().map_err(|error| {
        AutorouteRoutingError::candidate_backend_rejected(
            backend,
            format!("ordered GPU census failed: {error}"),
        )
    })?;
    let exposures = census
        .eligible
        .iter()
        .map(|index| {
            census.exposures.get(*index).ok_or_else(|| {
                AutorouteRoutingError::candidate_backend_rejected(
                    backend,
                    format!("ordered GPU census index {index} is out of bounds"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if exposures.len() < 2
        || exposures
            .iter()
            .any(|exposure| exposure.api.scan_backend() != backend)
    {
        return Ok(None);
    }
    let sample_bytes = calibration_sample_bytes(sample)?;
    let capacities = exposures
        .iter()
        .map(|exposure| exposure.capacity_bytes)
        .collect::<Vec<_>>();
    let total_capacity = capacities
        .iter()
        .try_fold(0u64, |total, capacity| total.checked_add(*capacity))
        .ok_or_else(|| {
            AutorouteRoutingError::candidate_backend_rejected(
                backend,
                "ordered GPU physical capacity sum overflows u64",
            )
        })?;
    let process_resident_limit_bytes = total_capacity.min(MAX_PROCESS_RESIDENT_BYTES);
    let resident_budgets = keyhog_scanner::gpu::device_set::derive_resident_budgets(
        &capacities,
        process_resident_limit_bytes,
    )
    .map_err(|error| {
        AutorouteRoutingError::candidate_backend_rejected(
            backend,
            format!("ordered GPU resident budget derivation failed: {error}"),
        )
    })?;
    let mut provisional_devices = Vec::new();
    provisional_devices
        .try_reserve_exact(exposures.len())
        .map_err(|error| {
            AutorouteRoutingError::candidate_backend_rejected(
                backend,
                format!("ordered GPU calibration device reserve failed: {error}"),
            )
        })?;
    for (exposure, resident_budget_bytes) in exposures.into_iter().zip(resident_budgets) {
        provisional_devices.push(CalibratedGpuDevice {
            api: exposure.api,
            api_ordinal: exposure.api_ordinal,
            physical_identity: exposure.physical_identity.clone(),
            topology_identity: exposure.topology_identity.clone(),
            name: exposure.name.clone(),
            vendor_id: exposure.vendor_id,
            device_id: exposure.device_id,
            software_eligible: !exposure.is_software,
            display_eligible: !exposure.is_display_only,
            driver_identity: exposure.driver_identity.clone(),
            runtime_identity: exposure.runtime_identity.clone(),
            capacity_bytes: exposure.capacity_bytes,
            workload_weight: 1,
            timing: DeviceTimingEvidence {
                sample_bytes,
                trials_ns: vec![1],
            },
            resident_budget_bytes,
        });
    }
    let provisional_route = OrderedGpuDeviceRoute::new(
        workload_identity.to_string(),
        detector_digest.to_string(),
        config_digest.to_string(),
        process_resident_limit_bytes,
        provisional_devices,
    )
    .map_err(|error| {
        AutorouteRoutingError::candidate_backend_rejected(
            backend,
            format!("ordered GPU calibration route is invalid: {error}"),
        )
    })?;
    let provisional = keyhog_scanner::gpu::acquire_ordered_gpu_device_set(&provisional_route)
        .map_err(|error| {
            AutorouteRoutingError::candidate_backend_rejected(
                backend,
                format!("ordered GPU calibration acquisition failed: {error}"),
            )
        })?;

    let mut device_trials = Vec::new();
    device_trials
        .try_reserve_exact(provisional_route.devices.len())
        .map_err(|error| {
            AutorouteRoutingError::candidate_backend_rejected(
                backend,
                format!("ordered GPU timing reserve failed: {error}"),
            )
        })?;
    for device_index in 0..provisional_route.devices.len() {
        let mut trials = Vec::with_capacity(AUTOROUTE_CALIBRATION_TRIALS);
        for trial in 0..AUTOROUTE_CALIBRATION_TRIALS {
            let started = Instant::now();
            let matches = scanner
                .scan_coalesced_on_ordered_gpu_device(
                    sample,
                    backend,
                    &provisional_route,
                    &provisional,
                    device_index,
                    measured_route.execution_route(),
                )
                .map_err(|error| {
                    AutorouteRoutingError::candidate_backend_rejected(
                        backend,
                        format!("ordered GPU device {device_index} dispatch failed: {error}"),
                    )
                })?;
            let elapsed = started.elapsed().as_nanos().max(1);
            calibration_candidate_parity_result(backend, trial, &matches, reference_key)?;
            trials.push(u64::try_from(elapsed).map_err(|_| {
                AutorouteRoutingError::candidate_backend_rejected(
                    backend,
                    "ordered GPU device timing exceeds u64 nanoseconds",
                )
            })?);
        }
        device_trials.push(trials);
    }
    drop(provisional);

    let medians = device_trials
        .iter()
        .map(|trials| {
            let mut ordered = trials.clone();
            ordered.sort_unstable();
            ordered[ordered.len() / 2]
        })
        .collect::<Vec<_>>();
    let slowest = medians.iter().copied().max().unwrap_or(1);
    let mut devices = provisional_route.devices;
    for ((device, trials), median) in devices.iter_mut().zip(device_trials).zip(medians) {
        let scaled = u128::from(slowest).checked_mul(1_000_000).ok_or_else(|| {
            AutorouteRoutingError::candidate_backend_rejected(
                backend,
                "ordered GPU throughput weight overflows u128",
            )
        })? / u128::from(median.max(1));
        device.workload_weight = u64::try_from(scaled.clamp(1, 1_000_000_000)).map_err(|_| {
            AutorouteRoutingError::candidate_backend_rejected(
                backend,
                "ordered GPU throughput weight exceeds u64",
            )
        })?;
        device.timing = DeviceTimingEvidence {
            sample_bytes,
            trials_ns: trials,
        };
    }
    let route = OrderedGpuDeviceRoute::new(
        workload_identity.to_string(),
        detector_digest.to_string(),
        config_digest.to_string(),
        process_resident_limit_bytes,
        devices,
    )
    .map_err(|error| {
        AutorouteRoutingError::candidate_backend_rejected(
            backend,
            format!("measured ordered GPU route is invalid: {error}"),
        )
    })?;
    let timing =
        measure_complete_ordered_gpu_route(scanner, sample, measured_route, reference_key, &route)?;
    Ok(Some((route, timing)))
}

#[cfg(feature = "gpu")]
fn measure_complete_ordered_gpu_route(
    scanner: &CompiledScanner,
    sample: &[Chunk],
    measured_route: MeasuredRoute,
    reference_key: &[CanonicalMatch<'_>],
    route: &keyhog_scanner::gpu::device_set::OrderedGpuDeviceRoute,
) -> Result<BackendTimingEvidence, AutorouteRoutingError> {
    let backend = measured_route.backend;
    let cold_started = Instant::now();
    let acquired = keyhog_scanner::gpu::acquire_ordered_gpu_device_set(route).map_err(|error| {
        AutorouteRoutingError::candidate_backend_rejected(
            backend,
            format!("measured ordered GPU route acquisition failed: {error}"),
        )
    })?;
    let mut route_trials = Vec::with_capacity(AUTOROUTE_CALIBRATION_TRIALS);
    for trial in 0..AUTOROUTE_CALIBRATION_TRIALS {
        let started = if trial == 0 {
            cold_started
        } else {
            Instant::now()
        };
        let matches = scanner
            .scan_coalesced_with_ordered_gpu_device_route(
                sample,
                backend,
                route,
                &acquired,
                measured_route.execution_route(),
            )
            .map_err(|error| {
                AutorouteRoutingError::candidate_backend_rejected(
                    backend,
                    format!("ordered GPU route dispatch failed: {error}"),
                )
            })?;
        route_trials.push(started.elapsed());
        calibration_candidate_parity_result(backend, trial, &matches, reference_key)?;
    }
    BackendTimingEvidence::from_durations(route_trials).ok_or_else(|| {
        AutorouteRoutingError::candidate_backend_rejected(
            backend,
            "ordered GPU route produced no timing evidence",
        )
    })
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
) -> Result<CalibrationTrialOutcome, AutorouteRoutingError> {
    // Establish the canonical finding set outside the rotated timed plan. The
    // always-present scalar engine is independent of optional accelerator
    // compilation and therefore remains the correctness oracle. It also fixes
    // the coverage shape every candidate must reproduce exactly.
    scanner.clear_fragment_cache();
    let reference = scan_calibration_backend(scanner, sample, route, admission_plan, None)?;
    scanner.clear_fragment_cache();
    Ok(reference)
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
    reference_coverage: ScannerCoverageSnapshot,
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
                reference_coverage,
            )?);
        } else {
            // LAW10: only the warm-up timing value is discarded; trial errors propagate through `?` and abort calibration.
            let _ = measure_candidate_trial(
                scanner,
                sample,
                *route,
                reference_key,
                admission_plan,
                0,
                reference_coverage,
            )?;
        }
    }
    for (route, _) in measurements
        .iter()
        .filter(|(route, _)| route.backend.is_gpu())
    {
        // LAW10: only the warm-up timing value is discarded; trial errors propagate through `?` and abort calibration.
        let _ = measure_candidate_trial(
            scanner,
            sample,
            *route,
            reference_key,
            admission_plan,
            0,
            reference_coverage,
        )?;
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
                reference_coverage,
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
    reference_coverage: ScannerCoverageSnapshot,
) -> Result<Duration, AutorouteRoutingError> {
    let backend = route.backend;
    let reported_trial = trial.max(1);
    let preserve_single_dispatch =
        reported_trial == 1 && (backend == ScanBackend::SimdCpu || backend.is_gpu());
    let mut total = Duration::ZERO;
    let mut repetitions = 0_u32;

    loop {
        scanner.clear_fragment_cache();
        let trial_timer =
            keyhog_profile::decision_timer(keyhog_profile::Stage::AutorouteCalibration);
        let outcome = scan_calibration_backend(
            scanner,
            sample,
            route,
            admission_plan,
            Some(reference_coverage),
        )?;
        total = total.saturating_add(trial_timer.finish());
        repetitions += 1;

        validate_calibration_candidate_matches(
            scanner,
            backend,
            reported_trial,
            &outcome.matches,
            reference_key,
        )?;

        if preserve_single_dispatch
            || total >= MIN_WARM_TRIAL_WINDOW
            || repetitions >= MAX_WARM_TRIAL_REPETITIONS
        {
            break;
        }
    }

    Ok(total / repetitions)
}

fn validate_calibration_candidate_matches(
    scanner: &CompiledScanner,
    backend: ScanBackend,
    reported_trial: usize,
    matches: &[Vec<keyhog_core::RawMatch>],
    reference_key: &[CanonicalMatch<'_>],
) -> Result<(), AutorouteRoutingError> {
    let Err(error) =
        calibration_candidate_parity_result(backend, reported_trial, matches, reference_key)
    else {
        return Ok(());
    };

    let trial_key = canonical_matches(matches);
    // Positional field comparison only means something when both sides have the
    // same number of records. One extra match shifts every later pair, so the
    // list would name almost every field and say nothing.
    let differing_fields = (reference_key.len() == trial_key.len())
        .then(|| differing_canonical_match_fields(reference_key, &trial_key))
        .unwrap_or_default(); // LAW10: unequal canonical lengths need no field-name diff; the preceding boolean still records the parity failure.
    tracing::error!(
        target: "keyhog::routing",
        backend = backend.label(),
        trial = reported_trial,
        reference_match_count = reference_key.len(),
        trial_match_count = trial_key.len(),
        only_in_reference_count =
            sorted_calibration_difference_count(reference_key, &trial_key),
        only_in_trial_count = sorted_calibration_difference_count(&trial_key, reference_key),
        differing_fields = ?differing_fields,
        message = if backend == ScanBackend::CpuFallback {
            "reference backend produced inconsistent calibration results; autoroute calibration aborted"
        } else {
            "backend rejected by autoroute parity check"
        },
    );
    scanner.clear_fragment_cache();
    Err(error)
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

/// Enough differing records to recognise a pattern, few enough to stay one
/// readable line.
const PARITY_EXAMPLES: usize = 3;

/// Whether a candidate backend reproduced the scalar reference exactly.
///
/// A rejection blocks the entire calibration, so the message carries the
/// evidence an operator needs to act: how many records each side had, how many
/// were unique to each, and a few of them named by detector, file, line and
/// offset. Those fields are already redacted, and only eight hex characters of
/// the credential digest appear, so nothing here is secret-bearing.
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
    let trial_key = canonical_matches(matches);
    let only_in_reference = canonical_match_differences(reference_key, &trial_key, PARITY_EXAMPLES);
    let only_in_trial = canonical_match_differences(&trial_key, reference_key, PARITY_EXAMPLES);
    Err(AutorouteRoutingError::candidate_findings_diverged(
        backend,
        &format!(
            "candidate findings diverged from the scalar reference: \
             {reference_count} reference matches against {trial_count}, \
             {only_in_reference_count} only in the reference{reference_examples}, \
             {only_in_trial_count} only in the candidate{trial_examples}",
            reference_count = reference_key.len(),
            trial_count = trial_key.len(),
            only_in_reference_count =
                sorted_calibration_difference_count(reference_key, &trial_key),
            only_in_trial_count = sorted_calibration_difference_count(&trial_key, reference_key),
            reference_examples = render_parity_examples(&only_in_reference),
            trial_examples = render_parity_examples(&only_in_trial),
        ),
    ))
}

fn render_parity_examples(examples: &[String]) -> String {
    if examples.is_empty() {
        return String::new();
    }
    format!(" (e.g. {})", examples.join("; "))
}

/// Run every calibration candidate through the same backend-dispatch boundary
/// used by in-process batches and daemon requests. The boundary selects the
/// coalesced Hyperscan implementation and the ordinary CPU or GPU batch path.
fn scan_calibration_backend(
    scanner: &CompiledScanner,
    sample: &[Chunk],
    route: MeasuredRoute,
    admission_plan: Option<&Phase1AdmissionPlan>,
    expected_coverage: Option<ScannerCoverageSnapshot>,
) -> Result<CalibrationTrialOutcome, AutorouteRoutingError> {
    let coverage_before = ScannerCoverageSnapshot::capture();
    let outcome = scanner
        .scan_coalesced_with_backend_admission_route_and_recovery(
            sample,
            route.backend,
            admission_plan,
            route.execution_route(),
            false,
        )
        .map_err(|error| {
            AutorouteRoutingError::candidate_backend_rejected(
                route.backend,
                format!("calibration dispatch failed: {error}"),
            )
        })?;
    let coverage = ScannerCoverageSnapshot::capture().saturating_delta(coverage_before);
    // What makes a coverage gap disqualifying is that ONE candidate covered
    // less than its peers, because then its time is not a time for the same
    // work. A gap every candidate reproduces identically is a property of the
    // sample under this resolved configuration, not a degraded backend: a
    // deterministic ceiling such as `max_decode_bytes` is part of the config
    // digest, so the real scan will skip exactly the same bytes and the
    // measurement describes exactly the work it will do.
    //
    // Rejecting on any nonzero gap threw away complete, valid calibrations.
    // Measured: `crates/` ran a full 346-second sweep across eight workload
    // buckets and persisted nothing, because one probe batch held a chunk over
    // the decode ceiling and the very first reference trial was refused. Every
    // later automatic scan of that tree then failed closed without a route.
    //
    // The two directions of a difference are not equally informative, and only
    // one of them is a fact.
    //
    // A candidate ABOVE the reference on any counter definitely ran that
    // counter and definitely skipped more, so it covered less than the oracle
    // it is being timed against. That is a refusal.
    //
    // A candidate BELOW the reference is ambiguous, because an absent counter
    // and a real zero are the same value. It can mean the candidate expanded
    // content the reference declined, or it can mean the candidate never
    // reached the site that records a skip, and the two backends admit and
    // chunk through different phase-1 paths. Refusing on that direction
    // compares instrument coverage rather than byte coverage, and it is what
    // stopped `crates/` calibrating on a signal with no observable output
    // difference: `--backend cpu-fallback` and `--backend simd-regex` return
    // byte-identical findings on that tree. Match parity against the scalar
    // reference is already proved separately, per trial, so this direction is
    // reported and recorded rather than treated as proof. It becomes a refusal
    // once the scanner records an explicit zero for a decode path that ran and
    // skipped nothing, which is the change that makes absent and zero
    // distinguishable.
    if let Some(expected) = expected_coverage {
        if !coverage.saturating_delta(expected).is_empty() {
            return Err(AutorouteRoutingError::candidate_findings_diverged(
                route.backend,
                format!(
                    "calibration trial skipped more than the scalar reference \
                     (reference gaps {}; this candidate {}), so it covered less than the \
                     oracle it is timed against",
                    render_coverage_gaps(expected),
                    render_coverage_gaps(coverage),
                ),
            ));
        }
        if coverage != expected {
            eprintln!(
                "keyhog: WARNING: autoroute calibration candidate {} reported fewer coverage \
                 gaps than the scalar reference (reference {}; this candidate {}); findings \
                 parity against the reference is proved separately, but this candidate's \
                 timing may not measure the same work",
                route.backend.label(),
                render_coverage_gaps(expected),
                render_coverage_gaps(coverage),
            );
        }
    }
    if let Some(recovery) = outcome.recovery {
        return Err(AutorouteRoutingError::candidate_backend_rejected(
            route.backend,
            format!(
                "calibration trial required {} byte(s) of {} recovery after {} failed: {}",
                recovery.recovered_bytes(),
                recovery.recovery_backend.label(),
                recovery.failed_backend.label(),
                recovery.reason,
            ),
        ));
    }
    Ok(CalibrationTrialOutcome {
        matches: outcome.matches,
        coverage,
    })
}

/// One candidate scan plus the coverage shape it produced.
struct CalibrationTrialOutcome {
    matches: Vec<Vec<keyhog_core::RawMatch>>,
    coverage: ScannerCoverageSnapshot,
}

fn render_coverage_gaps(coverage: ScannerCoverageSnapshot) -> String {
    if coverage.is_empty() {
        return "none".to_string();
    }
    format!("{coverage:?}")
}

fn current_unix_time_ms() -> Result<u128, std::time::SystemTimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
}

#[cfg(test)]
#[path = "../../../../tests/unit/backend_calibration.rs"]
mod tests;
