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
use keyhog_scanner::hw_probe::{HardwareCaps, ScanBackend};
use keyhog_scanner::CompiledScanner;
use std::collections::BTreeSet;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::evidence::{
    canonical_match_digest, canonical_matches, canonical_matches_equal_reference,
    gpu_cold_warm_route_evidence, AutorouteDecision, BackendTimingEvidence,
};
use super::{is_gpu_backend, AutorouteRoutingError, AUTOROUTE_CALIBRATION_TRIALS};

pub(super) fn calibrate_fastest_correct_backend(
    scanner: &CompiledScanner,
    hw_caps: &HardwareCaps,
    _pattern_count: usize,
    sample: &[Chunk],
    autoroute_gpu: bool,
) -> Result<AutorouteDecision, AutorouteRoutingError> {
    let sample_bytes = calibration_sample_bytes(sample)?;

    let (reference_matches, simd_timing) = measure_reference_simd(scanner, sample)?;

    let cpu_timing = measure_candidate_backend(
        scanner,
        sample,
        ScanBackend::CpuFallback,
        &reference_matches,
    )?;
    let cpu_timing = Some(cpu_timing);

    let mut gpu_timing = None;
    let gpu_candidate_allowed = autoroute_gpu && hw_caps.gpu_available && !hw_caps.gpu_is_software;
    if gpu_candidate_allowed {
        let measured_gpu_timing =
            measure_candidate_backend(scanner, sample, ScanBackend::Gpu, &reference_matches)?;
        // Admit the GPU candidate only if its timing can produce valid cold/warm
        // route evidence, the SAME derivability invariant the loaded-cache path
        // enforces (`store::validate_gpu_cold_warm_cache_evidence`). The cold /
        // warm / route VALUES are DERIVED on demand from `gpu_timing`
        // (`AutorouteDecision::gpu_cold_warm_route`), never stored here.
        if gpu_cold_warm_route_evidence(&measured_gpu_timing).is_some() {
            gpu_timing = Some(measured_gpu_timing);
        } else {
            tracing::error!(
                target: "keyhog::routing",
                backend = ScanBackend::Gpu.label(),
                "backend rejected by autoroute GPU cold/warm evidence check"
            );
            return Err(AutorouteRoutingError::candidate_backend_rejected(
                ScanBackend::Gpu,
                "GPU cold/warm route evidence was incomplete or invalid",
            ));
        }
    }

    let calibrated_at_unix_ms = current_unix_time_ms().map_err(|error| {
        AutorouteRoutingError::calibration_not_persisted(format!(
            "system clock is before the UNIX epoch ({error})"
        ))
    })?;
    let correctness_digest = canonical_match_digest(&canonical_matches(&reference_matches));

    // Construct with the reference backend provisionally, then resolve the REAL
    // selection deterministically from the measured evidence: the provably-fastest
    // route if one is statistically separated, otherwise the lowest measured
    // median among statistically non-dominated routes. Engagement overhead is
    // consulted only for an exact median tie. `resolved_routing_backend` is the SAME
    // function `store::validate_decision_route_evidence` re-checks, so
    // calibration never persists a decision validation would reject, and a fast
    // host with overlapping intervals still gets a measured decision without
    // pretending that overlap proves equivalence or applying a backend hierarchy.
    // The provisional backend/margin are ALWAYS overwritten below; only the
    // resolved pair is ever observable.
    let mut decision = AutorouteDecision::from_timing_evidence(
        ScanBackend::SimdCpu,
        sample_bytes,
        sample.len(),
        correctness_digest,
        calibrated_at_unix_ms,
        simd_timing,
        cpu_timing,
        gpu_timing,
    );
    let Some(resolved) = decision.resolved_routing_backend() else {
        return Err(AutorouteRoutingError::calibration_not_persisted(
            "calibration produced no route timing evidence to resolve a backend from",
        ));
    };
    // Persist the resolved backend; the selected-backend margin is DERIVED from
    // it + the timing evidence on demand (`AutorouteDecision::selected_margin_ns`),
    // not stored (so it can never disagree with the persisted evidence).
    decision.backend = resolved.label().to_string();

    tracing::info!(
        target: "keyhog::routing",
        backend = resolved.label(),
        sample_chunks = sample.len(),
        sample_bytes,
        simd_ms = decision.simd_ms(),
        cpu_ms = decision.cpu_ms(),
        gpu_opt_in = autoroute_gpu,
        gpu_considered = gpu_candidate_allowed,
        gpu_ms = decision.gpu_ms(),
        gpu_cold_ms = decision.gpu_cold_ns().map(|ns| ns / 1_000_000),
        gpu_warm_ms = decision.gpu_warm_ms(),
        gpu_route_ms = decision.gpu_route_ns().map(|ns| ns / 1_000_000),
        trials = AUTOROUTE_CALIBRATION_TRIALS,
        "autoroute calibrated backend decision"
    );
    Ok(decision)
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

fn measure_reference_simd(
    scanner: &CompiledScanner,
    sample: &[Chunk],
) -> Result<(Vec<Vec<keyhog_core::RawMatch>>, BackendTimingEvidence), AutorouteRoutingError> {
    // Warmup (UN-timed): the reference scan establishes the reference match set
    // AND absorbs one-time cold costs. Hyperscan scratch first-alloc, cold
    // instruction cache, page-faults, so the timed trials below measure
    // steady-state throughput, not first-run startup. Including the cold first
    // run would inflate the SIMD baseline and unfairly bias every candidate
    // comparison against it (Law 7: a biased measurement is a production bug).
    scanner.clear_fragment_cache();
    let reference = scan_calibration_backend(scanner, sample, ScanBackend::SimdCpu);
    let reference_key = canonical_matches(&reference);
    let mut durations = Vec::with_capacity(AUTOROUTE_CALIBRATION_TRIALS);
    for trial_idx in 0..AUTOROUTE_CALIBRATION_TRIALS {
        scanner.clear_fragment_cache();
        let (matches, dur) =
            timed(|| scan_calibration_backend(scanner, sample, ScanBackend::SimdCpu));
        if !canonical_matches_equal_reference(&matches, &reference_key) {
            let reference_set = calibration_match_identity_set(&reference);
            let trial_set = calibration_match_identity_set(&matches);
            let only_in_reference: Vec<&String> = reference_set.difference(&trial_set).collect();
            let only_in_trial: Vec<&String> = trial_set.difference(&reference_set).collect();
            tracing::error!(
                target: "keyhog::routing",
                backend = ScanBackend::SimdCpu.label(),
                trial = trial_idx + 1,
                only_in_reference = ?only_in_reference,
                only_in_trial = ?only_in_trial,
                "reference backend produced inconsistent calibration results; autoroute calibration aborted"
            );
            scanner.clear_fragment_cache();
            return Err(AutorouteRoutingError::inconsistent_reference_backend(
                trial_idx + 1,
            ));
        }
        durations.push(dur);
    }
    scanner.clear_fragment_cache();
    let timing = BackendTimingEvidence::from_durations(durations).ok_or_else(|| {
        AutorouteRoutingError::calibration_not_persisted(
            "reference SIMD timing evidence had no recorded trials",
        )
    })?;
    if !timing.is_valid_for_trials(AUTOROUTE_CALIBRATION_TRIALS) {
        return Err(AutorouteRoutingError::calibration_not_persisted(
            "reference SIMD timing evidence was invalid",
        ));
    }
    Ok((reference, timing))
}

/// The reference-mismatch diff view: every match's calibration identity,
/// rendered. Derived from `evidence::canonical_matches` + `render_canonical_match`
/// so the identity FIELDS have exactly one owner (`evidence::canonical_match`)
/// and this diff can never drift from the equality check it explains.
pub(super) fn calibration_match_identity_set(
    results: &[Vec<keyhog_core::RawMatch>],
) -> BTreeSet<String> {
    canonical_matches(results)
        .iter()
        .map(super::evidence::render_canonical_match)
        .collect()
}

fn measure_candidate_backend(
    scanner: &CompiledScanner,
    sample: &[Chunk],
    backend: ScanBackend,
    reference_matches: &[Vec<keyhog_core::RawMatch>],
) -> Result<BackendTimingEvidence, AutorouteRoutingError> {
    let reference_key = canonical_matches(reference_matches);
    let mut durations = Vec::with_capacity(AUTOROUTE_CALIBRATION_TRIALS);
    let records_cold_trial = is_gpu_backend(backend);
    // GPU routing evidence deliberately stores the first real dispatch as its
    // cold trial followed by warm trials. Discarding that call and labelling the
    // second one "cold" makes one-shot routing evidence optimistically false.
    // CPU/Hyperscan candidates still get one checked, unrecorded warmup so their
    // persisted trials measure steady-state throughput like the SIMD reference.
    let calls = AUTOROUTE_CALIBRATION_TRIALS + usize::from(!records_cold_trial);
    for trial_idx in 0..calls {
        scanner.clear_fragment_cache();
        let gpu_degrade_count_before = if is_gpu_backend(backend) {
            Some(scanner.runtime_status().gpu_degrade_count)
        } else {
            None
        };
        let (matches, dur) = timed(|| scan_calibration_backend(scanner, sample, backend));
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
                    format!(
                        "GPU degrade count changed from {before} to {after} during calibration"
                    ),
                ));
            }
        }
        if !canonical_matches_equal_reference(&matches, &reference_key) {
            tracing::error!(
                target: "keyhog::routing",
                backend = backend.label(),
                "backend rejected by autoroute parity check"
            );
            scanner.clear_fragment_cache();
            return Err(AutorouteRoutingError::candidate_backend_rejected(
                backend,
                "candidate findings diverged from the SIMD reference",
            ));
        }
        if records_cold_trial || trial_idx > 0 {
            durations.push(dur);
        }
    }
    scanner.clear_fragment_cache();
    BackendTimingEvidence::from_durations(durations).ok_or_else(|| {
        AutorouteRoutingError::candidate_backend_rejected(
            backend,
            "candidate timing evidence had no recorded trials",
        )
    })
}

/// Run every calibration candidate through the same backend-dispatch boundary
/// used by in-process batches and daemon requests. The boundary selects the
/// coalesced Hyperscan implementation and the ordinary CPU or GPU batch path.
fn scan_calibration_backend(
    scanner: &CompiledScanner,
    sample: &[Chunk],
    backend: ScanBackend,
) -> Vec<Vec<keyhog_core::RawMatch>> {
    scanner.scan_coalesced_with_backend(sample, backend)
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
