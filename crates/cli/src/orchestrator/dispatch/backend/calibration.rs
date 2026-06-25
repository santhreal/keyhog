//! Install-time autoroute calibration measurement.

use keyhog_core::Chunk;
use keyhog_scanner::hw_probe::{HardwareCaps, ScanBackend};
use keyhog_scanner::CompiledScanner;
use std::collections::BTreeSet;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::evidence::{
    canonical_match_digest, canonical_matches, canonical_matches_equal_reference,
    gpu_cold_warm_route_evidence, selected_backend_margin_ns, AutorouteDecision,
    BackendTimingEvidence,
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
    let mut candidates = vec![(ScanBackend::SimdCpu, simd_timing.best_ns)];
    let mut best = (ScanBackend::SimdCpu, simd_timing.best_ns);

    let cpu_timing = measure_candidate_backend(
        scanner,
        sample,
        ScanBackend::CpuFallback,
        &reference_matches,
    )?;
    if cpu_timing.best_ns < best.1 {
        best = (ScanBackend::CpuFallback, cpu_timing.best_ns);
    }
    candidates.push((ScanBackend::CpuFallback, cpu_timing.best_ns));
    let cpu_timing = Some(cpu_timing);

    let mut gpu_timing = None;
    let mut gpu_cold_ns = None;
    let mut gpu_warm_timing = None;
    let mut gpu_route_ns = None;
    let gpu_candidate_allowed = autoroute_gpu && hw_caps.gpu_available && !hw_caps.gpu_is_software;
    if gpu_candidate_allowed {
        let measured_gpu_timing =
            measure_candidate_backend(scanner, sample, ScanBackend::Gpu, &reference_matches)?;
        if let Some((cold_ns, warm_timing, route_ns)) =
            gpu_cold_warm_route_evidence(&measured_gpu_timing)
        {
            if route_ns < best.1 {
                best = (ScanBackend::Gpu, route_ns);
            }
            candidates.push((ScanBackend::Gpu, route_ns));
            gpu_cold_ns = Some(cold_ns);
            gpu_warm_timing = Some(warm_timing);
            gpu_route_ns = Some(route_ns);
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

    let selected_margin_ns = selected_backend_margin_ns(best.0, &candidates);
    let calibrated_at_unix_ms = current_unix_time_ms().map_err(|error| {
        AutorouteRoutingError::calibration_not_persisted(format!(
            "system clock is before the UNIX epoch ({error})"
        ))
    })?;
    let correctness_digest = canonical_match_digest(&canonical_matches(&reference_matches));

    tracing::info!(
        target: "keyhog::routing",
        backend = best.0.label(),
        sample_chunks = sample.len(),
        sample_bytes,
        simd_ms = simd_timing.best_ms(),
        cpu_ms = cpu_timing.as_ref().map(BackendTimingEvidence::best_ms),
        gpu_opt_in = autoroute_gpu,
        gpu_considered = gpu_candidate_allowed,
        gpu_ms = gpu_timing.as_ref().map(BackendTimingEvidence::best_ms),
        gpu_cold_ms = gpu_cold_ns.map(|ns| ns / 1_000_000),
        gpu_warm_ms = gpu_warm_timing.as_ref().map(BackendTimingEvidence::best_ms),
        gpu_route_ms = gpu_route_ns.map(|ns| ns / 1_000_000),
        trials = AUTOROUTE_CALIBRATION_TRIALS,
        "autoroute calibrated backend decision"
    );
    let decision = AutorouteDecision::from_timing_evidence(
        best.0,
        sample_bytes,
        sample.len(),
        correctness_digest,
        calibrated_at_unix_ms,
        selected_margin_ns,
        simd_timing,
        cpu_timing,
        gpu_timing,
        gpu_cold_ns,
        gpu_warm_timing,
        gpu_route_ns,
    );
    // Resolve the backend deterministically from the measured evidence: the
    // provably-fastest route if one is statistically separated, otherwise the
    // lowest-overhead member of the tied-fastest set. This is the SAME function
    // `store::validate_decision_route_evidence` re-checks, so calibration never
    // persists a decision validation would reject — and a fast host where the
    // routes tie within measurement noise still gets a usable, sound cache
    // instead of an empty one that hard-errors every auto scan.
    let Some(resolved) = decision.resolved_routing_backend() else {
        return Err(AutorouteRoutingError::calibration_not_persisted(
            "calibration produced no route timing evidence to resolve a backend from",
        ));
    };
    if resolved == best.0 {
        return Ok(decision);
    }
    let resolved_margin_ns = selected_backend_margin_ns(resolved, &candidates);
    Ok(AutorouteDecision::from_timing_evidence(
        resolved,
        sample_bytes,
        sample.len(),
        correctness_digest,
        calibrated_at_unix_ms,
        resolved_margin_ns,
        decision.simd_timing.clone(),
        decision.cpu_timing.clone(),
        decision.gpu_timing.clone(),
        decision.gpu_cold_ns,
        decision.gpu_warm_timing.clone(),
        decision.gpu_route_ns,
    ))
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
    scanner.clear_fragment_cache();
    let (reference, first_dur) =
        timed(|| scanner.scan_coalesced_with_backend(sample, ScanBackend::SimdCpu));
    let reference_key = canonical_matches(&reference);
    let mut durations = vec![first_dur];
    for trial_idx in 1..AUTOROUTE_CALIBRATION_TRIALS {
        scanner.clear_fragment_cache();
        let (matches, dur) =
            timed(|| scanner.scan_coalesced_with_backend(sample, ScanBackend::SimdCpu));
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

pub(super) fn calibration_match_identity_set(
    results: &[Vec<keyhog_core::RawMatch>],
) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for (chunk_idx, chunk_matches) in results.iter().enumerate() {
        for m in chunk_matches {
            let credential_hash_hex: String = m
                .credential_hash
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            set.insert(format!(
                "chunk={chunk_idx} detector={} cred_hash={} file={:?} line={:?} offset={}",
                m.detector_id,
                credential_hash_hex,
                m.location.file_path.as_deref(),
                m.location.line,
                m.location.offset,
            ));
        }
    }
    set
}

fn measure_candidate_backend(
    scanner: &CompiledScanner,
    sample: &[Chunk],
    backend: ScanBackend,
    reference_matches: &[Vec<keyhog_core::RawMatch>],
) -> Result<BackendTimingEvidence, AutorouteRoutingError> {
    let reference_key = canonical_matches(reference_matches);
    let mut durations = Vec::with_capacity(AUTOROUTE_CALIBRATION_TRIALS);
    for _ in 0..AUTOROUTE_CALIBRATION_TRIALS {
        scanner.clear_fragment_cache();
        let gpu_degrade_count_before = if is_gpu_backend(backend) {
            Some(scanner.runtime_status().gpu_degrade_count)
        } else {
            None
        };
        let (matches, dur) = timed(|| scanner.scan_chunks_with_backend(sample, backend));
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
        durations.push(dur);
    }
    scanner.clear_fragment_cache();
    BackendTimingEvidence::from_durations(durations).ok_or_else(|| {
        AutorouteRoutingError::candidate_backend_rejected(
            backend,
            "candidate timing evidence had no recorded trials",
        )
    })
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
