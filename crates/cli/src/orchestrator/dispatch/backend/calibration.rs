//! Install-time autoroute calibration measurement.

use keyhog_core::Chunk;
use keyhog_scanner::hw_probe::{HardwareCaps, ScanBackend};
use keyhog_scanner::CompiledScanner;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::evidence::{
    canonical_match_digest, canonical_matches, gpu_cold_warm_route_evidence,
    selected_backend_margin_ns, AutorouteDecision, BackendTimingEvidence, CanonicalMatch,
};
use super::workload::sample_batch;
use super::{is_gpu_backend, AutorouteRoutingError, AUTOROUTE_CALIBRATION_TRIALS};

pub(super) fn calibrate_fastest_correct_backend(
    scanner: &CompiledScanner,
    hw_caps: &HardwareCaps,
    _pattern_count: usize,
    batch: &[Chunk],
    autoroute_gpu: bool,
) -> Result<AutorouteDecision, AutorouteRoutingError> {
    let sample = sample_batch(batch);
    let sample_bytes = calibration_sample_bytes(&sample)?;

    let (reference_key, simd_timing) = measure_reference_simd(scanner, &sample);
    let mut candidates = vec![(ScanBackend::SimdCpu, simd_timing.best_ns)];
    let mut best = (ScanBackend::SimdCpu, simd_timing.best_ns);

    let cpu_timing =
        measure_candidate_backend(scanner, &sample, ScanBackend::CpuFallback, &reference_key);
    if let Some(cpu_timing) = cpu_timing.clone() {
        if cpu_timing.best_ns < best.1 {
            best = (ScanBackend::CpuFallback, cpu_timing.best_ns);
        }
        candidates.push((ScanBackend::CpuFallback, cpu_timing.best_ns));
    }

    let mut gpu_timing = None;
    let mut gpu_cold_ns = None;
    let mut gpu_warm_timing = None;
    let mut gpu_route_ns = None;
    let gpu_candidate_allowed = autoroute_gpu && hw_caps.gpu_available && !hw_caps.gpu_is_software;
    if gpu_candidate_allowed {
        if let Some(measured_gpu_timing) =
            measure_candidate_backend(scanner, &sample, ScanBackend::Gpu, &reference_key)
        {
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
                tracing::warn!(
                    target: "keyhog::routing",
                    backend = ScanBackend::Gpu.label(),
                    "backend rejected by autoroute GPU cold/warm evidence check"
                );
            }
        }
    }

    let selected_margin_ns = selected_backend_margin_ns(best.0, &candidates);
    let calibrated_at_unix_ms = current_unix_time_ms().map_err(|error| {
        AutorouteRoutingError::calibration_not_persisted(format!(
            "system clock is before the UNIX epoch ({error})"
        ))
    })?;
    let correctness_digest = canonical_match_digest(&reference_key);

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
    Ok(AutorouteDecision::from_timing_evidence(
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
) -> (Vec<CanonicalMatch>, BackendTimingEvidence) {
    scanner.clear_fragment_cache();
    let (reference, first_dur) = timed(|| scanner.scan_coalesced(sample));
    let reference_key = canonical_matches(&reference);
    let mut durations = vec![first_dur];
    for _ in 1..AUTOROUTE_CALIBRATION_TRIALS {
        scanner.clear_fragment_cache();
        let (matches, dur) = timed(|| scanner.scan_coalesced(sample));
        if canonical_matches(&matches) != reference_key {
            tracing::warn!(
                target: "keyhog::routing",
                backend = ScanBackend::SimdCpu.label(),
                "reference backend produced inconsistent calibration results"
            );
            continue;
        }
        durations.push(dur);
    }
    scanner.clear_fragment_cache();
    (
        reference_key,
        BackendTimingEvidence::from_durations(durations),
    )
}

fn measure_candidate_backend(
    scanner: &CompiledScanner,
    sample: &[Chunk],
    backend: ScanBackend,
    reference_key: &[CanonicalMatch],
) -> Option<BackendTimingEvidence> {
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
                tracing::warn!(
                    target: "keyhog::routing",
                    backend = backend.label(),
                    gpu_degrade_count_before = before,
                    gpu_degrade_count_after = after,
                    "backend rejected by autoroute GPU degrade check"
                );
                scanner.clear_fragment_cache();
                return None;
            }
        }
        if canonical_matches(&matches) != reference_key {
            tracing::warn!(
                target: "keyhog::routing",
                backend = backend.label(),
                "backend rejected by autoroute parity check"
            );
            scanner.clear_fragment_cache();
            return None;
        }
        durations.push(dur);
    }
    scanner.clear_fragment_cache();
    Some(BackendTimingEvidence::from_durations(durations))
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
