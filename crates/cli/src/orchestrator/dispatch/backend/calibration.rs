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
use keyhog_scanner::CompiledScanner;
#[cfg(test)]
use std::collections::BTreeSet;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::evidence::{
    canonical_match_digest, canonical_matches, canonical_matches_equal_reference,
    gpu_cold_warm_route_evidence, AutorouteDecision, BackendTimingEvidence, CanonicalMatch,
};
use super::{is_gpu_backend, AutorouteRoutingError, AUTOROUTE_CALIBRATION_TRIALS};

const CALIBRATION_MISMATCH_RECORD_LIMIT: usize = 32;

pub(super) fn calibrate_fastest_correct_backend(
    scanner: &CompiledScanner,
    _pattern_count: usize,
    sample: &[Chunk],
    autoroute_gpu: bool,
) -> Result<AutorouteDecision, AutorouteRoutingError> {
    let sample_bytes = calibration_sample_bytes(sample)?;

    let reference_matches = establish_reference_simd(scanner, sample);

    let gpu_candidates = scanner.gpu_backend_candidates();
    if autoroute_gpu {
        if let Some(candidate) = gpu_candidates.iter().find(|candidate| {
            candidate.acquired && !candidate.is_software && !candidate.is_eligible()
        }) {
            return Err(AutorouteRoutingError::candidate_backend_rejected(
                candidate.backend,
                "GPU peer was acquired without complete driver, device, and runtime identity",
            ));
        }
    }
    let eligible_gpu_backends = if autoroute_gpu {
        gpu_candidates
            .iter()
            .filter(|candidate| candidate.is_eligible())
            .map(|candidate| candidate.backend)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let gpu_candidate_allowed = !eligible_gpu_backends.is_empty();
    if gpu_candidate_allowed {
        scanner
            .prepare_autoroute_calibration_gpu_artifact()
            .map_err(AutorouteRoutingError::calibration_not_persisted)?;
    }

    let mut candidate_backends = Vec::with_capacity(2 + eligible_gpu_backends.len());
    candidate_backends.push(ScanBackend::SimdCpu);
    candidate_backends.push(ScanBackend::CpuFallback);
    candidate_backends.extend(eligible_gpu_backends);
    let rotation =
        calibration_candidate_rotation(sample_bytes, sample.len(), candidate_backends.len());
    candidate_backends.rotate_left(rotation);

    let mut simd_timing = None;
    let mut cpu_timing = None;
    let mut gpu_cuda_timing = None;
    let mut gpu_wgpu_timing = None;
    for backend in candidate_backends {
        let mut measured = measure_candidate_backend(scanner, sample, backend, &reference_matches)?;
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
        match backend {
            ScanBackend::SimdCpu => simd_timing = Some(measured),
            ScanBackend::CpuFallback => cpu_timing = Some(measured),
            ScanBackend::GpuCuda => gpu_cuda_timing = Some(measured),
            ScanBackend::GpuWgpu => gpu_wgpu_timing = Some(measured),
            _ => {
                return Err(AutorouteRoutingError::candidate_backend_rejected(
                    backend,
                    "calibration candidate enumeration returned an unsupported route",
                ));
            }
        }
    }
    let simd_timing = simd_timing.ok_or_else(|| {
        AutorouteRoutingError::calibration_not_persisted(
            "calibration candidate plan omitted the SIMD reference backend",
        )
    })?;

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
    let mut decision = AutorouteDecision::from_peer_timing_evidence(
        ScanBackend::SimdCpu,
        sample_bytes,
        sample.len(),
        correctness_digest,
        calibrated_at_unix_ms,
        simd_timing,
        cpu_timing,
        gpu_cuda_timing,
        gpu_wgpu_timing,
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
        cuda_ms = decision.timing_for_backend(ScanBackend::GpuCuda).map(BackendTimingEvidence::median_ms),
        wgpu_ms = decision.timing_for_backend(ScanBackend::GpuWgpu).map(BackendTimingEvidence::median_ms),
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

fn establish_reference_simd(
    scanner: &CompiledScanner,
    sample: &[Chunk],
) -> Vec<Vec<keyhog_core::RawMatch>> {
    // Establish the canonical finding set outside the rotated timed plan. SIMD
    // is still the correctness reference, but no longer receives the same
    // first thermal position in every workload.
    scanner.clear_fragment_cache();
    let reference = scan_calibration_backend(scanner, sample, ScanBackend::SimdCpu);
    scanner.clear_fragment_cache();
    reference
}

/// The reference-mismatch diff view: every match's calibration identity,
/// rendered. Derived from `evidence::canonical_matches` + `render_canonical_match`
/// so the identity FIELDS have exactly one owner (`evidence::canonical_match`)
/// and this diff can never drift from the equality check it explains.
#[cfg(test)]
pub(super) fn calibration_match_identity_set(
    results: &[Vec<keyhog_core::RawMatch>],
) -> BTreeSet<String> {
    calibration_match_identity_records(results)
        .into_iter()
        .collect()
}

#[cfg(test)]
fn calibration_match_identity_records(results: &[Vec<keyhog_core::RawMatch>]) -> Vec<String> {
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
        if let Err(error) =
            calibration_candidate_parity_result(backend, trial_idx + 1, &matches, &reference_key)
        {
            let trial_key = canonical_matches(&matches);
            let (only_in_reference_count, only_in_reference) =
                bounded_sorted_calibration_difference(&reference_key, &trial_key, |record| {
                    super::evidence::render_canonical_match(record)
                });
            let (only_in_trial_count, only_in_trial) =
                bounded_sorted_calibration_difference(&trial_key, &reference_key, |record| {
                    super::evidence::render_canonical_match(record)
                });
            if backend == ScanBackend::SimdCpu {
                tracing::error!(
                    target: "keyhog::routing",
                    backend = backend.label(),
                    trial = trial_idx + 1,
                    only_in_reference_count,
                    only_in_trial_count,
                    only_in_reference = ?only_in_reference,
                    only_in_trial = ?only_in_trial,
                    "reference backend produced inconsistent calibration results; autoroute calibration aborted"
                );
            } else {
                tracing::error!(
                    target: "keyhog::routing",
                    backend = backend.label(),
                    trial = trial_idx + 1,
                    only_in_reference_count,
                    only_in_trial_count,
                    only_in_reference = ?only_in_reference,
                    only_in_trial = ?only_in_trial,
                    "backend rejected by autoroute parity check"
                );
            }
            scanner.clear_fragment_cache();
            return Err(error);
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

#[derive(Debug, PartialEq, Eq)]
struct CalibrationMismatchRecord {
    record: String,
    missing_occurrences: usize,
}

fn bounded_sorted_calibration_difference<T: Ord>(
    left: &[T],
    right: &[T],
    render: impl Fn(&T) -> String,
) -> (usize, Vec<CalibrationMismatchRecord>) {
    let mut missing_occurrences = 0usize;
    let mut records = Vec::new();
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
        if records.len() < CALIBRATION_MISMATCH_RECORD_LIMIT {
            records.push(CalibrationMismatchRecord {
                record: render(record),
                missing_occurrences: missing,
            });
        }
        left_index = left_end;
    }
    (missing_occurrences, records)
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
    if backend == ScanBackend::SimdCpu {
        return Err(AutorouteRoutingError::inconsistent_reference_backend(trial));
    }
    Err(AutorouteRoutingError::candidate_backend_rejected(
        backend,
        "candidate findings diverged from the SIMD reference",
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibration_difference_reports_exact_count_with_bounded_records() {
        let mut left = vec!["record-00".to_string(); 4];
        left.extend(
            (1..CALIBRATION_MISMATCH_RECORD_LIMIT + 5).map(|index| format!("record-{index:02}")),
        );
        let right = vec!["record-00".to_string()];

        let (count, records) = bounded_sorted_calibration_difference(&left, &right, Clone::clone);

        assert_eq!(count, CALIBRATION_MISMATCH_RECORD_LIMIT + 7);
        assert_eq!(records.len(), CALIBRATION_MISMATCH_RECORD_LIMIT);
        assert_eq!(
            records.first(),
            Some(&CalibrationMismatchRecord {
                record: "record-00".to_string(),
                missing_occurrences: 3,
            })
        );
        assert_eq!(
            records.last().map(|record| record.record.as_str()),
            Some("record-31")
        );
    }
}
