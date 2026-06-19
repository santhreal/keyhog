//! Autoroute timing evidence, backend decisions, and correctness digests.

use keyhog_core::RawMatch;
use keyhog_scanner::hw_probe::ScanBackend;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::{AUTOROUTE_CALIBRATION_TRIALS, AUTOROUTE_GPU_WARM_TRIALS};

pub(super) fn selected_backend_margin_ns(
    selected: ScanBackend,
    candidates: &[(ScanBackend, u128)],
) -> Option<u128> {
    let selected_best = candidates
        .iter()
        .find(|(backend, _)| *backend == selected)?
        .1;
    candidates
        .iter()
        .filter(|(backend, _)| *backend != selected)
        .map(|(_, timing_ns)| *timing_ns)
        .min()
        .map(|second_best| second_best.saturating_sub(selected_best))
}

pub(super) fn gpu_cold_warm_route_evidence(
    gpu_timing: &BackendTimingEvidence,
) -> Option<(u128, BackendTimingEvidence, u128)> {
    let (&cold_ns, warm_trials) = gpu_timing.trials_ns.split_first()?;
    if warm_trials.len() < AUTOROUTE_GPU_WARM_TRIALS {
        return None;
    }
    let warm_timing = BackendTimingEvidence::from_trial_ns(warm_trials.to_vec())?;
    if !warm_timing.is_valid_for_trials(AUTOROUTE_GPU_WARM_TRIALS) {
        return None;
    }
    let route_ns = cold_ns.max(warm_timing.best_ns);
    Some((cold_ns, warm_timing, route_ns))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct AutorouteDecision {
    pub(super) backend: String,
    pub(super) sample_bytes: u64,
    pub(super) sample_chunks: usize,
    pub(super) correctness_digest: u64,
    pub(super) calibrated_at_unix_ms: u128,
    pub(super) simd_ms: u128,
    pub(super) cpu_ms: Option<u128>,
    pub(super) gpu_ms: Option<u128>,
    pub(super) simd_timing: BackendTimingEvidence,
    pub(super) cpu_timing: Option<BackendTimingEvidence>,
    pub(super) gpu_timing: Option<BackendTimingEvidence>,
    pub(super) gpu_cold_ns: Option<u128>,
    pub(super) gpu_warm_ms: Option<u128>,
    pub(super) gpu_warm_timing: Option<BackendTimingEvidence>,
    pub(super) gpu_route_ns: Option<u128>,
    pub(super) selected_margin_ns: Option<u128>,
    pub(super) trials: usize,
}

impl AutorouteDecision {
    #[cfg(test)]
    pub(super) fn new(
        backend: ScanBackend,
        sample_bytes: u64,
        sample_chunks: usize,
        simd_ms: u128,
        cpu_ms: Option<u128>,
        gpu_ms: Option<u128>,
    ) -> Self {
        let simd_timing = BackendTimingEvidence::constant_ms(simd_ms, AUTOROUTE_CALIBRATION_TRIALS);
        let cpu_timing =
            cpu_ms.map(|ms| BackendTimingEvidence::constant_ms(ms, AUTOROUTE_CALIBRATION_TRIALS));
        let gpu_timing =
            gpu_ms.map(|ms| BackendTimingEvidence::constant_ms(ms, AUTOROUTE_CALIBRATION_TRIALS));
        let (gpu_cold_ns, gpu_warm_timing, gpu_route_ns) =
            match gpu_timing.as_ref().and_then(gpu_cold_warm_route_evidence) {
                Some((cold_ns, warm_timing, route_ns)) => {
                    (Some(cold_ns), Some(warm_timing), Some(route_ns))
                }
                None => (None, None, None),
            };
        let candidates = route_candidates(&simd_timing, cpu_timing.as_ref(), gpu_route_ns);
        let selected_margin_ns = selected_backend_margin_ns(backend, &candidates);
        Self {
            backend: backend.label().to_string(),
            sample_bytes,
            sample_chunks,
            correctness_digest: 0xA11D_0B57_A11D_0B57,
            calibrated_at_unix_ms: 1,
            simd_ms: simd_timing.best_ms(),
            cpu_ms: cpu_timing.as_ref().map(BackendTimingEvidence::best_ms),
            gpu_ms: gpu_timing.as_ref().map(BackendTimingEvidence::best_ms),
            simd_timing,
            cpu_timing,
            gpu_timing,
            gpu_cold_ns,
            gpu_warm_ms: gpu_warm_timing.as_ref().map(BackendTimingEvidence::best_ms),
            gpu_warm_timing,
            gpu_route_ns,
            selected_margin_ns,
            trials: AUTOROUTE_CALIBRATION_TRIALS,
        }
    }

    pub(super) fn from_timing_evidence(
        backend: ScanBackend,
        sample_bytes: u64,
        sample_chunks: usize,
        correctness_digest: u64,
        calibrated_at_unix_ms: u128,
        selected_margin_ns: Option<u128>,
        simd_timing: BackendTimingEvidence,
        cpu_timing: Option<BackendTimingEvidence>,
        gpu_timing: Option<BackendTimingEvidence>,
        gpu_cold_ns: Option<u128>,
        gpu_warm_timing: Option<BackendTimingEvidence>,
        gpu_route_ns: Option<u128>,
    ) -> Self {
        Self {
            backend: backend.label().to_string(),
            sample_bytes,
            sample_chunks,
            correctness_digest,
            calibrated_at_unix_ms,
            simd_ms: simd_timing.best_ms(),
            cpu_ms: cpu_timing.as_ref().map(BackendTimingEvidence::best_ms),
            gpu_ms: gpu_timing.as_ref().map(BackendTimingEvidence::best_ms),
            simd_timing,
            cpu_timing,
            gpu_timing,
            gpu_cold_ns,
            gpu_warm_ms: gpu_warm_timing.as_ref().map(BackendTimingEvidence::best_ms),
            gpu_warm_timing,
            gpu_route_ns,
            selected_margin_ns,
            trials: AUTOROUTE_CALIBRATION_TRIALS,
        }
    }

    pub(super) fn backend(&self) -> Option<ScanBackend> {
        keyhog_scanner::hw_probe::parse_backend_str(&self.backend)
    }

    pub(super) fn timing_for_backend(
        &self,
        backend: ScanBackend,
    ) -> Option<&BackendTimingEvidence> {
        match backend {
            ScanBackend::SimdCpu => Some(&self.simd_timing),
            ScanBackend::CpuFallback => self.cpu_timing.as_ref(),
            ScanBackend::Gpu | ScanBackend::MegaScan => self.gpu_timing.as_ref(),
            _ => None,
        }
    }

    pub(super) fn route_candidates(&self) -> Vec<(ScanBackend, u128)> {
        route_candidates(
            &self.simd_timing,
            self.cpu_timing.as_ref(),
            self.gpu_route_ns,
        )
    }
}

pub(super) fn route_candidates(
    simd_timing: &BackendTimingEvidence,
    cpu_timing: Option<&BackendTimingEvidence>,
    gpu_route_ns: Option<u128>,
) -> Vec<(ScanBackend, u128)> {
    let mut candidates = vec![(ScanBackend::SimdCpu, simd_timing.best_ns)];
    if let Some(cpu_timing) = cpu_timing {
        candidates.push((ScanBackend::CpuFallback, cpu_timing.best_ns));
    }
    if let Some(gpu_route_ns) = gpu_route_ns {
        candidates.push((ScanBackend::Gpu, gpu_route_ns));
    }
    candidates
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct BackendTimingEvidence {
    pub(super) trials_ns: Vec<u128>,
    pub(super) best_ns: u128,
    pub(super) min_ns: u128,
    pub(super) max_ns: u128,
    pub(super) mean_ns: u128,
    pub(super) confidence_interval_95_ns: TimingConfidenceInterval,
}

impl BackendTimingEvidence {
    pub(super) fn from_durations(durations: Vec<Duration>) -> Option<Self> {
        let trials_ns = durations.into_iter().map(|dur| dur.as_nanos()).collect();
        Self::from_trial_ns(trials_ns)
    }

    #[cfg(test)]
    pub(super) fn constant_ms(ms: u128, trials: usize) -> Self {
        Self::from_trial_ns(vec![ms.saturating_mul(1_000_000); trials])
            .expect("test timing evidence must contain at least one trial")
    }

    pub(super) fn from_trial_ns(trials_ns: Vec<u128>) -> Option<Self> {
        if trials_ns.is_empty() {
            return None;
        }
        let mut min_ns: Option<u128> = None;
        let mut max_ns: Option<u128> = None;
        let mut sum = 0u128;
        for ns in trials_ns.iter().copied() {
            min_ns = Some(min_ns.map_or(ns, |current| current.min(ns)));
            max_ns = Some(max_ns.map_or(ns, |current| current.max(ns)));
            sum = sum.saturating_add(ns);
        }
        let min_ns = match min_ns {
            Some(ns) => ns,
            None => 0,
        };
        let max_ns = match max_ns {
            Some(ns) => ns,
            None => 0,
        };
        let mean_ns = sum / trials_ns.len() as u128;
        let confidence_interval_95_ns = TimingConfidenceInterval::from_trials(&trials_ns);
        Some(Self {
            trials_ns,
            best_ns: min_ns,
            min_ns,
            max_ns,
            mean_ns,
            confidence_interval_95_ns,
        })
    }

    pub(super) fn best_ms(&self) -> u128 {
        self.best_ns / 1_000_000
    }

    pub(super) fn is_valid_for_trials(&self, min_trials: usize) -> bool {
        self.trials_ns.len() >= min_trials
            && self.best_ns > 0
            && self.min_ns > 0
            && self.best_ns == self.min_ns
            && self.min_ns <= self.mean_ns
            && self.mean_ns <= self.max_ns
            && self.trials_ns.iter().all(|&trial| trial > 0)
            && self.trials_ns.iter().all(|&trial| trial >= self.min_ns)
            && self.trials_ns.iter().all(|&trial| trial <= self.max_ns)
            && self.confidence_interval_95_ns.low_ns <= self.confidence_interval_95_ns.high_ns
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct TimingConfidenceInterval {
    pub(super) low_ns: u128,
    pub(super) high_ns: u128,
}

impl TimingConfidenceInterval {
    fn from_trials(trials_ns: &[u128]) -> Self {
        let count = trials_ns.len() as f64;
        let mean = trials_ns.iter().map(|&ns| ns as f64).sum::<f64>() / count;
        let variance = if trials_ns.len() > 1 {
            trials_ns
                .iter()
                .map(|&ns| {
                    let delta = ns as f64 - mean;
                    delta * delta
                })
                .sum::<f64>()
                / (count - 1.0)
        } else {
            0.0
        };
        let half_width = 1.96 * variance.sqrt() / count.sqrt();
        Self {
            low_ns: (mean - half_width).max(0.0).floor() as u128,
            high_ns: (mean + half_width).ceil() as u128,
        }
    }
}

pub(super) type CanonicalMatch = (
    usize,
    String,
    [u8; 32],
    Option<String>,
    Option<usize>,
    usize,
);

pub(super) fn canonical_matches(matches: &[Vec<RawMatch>]) -> Vec<CanonicalMatch> {
    let mut out = Vec::new();
    for (chunk_idx, chunk_matches) in matches.iter().enumerate() {
        for m in chunk_matches {
            out.push((
                chunk_idx,
                m.detector_id.to_string(),
                m.credential_hash,
                m.location.file_path.as_ref().map(ToString::to_string),
                m.location.line,
                m.location.offset,
            ));
        }
    }
    out.sort_unstable();
    out
}

pub(super) fn canonical_match_digest(matches: &[CanonicalMatch]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    matches.len().hash(&mut h);
    matches.hash(&mut h);
    h.finish()
}
