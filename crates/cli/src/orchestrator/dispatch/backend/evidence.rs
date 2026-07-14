//! Autoroute backend decisions derived from measured timing evidence.

use keyhog_scanner::hw_probe::ScanBackend;
use serde::{Deserialize, Serialize};

mod match_identity;
mod timing;

pub(super) use match_identity::{
    canonical_match_digest, canonical_matches, canonical_matches_equal_reference,
    render_canonical_match,
};
pub(super) use timing::{BackendTimingEvidence, TimingConfidenceInterval};

use super::{AUTOROUTE_CALIBRATION_TRIALS, AUTOROUTE_GPU_WARM_TRIALS};

pub(super) fn selected_backend_margin_ns(
    selected: ScanBackend,
    candidates: &[(ScanBackend, u128)],
) -> Option<u128> {
    let selected_time = candidates
        .iter()
        .find(|(backend, _)| *backend == selected)?
        .1;
    candidates
        .iter()
        .filter(|(backend, _)| *backend != selected)
        .map(|(_, timing_ns)| *timing_ns)
        .min()
        .map(|next_time| next_time.saturating_sub(selected_time))
}

pub(super) fn gpu_cold_warm_route_evidence(
    gpu_timing: &BackendTimingEvidence,
) -> Option<(u128, BackendTimingEvidence, u128)> {
    let (&cold_ns, warm_trials) = gpu_timing.trials_ns.split_first()?;
    if warm_trials.len() != AUTOROUTE_GPU_WARM_TRIALS {
        return None;
    }
    let warm_timing = BackendTimingEvidence::from_trial_ns(warm_trials.to_vec())?;
    if !warm_timing.is_valid_for_trials(AUTOROUTE_GPU_WARM_TRIALS) {
        return None;
    }
    // A single lucky minimum is not representative routing evidence. Use the
    // warm median, while retaining the real first dispatch as a lower bound for
    // one-shot routing. The daemon path consumes the warm median directly.
    let route_ns = cold_ns.max(warm_timing.median_ns());
    Some((cold_ns, warm_timing, route_ns))
}

/// A calibrated routing decision for one workload bucket.
///
/// PRIMARY EVIDENCE ONLY: the persisted state is the measured timing evidence
/// (`simd_timing`, `cpu_timing`, and per-driver GPU timing) plus `backend`,
/// calibration sample, digest, timestamp, and trial count. Every value that is a
/// pure function of that evidence, per-backend median-ms (`simd_ms()`/…), the GPU
/// cold/warm/route triple (`gpu_cold_warm_route()`), and the selected-backend
/// margin (`selected_margin_ns()`), is DERIVED on demand through the accessors
/// below rather than stored a second time. This is the ONE-PLACE invariant: a
/// cache can never hold a derived value inconsistent with its own evidence,
/// because there is no stored copy to drift, which is why the old
/// `validate_decision_route_evidence` cross-field-mismatch checks no longer exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AutorouteDecision {
    pub(super) backend: String,
    pub(super) sample_bytes: u64,
    pub(super) sample_chunks: usize,
    pub(super) correctness_digest: u64,
    pub(super) calibrated_at_unix_ms: u128,
    pub(super) simd_timing: BackendTimingEvidence,
    pub(super) cpu_timing: Option<BackendTimingEvidence>,
    pub(super) gpu_cuda_timing: Option<BackendTimingEvidence>,
    pub(super) gpu_wgpu_timing: Option<BackendTimingEvidence>,
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
        let gpu_wgpu_timing =
            gpu_ms.map(|ms| BackendTimingEvidence::constant_ms(ms, AUTOROUTE_CALIBRATION_TRIALS));
        Self {
            backend: backend.label().to_string(),
            sample_bytes,
            sample_chunks,
            correctness_digest: 0xA11D_0B57_A11D_0B57,
            calibrated_at_unix_ms: 1,
            simd_timing,
            cpu_timing,
            gpu_cuda_timing: None,
            gpu_wgpu_timing,
            trials: AUTOROUTE_CALIBRATION_TRIALS,
        }
    }

    #[cfg(test)]
    pub(super) fn from_timing_evidence(
        backend: ScanBackend,
        sample_bytes: u64,
        sample_chunks: usize,
        correctness_digest: u64,
        calibrated_at_unix_ms: u128,
        simd_timing: BackendTimingEvidence,
        cpu_timing: Option<BackendTimingEvidence>,
        gpu_timing: Option<BackendTimingEvidence>,
    ) -> Self {
        Self {
            backend: backend.label().to_string(),
            sample_bytes,
            sample_chunks,
            correctness_digest,
            calibrated_at_unix_ms,
            simd_timing,
            cpu_timing,
            gpu_cuda_timing: None,
            gpu_wgpu_timing: gpu_timing,
            trials: AUTOROUTE_CALIBRATION_TRIALS,
        }
    }

    pub(super) fn from_peer_timing_evidence(
        backend: ScanBackend,
        sample_bytes: u64,
        sample_chunks: usize,
        correctness_digest: u64,
        calibrated_at_unix_ms: u128,
        simd_timing: BackendTimingEvidence,
        cpu_timing: Option<BackendTimingEvidence>,
        gpu_cuda_timing: Option<BackendTimingEvidence>,
        gpu_wgpu_timing: Option<BackendTimingEvidence>,
    ) -> Self {
        Self {
            backend: backend.label().to_string(),
            sample_bytes,
            sample_chunks,
            correctness_digest,
            calibrated_at_unix_ms,
            simd_timing,
            cpu_timing,
            gpu_cuda_timing,
            gpu_wgpu_timing,
            trials: AUTOROUTE_CALIBRATION_TRIALS,
        }
    }

    pub(super) fn backend(&self) -> Option<ScanBackend> {
        keyhog_scanner::hw_probe::parse_backend_str(&self.backend)
    }

    // ── Derived evidence accessors (see the struct doc: primary-evidence-only) ──
    // Each is a pure function of the persisted timing set, computed on demand so
    // no stored copy can drift. These replace the former denormalized fields.

    /// Representative SIMD route time in ms (median of measured trials).
    pub(super) fn simd_ms(&self) -> u128 {
        self.simd_timing.median_ms()
    }

    /// Representative CPU-fallback route time in ms, if CPU was measured.
    pub(super) fn cpu_ms(&self) -> Option<u128> {
        self.cpu_timing
            .as_ref()
            .map(BackendTimingEvidence::median_ms)
    }

    /// Representative one-shot GPU route time in ms, including the measured
    /// first-dispatch lower bound.
    #[cfg(test)]
    pub(super) fn gpu_ms(&self) -> Option<u128> {
        self.gpu_route_ns().map(|route_ns| route_ns / 1_000_000)
    }

    /// The GPU cold-start ns, warm timing evidence, and routing ns, all derived
    /// from the selected driver's persisted timing through the single owner
    /// [`gpu_cold_warm_route_evidence`]. `None` when there is no GPU timing or it
    /// cannot produce valid cold/warm evidence (too few warm trials).
    #[cfg(test)]
    pub(super) fn gpu_cold_warm_route(&self) -> Option<(u128, BackendTimingEvidence, u128)> {
        let backend = self.backend()?.is_gpu().then_some(self.backend()?)?;
        self.timing_for_backend(backend)
            .and_then(gpu_cold_warm_route_evidence)
    }

    pub(super) fn gpu_cold_warm_route_for(
        &self,
        backend: ScanBackend,
    ) -> Option<(u128, BackendTimingEvidence, u128)> {
        self.timing_for_backend(backend)
            .and_then(gpu_cold_warm_route_evidence)
    }

    /// GPU cold-start ns, derived (see [`Self::gpu_cold_warm_route`]).
    #[cfg(test)]
    pub(super) fn gpu_cold_ns(&self) -> Option<u128> {
        self.gpu_cold_warm_route().map(|(cold_ns, _, _)| cold_ns)
    }

    /// GPU warm median-ms, derived.
    #[cfg(test)]
    pub(super) fn gpu_warm_ms(&self) -> Option<u128> {
        self.gpu_cold_warm_route()
            .map(|(_, warm_timing, _)| warm_timing.median_ms())
    }

    /// GPU routing ns (the cold-vs-warm route cost the router compares), derived.
    #[cfg(test)]
    pub(super) fn gpu_route_ns(&self) -> Option<u128> {
        self.gpu_cold_warm_route().map(|(_, _, route_ns)| route_ns)
    }

    /// The ns margin by which the persisted (resolved) backend beat the next
    /// candidate route, derived from the timing evidence via the SAME
    /// [`selected_backend_margin_ns`] / candidate set calibration selected it
    /// with. `None` when the backend is unparseable or there is no competing
    /// route to measure against.
    pub(super) fn selected_margin_ns(&self) -> Option<u128> {
        let backend = self.backend()?;
        let candidates = self.route_candidates();
        selected_backend_margin_ns(backend, &candidates)
    }

    /// The ns margin by which the derived persistent-daemon route beat the next
    /// candidate, using warm GPU evidence. `None` when no route or competitor
    /// exists.
    pub(super) fn persistent_selected_margin_ns(&self) -> Option<u128> {
        let backend = self.resolved_persistent_backend()?;
        let candidates = self.persistent_route_candidates();
        selected_backend_margin_ns(backend, &candidates)
    }

    pub(super) fn timing_for_backend(
        &self,
        backend: ScanBackend,
    ) -> Option<&BackendTimingEvidence> {
        match backend {
            ScanBackend::SimdCpu => Some(&self.simd_timing),
            ScanBackend::CpuFallback => self.cpu_timing.as_ref(),
            ScanBackend::GpuCuda => self.gpu_cuda_timing.as_ref(),
            ScanBackend::GpuWgpu => self.gpu_wgpu_timing.as_ref(),
            _ => None,
        }
    }

    pub(super) fn route_candidates(&self) -> Vec<(ScanBackend, u128)> {
        self.route_candidates_for_runtime(false)
    }

    fn persistent_route_candidates(&self) -> Vec<(ScanBackend, u128)> {
        self.route_candidates_for_runtime(true)
    }

    pub(super) fn selected_backend_has_non_overlapping_confidence(
        &self,
        selected: ScanBackend,
    ) -> bool {
        self.selected_backend_has_non_overlapping_confidence_for(selected, false)
    }

    fn selected_backend_has_non_overlapping_confidence_for(
        &self,
        selected: ScanBackend,
        persistent_runtime: bool,
    ) -> bool {
        let intervals = self.route_confidence_intervals_for(persistent_runtime);
        let Some((_, selected_interval)) = intervals
            .iter()
            .find(|(backend, _)| *backend == selected)
            .copied()
        else {
            return false;
        };
        intervals
            .iter()
            .filter(|(backend, _)| *backend != selected)
            .all(|(_, competitor_interval)| selected_interval.high_ns < competitor_interval.low_ns)
    }

    /// The single deterministic source of truth for which backend a persisted
    /// timing set routes to. Calibration SELECTS this; validation REQUIRES the
    /// persisted `backend` to equal it. It is a pure function of the measured
    /// timing evidence (each executable GPU driver has its own label and timing),
    /// so a cache that names any other backend is rejected as
    /// tampered or non-deterministic.
    ///
    /// Policy:
    /// - If one backend is provably fastest (its 95% CI lies entirely below
    ///   every competitor's), that backend wins.
    /// - Otherwise confidence overlap is explicitly inconclusive, not proof of
    ///   equivalence. Choose the lowest measured median among the statistically
    ///   non-dominated candidates. Engagement overhead breaks only an exact
    ///   median tie, never an overlap whose measured medians differ.
    pub(super) fn resolved_routing_backend(&self) -> Option<ScanBackend> {
        self.resolve_measured_backend(false)
    }

    /// Fastest-correct backend once a long-lived daemon has initialized its
    /// accelerator state. The persisted trials contain both the real first GPU
    /// dispatch and the warm trials; daemon routing uses only the warm interval,
    /// while one-shot routing conservatively includes cold cost.
    pub(super) fn resolved_persistent_backend(&self) -> Option<ScanBackend> {
        self.resolve_measured_backend(true)
    }

    /// True iff exactly one route is provably fastest. Equivalently, the
    /// resolved winner is separated from every competitor, its 95% CI lies
    /// entirely below theirs. When false, confidence intervals overlap and the
    /// measured-median selection rule is operator-visible as inconclusive.
    pub(super) fn has_separated_fastest_route(&self) -> bool {
        self.resolved_routing_backend()
            .is_some_and(|winner| self.selected_backend_has_non_overlapping_confidence(winner))
    }

    /// Persistent-daemon counterpart of [`Self::has_separated_fastest_route`],
    /// evaluated with warm GPU evidence.
    pub(super) fn has_separated_fastest_persistent_route(&self) -> bool {
        self.resolved_persistent_backend().is_some_and(|winner| {
            self.selected_backend_has_non_overlapping_confidence_for(winner, true)
        })
    }

    /// The set of routes that are not provably beaten by any competitor; that
    /// is, no other route's 95% CI lies entirely below this route's CI.
    /// Routing is
    /// decided from confidence intervals, never a single `best_ns` trial, so a
    /// lucky outlier on a noisy backend can never win over a steadily-faster one.
    ///
    /// - Exactly one member  → that route is provably fastest.
    /// - Two or more members → confidence is inconclusive; measured medians
    ///   decide, with overhead used only for an exact median tie.
    fn statistically_non_dominated_routes(&self, persistent_runtime: bool) -> Vec<ScanBackend> {
        let intervals = self.route_confidence_intervals_for(persistent_runtime);
        intervals
            .iter()
            .filter(|(backend, ci)| {
                !intervals
                    .iter()
                    .any(|(other, other_ci)| other != backend && other_ci.high_ns < ci.low_ns)
            })
            .map(|(backend, _)| *backend)
            .collect()
    }

    fn resolve_measured_backend(&self, persistent_runtime: bool) -> Option<ScanBackend> {
        self.statistically_non_dominated_routes(persistent_runtime)
            .into_iter()
            .filter_map(|backend| {
                self.route_median_ns(backend, persistent_runtime)
                    .map(|median_ns| (backend, median_ns))
            })
            .min_by_key(|(backend, median_ns)| (*median_ns, backend_overhead_rank(*backend)))
            .map(|(backend, _)| backend)
    }

    fn route_median_ns(&self, backend: ScanBackend, persistent_runtime: bool) -> Option<u128> {
        match backend {
            ScanBackend::SimdCpu => Some(self.simd_timing.median_ns()),
            ScanBackend::CpuFallback => self
                .cpu_timing
                .as_ref()
                .map(BackendTimingEvidence::median_ns),
            ScanBackend::GpuCuda | ScanBackend::GpuWgpu => {
                let (_, warm_timing, one_shot_ns) = self.gpu_cold_warm_route_for(backend)?;
                Some(if persistent_runtime {
                    warm_timing.median_ns()
                } else {
                    one_shot_ns
                })
            }
            _ => None,
        }
    }

    fn route_confidence_intervals_for(
        &self,
        persistent_runtime: bool,
    ) -> Vec<(ScanBackend, TimingConfidenceInterval)> {
        let mut intervals = vec![(
            ScanBackend::SimdCpu,
            self.simd_timing.confidence_interval_95_ns(),
        )];
        if let Some(cpu_timing) = self.cpu_timing.as_ref() {
            intervals.push((
                ScanBackend::CpuFallback,
                cpu_timing.confidence_interval_95_ns(),
            ));
        }
        for backend in [ScanBackend::GpuCuda, ScanBackend::GpuWgpu] {
            if let Some((cold_ns, warm_timing, _route_ns)) = self.gpu_cold_warm_route_for(backend) {
                let warm_interval = warm_timing.confidence_interval_95_ns();
                intervals.push((
                    backend,
                    if persistent_runtime {
                        warm_interval
                    } else {
                        TimingConfidenceInterval {
                            low_ns: cold_ns.max(warm_interval.low_ns),
                            high_ns: cold_ns.max(warm_interval.high_ns),
                        }
                    },
                ));
            }
        }
        intervals
    }

    fn route_candidates_for_runtime(&self, persistent_runtime: bool) -> Vec<(ScanBackend, u128)> {
        let mut candidates = vec![(ScanBackend::SimdCpu, self.simd_timing.median_ns())];
        if let Some(cpu_timing) = self.cpu_timing.as_ref() {
            candidates.push((ScanBackend::CpuFallback, cpu_timing.median_ns()));
        }
        for backend in [ScanBackend::GpuCuda, ScanBackend::GpuWgpu] {
            if let Some((_, warm_timing, one_shot_ns)) = self.gpu_cold_warm_route_for(backend) {
                candidates.push((
                    backend,
                    if persistent_runtime {
                        warm_timing.median_ns()
                    } else {
                        one_shot_ns
                    },
                ));
            }
        }
        candidates
    }
}

/// Engagement-overhead rank used only when representative measured medians are
/// exactly equal. Confidence-interval overlap alone never invokes this ranking.
fn backend_overhead_rank(backend: ScanBackend) -> u8 {
    match backend {
        ScanBackend::SimdCpu => 0,
        ScanBackend::CpuFallback => 1,
        ScanBackend::GpuCuda | ScanBackend::GpuWgpu => 2,
        _ => 3,
    }
}
