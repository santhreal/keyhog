//! Autoroute backend decisions derived from measured timing evidence.

use keyhog_scanner::hw_probe::ScanBackend;
use serde::{Deserialize, Serialize};

mod match_identity;
mod timing;

pub(super) use match_identity::{
    canonical_match_digest, canonical_matches, canonical_matches_equal_reference,
    differing_canonical_match_fields, CanonicalMatch,
};
pub(super) use timing::{BackendTimingEvidence, TimingConfidenceInterval};

use super::{AUTOROUTE_CALIBRATION_TRIALS, AUTOROUTE_GPU_WARM_TRIALS};

pub(super) const MAX_AUTOROUTE_MEASURED_POINTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MeasuredRoute {
    pub(super) backend: ScanBackend,
    pub(super) phase2_localizer: bool,
}

impl MeasuredRoute {
    pub(super) fn execution_route(self) -> keyhog_scanner::ScanExecutionRoute {
        keyhog_scanner::ScanExecutionRoute {
            phase2_localizer: self.phase2_localizer,
        }
    }
}

fn selected_route_margin_ns(
    selected: MeasuredRoute,
    candidates: &[(MeasuredRoute, u128)],
) -> Option<u128> {
    let selected_time = candidates.iter().find(|(route, _)| *route == selected)?.1;
    candidates
        .iter()
        .filter(|(route, _)| *route != selected)
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

/// Parity and timing binding for one measured backend candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BackendParityReceipt {
    pub(super) backend: String,
    pub(super) phase2_localizer: bool,
    pub(super) correctness_digest: u64,
    pub(super) completed_trials: usize,
    pub(super) evidence_digest: u64,
}

impl BackendParityReceipt {
    fn new(route: MeasuredRoute, correctness_digest: u64, timing: &BackendTimingEvidence) -> Self {
        let completed_trials = timing.trials_ns.len();
        let evidence_digest =
            Self::evidence_digest_for(route, correctness_digest, completed_trials, timing);
        Self {
            backend: route.backend.label().to_string(),
            phase2_localizer: route.phase2_localizer,
            correctness_digest,
            completed_trials,
            evidence_digest,
        }
    }

    pub(super) fn expected_evidence_digest(
        &self,
        route: MeasuredRoute,
        timing: &BackendTimingEvidence,
    ) -> u64 {
        Self::evidence_digest_for(
            route,
            self.correctness_digest,
            self.completed_trials,
            timing,
        )
    }

    fn evidence_digest_for(
        route: MeasuredRoute,
        correctness_digest: u64,
        completed_trials: usize,
        timing: &BackendTimingEvidence,
    ) -> u64 {
        let mut hasher = crate::stable_hash::StableHasher::new("autoroute-parity-receipt");
        hasher
            .field_str("backend", route.backend.label())
            .field_bool("phase2_localizer", route.phase2_localizer)
            .field_u64("correctness_digest", correctness_digest)
            .field_usize("completed_trials", completed_trials)
            .field_usize("timing.trials_ns.len", timing.trials_ns.len());
        for (index, trial_ns) in timing.trials_ns.iter().enumerate() {
            hasher
                .field_usize("timing.trial.index", index)
                .field_bytes("timing.trial.ns", &trial_ns.to_le_bytes());
        }
        hasher.finish_u64()
    }
}

/// One workload-class route backed by every retained measured point.
///
/// The persisted state contains only primary measurements and receipts.
/// Medians, confidence, margins, and runtime-class winners are derived across
/// `calibration_points`, so no separately stored summary can drift.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AutorouteDecision {
    pub(super) backend: String,
    pub(super) phase2_localizer: bool,
    pub(super) calibration_points: Vec<AutorouteCalibrationPoint>,
}

/// One measured point inside a coarse workload class.
///
/// Autoroute may reuse a class only when every retained point resolves the same
/// one-shot and daemon winners. Keeping the raw per-backend trials and parity
/// receipts makes that agreement reproducible instead of reducing a size band
/// to one optimistic representative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AutorouteCalibrationPoint {
    pub(super) sample_bytes: u64,
    pub(super) sample_chunks: usize,
    pub(super) candidate_receipts: Vec<BackendParityReceipt>,
    pub(super) calibrated_at_unix_ms: u128,
    pub(super) simd_timing: BackendTimingEvidence,
    pub(super) cpu_timing: Option<BackendTimingEvidence>,
    pub(super) gpu_cuda_timing: Option<BackendTimingEvidence>,
    pub(super) gpu_wgpu_timing: Option<BackendTimingEvidence>,
    pub(super) simd_localizer_timing: Option<BackendTimingEvidence>,
    pub(super) cpu_localizer_timing: Option<BackendTimingEvidence>,
    pub(super) gpu_cuda_localizer_timing: Option<BackendTimingEvidence>,
    pub(super) gpu_wgpu_localizer_timing: Option<BackendTimingEvidence>,
    pub(super) trials: usize,
}

impl AutorouteCalibrationPoint {
    fn measured_routes(&self) -> Vec<MeasuredRoute> {
        let mut routes = Vec::with_capacity(8);
        for backend in [
            ScanBackend::SimdCpu,
            ScanBackend::CpuFallback,
            ScanBackend::GpuCuda,
            ScanBackend::GpuWgpu,
        ] {
            for phase2_localizer in [false, true] {
                let route = MeasuredRoute {
                    backend,
                    phase2_localizer,
                };
                if self.timing_for_route(route).is_some() {
                    routes.push(route);
                }
            }
        }
        routes
    }

    pub(super) fn timing_for_route(&self, route: MeasuredRoute) -> Option<&BackendTimingEvidence> {
        match (route.backend, route.phase2_localizer) {
            (ScanBackend::SimdCpu, false) => Some(&self.simd_timing),
            (ScanBackend::CpuFallback, false) => self.cpu_timing.as_ref(),
            (ScanBackend::GpuCuda, false) => self.gpu_cuda_timing.as_ref(),
            (ScanBackend::GpuWgpu, false) => self.gpu_wgpu_timing.as_ref(),
            (ScanBackend::SimdCpu, true) => self.simd_localizer_timing.as_ref(),
            (ScanBackend::CpuFallback, true) => self.cpu_localizer_timing.as_ref(),
            (ScanBackend::GpuCuda, true) => self.gpu_cuda_localizer_timing.as_ref(),
            (ScanBackend::GpuWgpu, true) => self.gpu_wgpu_localizer_timing.as_ref(),
            _ => None,
        }
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

    pub(super) fn gpu_cold_warm_route_for_measured(
        &self,
        route: MeasuredRoute,
    ) -> Option<(u128, BackendTimingEvidence, u128)> {
        route.backend.is_gpu().then_some(())?;
        self.timing_for_route(route)
            .and_then(gpu_cold_warm_route_evidence)
    }

    pub(super) fn selected_route_has_non_overlapping_confidence_for(
        &self,
        selected: MeasuredRoute,
        persistent_runtime: bool,
    ) -> bool {
        let intervals = self.route_confidence_intervals_for(persistent_runtime);
        let Some((_, selected_interval)) = intervals
            .iter()
            .find(|(route, _)| *route == selected)
            .copied()
        else {
            return false;
        };
        intervals
            .iter()
            .filter(|(route, _)| *route != selected)
            .all(|(_, competitor_interval)| selected_interval.high_ns < competitor_interval.low_ns)
    }

    pub(super) fn resolve_measured_route(&self, persistent_runtime: bool) -> Option<MeasuredRoute> {
        self.statistically_non_dominated_routes(persistent_runtime)
            .into_iter()
            .filter_map(|route| {
                self.route_median_ns(route, persistent_runtime)
                    .map(|median_ns| (route, median_ns))
            })
            .min_by_key(|(route, median_ns)| {
                (
                    *median_ns,
                    backend_overhead_rank(route.backend),
                    route.phase2_localizer,
                )
            })
            .map(|(route, _)| route)
    }

    fn statistically_non_dominated_routes(&self, persistent_runtime: bool) -> Vec<MeasuredRoute> {
        let intervals = self.route_confidence_intervals_for(persistent_runtime);
        intervals
            .iter()
            .filter(|(route, ci)| {
                !intervals
                    .iter()
                    .any(|(other, other_ci)| other != route && other_ci.high_ns < ci.low_ns)
            })
            .map(|(route, _)| *route)
            .collect()
    }

    fn route_median_ns(&self, route: MeasuredRoute, persistent_runtime: bool) -> Option<u128> {
        match route.backend {
            ScanBackend::SimdCpu | ScanBackend::CpuFallback => self
                .timing_for_route(route)
                .map(BackendTimingEvidence::median_ns),
            ScanBackend::GpuCuda | ScanBackend::GpuWgpu => {
                let (_, warm_timing, one_shot_ns) = self.gpu_cold_warm_route_for_measured(route)?;
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
    ) -> Vec<(MeasuredRoute, TimingConfidenceInterval)> {
        let mut intervals = Vec::with_capacity(8);
        for route in self.measured_routes() {
            if route.backend.is_gpu() {
                let Some((cold_ns, warm_timing, _route_ns)) =
                    self.gpu_cold_warm_route_for_measured(route)
                else {
                    continue;
                };
                let warm_interval = warm_timing.confidence_interval_95_ns();
                intervals.push((
                    route,
                    if persistent_runtime {
                        warm_interval
                    } else {
                        TimingConfidenceInterval {
                            low_ns: cold_ns.max(warm_interval.low_ns),
                            high_ns: cold_ns.max(warm_interval.high_ns),
                        }
                    },
                ));
            } else if let Some(timing) = self.timing_for_route(route) {
                intervals.push((route, timing.confidence_interval_95_ns()));
            }
        }
        intervals
    }

    fn route_candidates_for_runtime(&self, persistent_runtime: bool) -> Vec<(MeasuredRoute, u128)> {
        self.measured_routes()
            .into_iter()
            .filter_map(|route| {
                self.route_median_ns(route, persistent_runtime)
                    .map(|timing| (route, timing))
            })
            .collect()
    }
}

impl AutorouteDecision {
    fn candidate_receipts(
        correctness_digest: u64,
        simd_timing: &BackendTimingEvidence,
        cpu_timing: Option<&BackendTimingEvidence>,
        gpu_cuda_timing: Option<&BackendTimingEvidence>,
        gpu_wgpu_timing: Option<&BackendTimingEvidence>,
        simd_localizer_timing: Option<&BackendTimingEvidence>,
        cpu_localizer_timing: Option<&BackendTimingEvidence>,
        gpu_cuda_localizer_timing: Option<&BackendTimingEvidence>,
        gpu_wgpu_localizer_timing: Option<&BackendTimingEvidence>,
    ) -> Vec<BackendParityReceipt> {
        [
            (
                MeasuredRoute {
                    backend: ScanBackend::SimdCpu,
                    phase2_localizer: false,
                },
                Some(simd_timing),
            ),
            (
                MeasuredRoute {
                    backend: ScanBackend::CpuFallback,
                    phase2_localizer: false,
                },
                cpu_timing,
            ),
            (
                MeasuredRoute {
                    backend: ScanBackend::GpuCuda,
                    phase2_localizer: false,
                },
                gpu_cuda_timing,
            ),
            (
                MeasuredRoute {
                    backend: ScanBackend::GpuWgpu,
                    phase2_localizer: false,
                },
                gpu_wgpu_timing,
            ),
            (
                MeasuredRoute {
                    backend: ScanBackend::SimdCpu,
                    phase2_localizer: true,
                },
                simd_localizer_timing,
            ),
            (
                MeasuredRoute {
                    backend: ScanBackend::CpuFallback,
                    phase2_localizer: true,
                },
                cpu_localizer_timing,
            ),
            (
                MeasuredRoute {
                    backend: ScanBackend::GpuCuda,
                    phase2_localizer: true,
                },
                gpu_cuda_localizer_timing,
            ),
            (
                MeasuredRoute {
                    backend: ScanBackend::GpuWgpu,
                    phase2_localizer: true,
                },
                gpu_wgpu_localizer_timing,
            ),
        ]
        .into_iter()
        .filter_map(|(route, timing)| {
            timing.map(|timing| BackendParityReceipt::new(route, correctness_digest, timing))
        })
        .collect()
    }

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
        // Production calibration always measures scalar CPU. Test fixtures
        // therefore default an omitted explicit value to the SIMD duration;
        // missing-candidate tests remove the field after construction.
        let cpu_duration_ms = match cpu_ms {
            Some(duration_ms) => duration_ms,
            None => simd_ms,
        };
        let cpu_timing = Some(BackendTimingEvidence::constant_ms(
            cpu_duration_ms,
            AUTOROUTE_CALIBRATION_TRIALS,
        ));
        let gpu_wgpu_timing =
            gpu_ms.map(|ms| BackendTimingEvidence::constant_ms(ms, AUTOROUTE_CALIBRATION_TRIALS));
        let slower = |timing: &BackendTimingEvidence| {
            BackendTimingEvidence::constant_ms(
                timing.median_ms().saturating_add(1_000),
                AUTOROUTE_CALIBRATION_TRIALS,
            )
        };
        let simd_localizer_timing = Some(slower(&simd_timing));
        let cpu_localizer_timing = cpu_timing.as_ref().map(slower);
        let gpu_wgpu_localizer_timing = gpu_wgpu_timing.as_ref().map(slower);
        let candidate_receipts = Self::candidate_receipts(
            0xA11D_0B57_A11D_0B57,
            &simd_timing,
            cpu_timing.as_ref(),
            None,
            gpu_wgpu_timing.as_ref(),
            simd_localizer_timing.as_ref(),
            cpu_localizer_timing.as_ref(),
            None,
            gpu_wgpu_localizer_timing.as_ref(),
        );
        Self {
            backend: backend.label().to_string(),
            phase2_localizer: false,
            calibration_points: vec![AutorouteCalibrationPoint {
                sample_bytes,
                sample_chunks,
                candidate_receipts,
                calibrated_at_unix_ms: 1,
                simd_timing,
                cpu_timing,
                gpu_cuda_timing: None,
                gpu_wgpu_timing,
                simd_localizer_timing,
                cpu_localizer_timing,
                gpu_cuda_localizer_timing: None,
                gpu_wgpu_localizer_timing,
                trials: AUTOROUTE_CALIBRATION_TRIALS,
            }],
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
        let slower = |timing: &BackendTimingEvidence| {
            BackendTimingEvidence::constant_ms(
                timing.median_ms().saturating_add(1_000),
                AUTOROUTE_CALIBRATION_TRIALS,
            )
        };
        let simd_localizer_timing = Some(slower(&simd_timing));
        let cpu_localizer_timing = cpu_timing.as_ref().map(slower);
        let gpu_localizer_timing = gpu_timing.as_ref().map(slower);
        let candidate_receipts = Self::candidate_receipts(
            correctness_digest,
            &simd_timing,
            cpu_timing.as_ref(),
            None,
            gpu_timing.as_ref(),
            simd_localizer_timing.as_ref(),
            cpu_localizer_timing.as_ref(),
            None,
            gpu_localizer_timing.as_ref(),
        );
        Self {
            backend: backend.label().to_string(),
            phase2_localizer: false,
            calibration_points: vec![AutorouteCalibrationPoint {
                sample_bytes,
                sample_chunks,
                candidate_receipts,
                calibrated_at_unix_ms,
                simd_timing,
                cpu_timing,
                gpu_cuda_timing: None,
                gpu_wgpu_timing: gpu_timing,
                simd_localizer_timing,
                cpu_localizer_timing,
                gpu_cuda_localizer_timing: None,
                gpu_wgpu_localizer_timing: gpu_localizer_timing,
                trials: AUTOROUTE_CALIBRATION_TRIALS,
            }],
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
        simd_localizer_timing: Option<BackendTimingEvidence>,
        cpu_localizer_timing: Option<BackendTimingEvidence>,
        gpu_cuda_localizer_timing: Option<BackendTimingEvidence>,
        gpu_wgpu_localizer_timing: Option<BackendTimingEvidence>,
    ) -> Self {
        let candidate_receipts = Self::candidate_receipts(
            correctness_digest,
            &simd_timing,
            cpu_timing.as_ref(),
            gpu_cuda_timing.as_ref(),
            gpu_wgpu_timing.as_ref(),
            simd_localizer_timing.as_ref(),
            cpu_localizer_timing.as_ref(),
            gpu_cuda_localizer_timing.as_ref(),
            gpu_wgpu_localizer_timing.as_ref(),
        );
        Self {
            backend: backend.label().to_string(),
            phase2_localizer: false,
            calibration_points: vec![AutorouteCalibrationPoint {
                sample_bytes,
                sample_chunks,
                candidate_receipts,
                calibrated_at_unix_ms,
                simd_timing,
                cpu_timing,
                gpu_cuda_timing,
                gpu_wgpu_timing,
                simd_localizer_timing,
                cpu_localizer_timing,
                gpu_cuda_localizer_timing,
                gpu_wgpu_localizer_timing,
                trials: AUTOROUTE_CALIBRATION_TRIALS,
            }],
        }
    }

    pub(super) fn contains_sample(&self, sample_bytes: u64, sample_chunks: usize) -> bool {
        self.calibration_points
            .iter()
            .any(|point| point.sample_bytes == sample_bytes && point.sample_chunks == sample_chunks)
    }

    pub(super) fn merge_calibration_point(
        &mut self,
        point: AutorouteDecision,
    ) -> Result<(), String> {
        if point.calibration_points.len() != 1 {
            return Err("cannot merge a nested autoroute calibration envelope".into());
        }
        let declared_one_shot = point
            .measured_route()
            .ok_or_else(|| "new workload point declares an unsupported route".to_string())?;
        let point = point
            .calibration_points
            .into_iter()
            .next()
            .expect("length checked");
        if self.contains_sample(point.sample_bytes, point.sample_chunks) {
            return Ok(());
        }
        if self.calibration_points.len() >= MAX_AUTOROUTE_MEASURED_POINTS {
            return Err(format!(
                "autoroute workload class already contains the maximum {MAX_AUTOROUTE_MEASURED_POINTS} measured calibration points; split the workload identity before adding more evidence"
            ));
        }
        let expected_one_shot = self.resolved_routing_route().ok_or_else(|| {
            "existing workload evidence does not resolve one one-shot backend across its measured points"
                .to_string()
        })?;
        let measured_one_shot = point
            .resolve_measured_route(false)
            .ok_or_else(|| "new workload point does not resolve one one-shot route".to_string())?;
        if declared_one_shot != measured_one_shot {
            return Err(format!(
                "new workload point declares {} but its timing evidence resolves {}; recalibrate the point",
                render_measured_route(declared_one_shot),
                render_measured_route(measured_one_shot)
            ));
        }
        let expected_daemon = self.resolved_persistent_route().ok_or_else(|| {
            "existing workload evidence does not resolve one daemon backend across its measured points"
                .to_string()
        })?;
        let measured_daemon = point
            .resolve_measured_route(true)
            .ok_or_else(|| "new workload point does not resolve one daemon route".to_string())?;
        if expected_one_shot != measured_one_shot || expected_daemon != measured_daemon {
            return Err(format!(
                "workload class changes fastest backend across measured points: existing one-shot={} daemon={}, new {}-byte/{}-chunk point one-shot={} daemon={}; split the workload identity at this crossover and recalibrate",
                render_measured_route(expected_one_shot),
                render_measured_route(expected_daemon),
                point.sample_bytes,
                point.sample_chunks,
                render_measured_route(measured_one_shot),
                render_measured_route(measured_daemon),
            ));
        }
        self.calibration_points.push(point);
        self.calibration_points
            .sort_unstable_by_key(|point| (point.sample_bytes, point.sample_chunks));
        Ok(())
    }

    pub(super) fn backend(&self) -> Option<ScanBackend> {
        keyhog_scanner::hw_probe::parse_backend_str(&self.backend)
    }

    pub(super) fn measured_route(&self) -> Option<MeasuredRoute> {
        Some(MeasuredRoute {
            backend: self.backend()?,
            phase2_localizer: self.phase2_localizer,
        })
    }

    pub(super) fn primary_point(&self) -> &AutorouteCalibrationPoint {
        self.calibration_points
            .first()
            .expect("autoroute decisions are constructed and validated with evidence")
    }

    #[cfg(test)]
    pub(super) fn primary_point_mut(&mut self) -> &mut AutorouteCalibrationPoint {
        self.calibration_points
            .first_mut()
            .expect("test autoroute decision must contain evidence")
    }

    // Derived evidence is computed on demand, never persisted a second time.

    /// Representative SIMD route time in ms (median of measured trials).
    pub(super) fn simd_ms(&self) -> u128 {
        self.primary_point().simd_timing.median_ms()
    }

    /// Representative CPU-fallback route time in ms, if CPU was measured.
    pub(super) fn cpu_ms(&self) -> Option<u128> {
        self.primary_point()
            .cpu_timing
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
        self.primary_point()
            .timing_for_backend(backend)
            .and_then(gpu_cold_warm_route_evidence)
    }

    pub(super) fn gpu_cold_warm_route_for(
        &self,
        backend: ScanBackend,
    ) -> Option<(u128, BackendTimingEvidence, u128)> {
        self.primary_point()
            .timing_for_backend(backend)
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

    /// The ns margin by which the persisted (resolved) route beat the next
    /// candidate route, derived from the timing evidence via the SAME
    /// [`selected_route_margin_ns`] / candidate set calibration selected it
    /// with. `None` when the route is unparseable or there is no competing
    /// route to measure against.
    pub(super) fn selected_margin_ns(&self) -> Option<u128> {
        let route = self.measured_route()?;
        self.calibration_points
            .iter()
            .map(|point| {
                selected_route_margin_ns(route, &point.route_candidates_for_runtime(false))
            })
            .collect::<Option<Vec<_>>>()?
            .into_iter()
            .min()
    }

    /// The ns margin by which the derived persistent-daemon route beat the next
    /// candidate, using warm GPU evidence. `None` when no route or competitor
    /// exists.
    pub(super) fn persistent_selected_margin_ns(&self) -> Option<u128> {
        let route = self.resolved_persistent_route()?;
        self.calibration_points
            .iter()
            .map(|point| selected_route_margin_ns(route, &point.route_candidates_for_runtime(true)))
            .collect::<Option<Vec<_>>>()?
            .into_iter()
            .min()
    }

    pub(super) fn timing_for_backend(
        &self,
        backend: ScanBackend,
    ) -> Option<&BackendTimingEvidence> {
        self.primary_point().timing_for_backend(backend)
    }

    #[cfg(test)]
    pub(super) fn selected_backend_has_non_overlapping_confidence(
        &self,
        selected: ScanBackend,
    ) -> bool {
        let Some(route) = self
            .measured_route()
            .filter(|route| route.backend == selected)
        else {
            return false;
        };
        self.selected_route_has_non_overlapping_confidence_for(route, false)
    }

    fn selected_route_has_non_overlapping_confidence_for(
        &self,
        selected: MeasuredRoute,
        persistent_runtime: bool,
    ) -> bool {
        self.calibration_points.iter().all(|point| {
            point.selected_route_has_non_overlapping_confidence_for(selected, persistent_runtime)
        })
    }

    /// The single deterministic source of truth for which route a persisted
    /// timing set routes to. Calibration SELECTS this; validation REQUIRES the
    /// persisted backend and localizer choice to equal it. It is a pure function
    /// of the measured timing evidence (each executable GPU driver and localizer
    /// mode has its own route and timing), so a cache that names any other route is rejected as
    /// tampered or non-deterministic.
    ///
    /// Policy:
    /// - If one route is provably fastest (its 95% CI lies entirely below every
    ///   competitor's), that route wins.
    /// - Otherwise confidence overlap is explicitly inconclusive, not proof of
    ///   equivalence. Choose the lowest measured median among the statistically
    ///   non-dominated candidates. Engagement overhead breaks only an exact
    ///   median tie, never an overlap whose measured medians differ.
    pub(super) fn resolved_routing_route(&self) -> Option<MeasuredRoute> {
        let selected = self
            .calibration_points
            .first()?
            .resolve_measured_route(false)?;
        self.calibration_points
            .iter()
            .all(|point| point.resolve_measured_route(false) == Some(selected))
            .then_some(selected)
    }

    #[cfg(test)]
    pub(super) fn resolved_routing_backend(&self) -> Option<ScanBackend> {
        self.resolved_routing_route().map(|route| route.backend)
    }

    /// Fastest-correct backend once a long-lived daemon has initialized its
    /// accelerator state. The persisted trials contain both the real first GPU
    /// dispatch and the warm trials; daemon routing uses only the warm interval,
    /// while one-shot routing conservatively includes cold cost.
    pub(super) fn resolved_persistent_route(&self) -> Option<MeasuredRoute> {
        let selected = self
            .calibration_points
            .first()?
            .resolve_measured_route(true)?;
        self.calibration_points
            .iter()
            .all(|point| point.resolve_measured_route(true) == Some(selected))
            .then_some(selected)
    }

    pub(super) fn resolved_persistent_backend(&self) -> Option<ScanBackend> {
        self.resolved_persistent_route().map(|route| route.backend)
    }

    /// True iff exactly one route is provably fastest. Equivalently, the
    /// resolved winner is separated from every competitor, its 95% CI lies
    /// entirely below theirs. When false, confidence intervals overlap and the
    /// measured-median selection rule is operator-visible as inconclusive.
    pub(super) fn has_separated_fastest_route(&self) -> bool {
        self.resolved_routing_route().is_some_and(|winner| {
            self.selected_route_has_non_overlapping_confidence_for(winner, false)
        })
    }

    /// Persistent-daemon counterpart of [`Self::has_separated_fastest_route`],
    /// evaluated with warm GPU evidence.
    pub(super) fn has_separated_fastest_persistent_route(&self) -> bool {
        self.resolved_persistent_route().is_some_and(|winner| {
            self.selected_route_has_non_overlapping_confidence_for(winner, true)
        })
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

fn render_measured_route(route: MeasuredRoute) -> String {
    format!(
        "{}+phase2-localizer={}",
        route.backend.label(),
        route.phase2_localizer
    )
}
