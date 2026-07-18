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

use super::{AUTOROUTE_ACCELERATOR_WARM_TRIALS, AUTOROUTE_CALIBRATION_TRIALS};

pub(super) const MAX_AUTOROUTE_MEASURED_POINTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MeasuredRoute {
    pub(super) backend: ScanBackend,
    pub(super) phase2_plain_localizer: bool,
    pub(super) phase2_keyword_localizer: bool,
}

impl MeasuredRoute {
    pub(super) fn execution_route(self) -> keyhog_scanner::ScanExecutionRoute {
        keyhog_scanner::ScanExecutionRoute {
            decode_backend: if self.backend.is_gpu() {
                ScanBackend::CpuFallback
            } else {
                self.backend
            },
            phase2_plain_localizer: self.phase2_plain_localizer,
            phase2_keyword_localizer: self.phase2_keyword_localizer,
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
        .filter(|(route, _)| route.backend != selected.backend)
        .map(|(_, timing_ns)| *timing_ns)
        .min()
        .map(|next_time| next_time.saturating_sub(selected_time))
}

fn accelerator_cold_warm_route_evidence(
    timing: &BackendTimingEvidence,
) -> Option<(u128, BackendTimingEvidence, u128)> {
    let (&cold_ns, warm_trials) = timing.trials_ns.split_first()?;
    if warm_trials.len() != AUTOROUTE_ACCELERATOR_WARM_TRIALS {
        return None;
    }
    let warm_timing = BackendTimingEvidence::from_trial_ns(warm_trials.to_vec())?;
    if !warm_timing.is_valid_for_trials(AUTOROUTE_ACCELERATOR_WARM_TRIALS) {
        return None;
    }
    // A single lucky minimum is not representative routing evidence. Use the
    // warm median, while retaining the real first dispatch as a lower bound for
    // one-shot routing. The daemon path consumes the warm median directly.
    let route_ns = cold_ns.max(warm_timing.median_ns());
    Some((cold_ns, warm_timing, route_ns))
}

pub(super) fn gpu_cold_warm_route_evidence(
    timing: &BackendTimingEvidence,
) -> Option<(u128, BackendTimingEvidence, u128)> {
    accelerator_cold_warm_route_evidence(timing)
}

pub(super) fn simd_cold_warm_route_evidence(
    timing: &BackendTimingEvidence,
) -> Option<(u128, BackendTimingEvidence, u128)> {
    accelerator_cold_warm_route_evidence(timing)
}

/// Parity and timing binding for one measured backend candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BackendParityReceipt {
    pub(super) backend: String,
    pub(super) phase2_plain_localizer: bool,
    pub(super) phase2_keyword_localizer: bool,
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
            phase2_plain_localizer: route.phase2_plain_localizer,
            phase2_keyword_localizer: route.phase2_keyword_localizer,
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
            .field_bool("phase2_plain_localizer", route.phase2_plain_localizer)
            .field_bool("phase2_keyword_localizer", route.phase2_keyword_localizer)
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
    pub(super) phase2_plain_localizer: bool,
    pub(super) phase2_keyword_localizer: bool,
    pub(super) calibration_points: Vec<AutorouteCalibrationPoint>,
}

/// Timing evidence for one exact backend and phase-two execution plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RouteTimingEvidence {
    pub(super) backend: String,
    pub(super) phase2_plain_localizer: bool,
    pub(super) phase2_keyword_localizer: bool,
    pub(super) timing: BackendTimingEvidence,
}

impl RouteTimingEvidence {
    pub(super) fn new(route: MeasuredRoute, timing: BackendTimingEvidence) -> Self {
        Self {
            backend: route.backend.label().to_string(),
            phase2_plain_localizer: route.phase2_plain_localizer,
            phase2_keyword_localizer: route.phase2_keyword_localizer,
            timing,
        }
    }

    pub(super) fn measured_route(&self) -> Option<MeasuredRoute> {
        Some(MeasuredRoute {
            backend: keyhog_scanner::hw_probe::parse_backend_str(&self.backend)?,
            phase2_plain_localizer: self.phase2_plain_localizer,
            phase2_keyword_localizer: self.phase2_keyword_localizer,
        })
    }
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
    pub(super) route_timings: Vec<RouteTimingEvidence>,
    pub(super) trials: usize,
}

impl AutorouteCalibrationPoint {
    fn measured_routes(&self) -> Vec<MeasuredRoute> {
        self.route_timings
            .iter()
            .filter_map(RouteTimingEvidence::measured_route)
            .collect()
    }

    pub(super) fn timing_for_route(&self, route: MeasuredRoute) -> Option<&BackendTimingEvidence> {
        self.route_timings
            .iter()
            .find(|entry| entry.measured_route() == Some(route))
            .map(|entry| &entry.timing)
    }

    pub(super) fn baseline_timing_for_backend(
        &self,
        backend: ScanBackend,
    ) -> Option<&BackendTimingEvidence> {
        self.timing_for_route(MeasuredRoute {
            backend,
            phase2_plain_localizer: false,
            phase2_keyword_localizer: false,
        })
    }

    pub(super) fn gpu_cold_warm_route_for_measured(
        &self,
        route: MeasuredRoute,
    ) -> Option<(u128, BackendTimingEvidence, u128)> {
        route.backend.is_gpu().then_some(())?;
        self.timing_for_route(route)
            .and_then(gpu_cold_warm_route_evidence)
    }

    fn accelerator_cold_warm_route_for_measured(
        &self,
        route: MeasuredRoute,
    ) -> Option<(u128, BackendTimingEvidence, u128)> {
        match route.backend {
            ScanBackend::SimdCpu => self
                .timing_for_route(route)
                .and_then(simd_cold_warm_route_evidence),
            ScanBackend::GpuCuda | ScanBackend::GpuWgpu => {
                self.gpu_cold_warm_route_for_measured(route)
            }
            _ => None,
        }
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
            .filter(|(route, _)| route.backend != selected.backend)
            .all(|(_, competitor_interval)| selected_interval.high_ns < competitor_interval.low_ns)
    }

    pub(super) fn resolve_measured_route(&self, persistent_runtime: bool) -> Option<MeasuredRoute> {
        self.resolve_measured_route_excluding(persistent_runtime, None)
    }

    fn resolve_measured_route_excluding(
        &self,
        persistent_runtime: bool,
        excluded_backend: Option<ScanBackend>,
    ) -> Option<MeasuredRoute> {
        let intervals = self
            .route_confidence_intervals_for(persistent_runtime)
            .into_iter()
            .filter(|(route, _)| Some(route.backend) != excluded_backend)
            .collect::<Vec<_>>();
        intervals
            .iter()
            .filter(|(route, interval)| {
                intervals.iter().all(|(competitor_route, competitor)| {
                    competitor_route.backend == route.backend
                        || interval.high_ns < competitor.low_ns
                })
            })
            .filter_map(|(route, _)| {
                self.route_median_ns(*route, persistent_runtime)
                    .map(|median_ns| (*route, median_ns))
            })
            .min_by_key(|(route, median_ns)| {
                (
                    *median_ns,
                    route.phase2_plain_localizer,
                    route.phase2_keyword_localizer,
                )
            })
            .map(|(route, _)| route)
    }

    fn route_median_ns(&self, route: MeasuredRoute, persistent_runtime: bool) -> Option<u128> {
        match route.backend {
            ScanBackend::CpuFallback => self
                .timing_for_route(route)
                .map(BackendTimingEvidence::median_ns),
            ScanBackend::SimdCpu | ScanBackend::GpuCuda | ScanBackend::GpuWgpu => {
                let (_, warm_timing, one_shot_ns) =
                    self.accelerator_cold_warm_route_for_measured(route)?;
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
        let mut intervals = Vec::with_capacity(self.route_timings.len());
        for route in self.measured_routes() {
            if route.backend == ScanBackend::SimdCpu || route.backend.is_gpu() {
                let Some((cold_ns, warm_timing, _route_ns)) =
                    self.accelerator_cold_warm_route_for_measured(route)
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
        route_timings: &[RouteTimingEvidence],
    ) -> Vec<BackendParityReceipt> {
        route_timings
            .iter()
            .filter_map(|entry| {
                Some(BackendParityReceipt::new(
                    entry.measured_route()?,
                    correctness_digest,
                    &entry.timing,
                ))
            })
            .collect()
    }

    fn canonicalize_route_timings(route_timings: &mut [RouteTimingEvidence]) {
        route_timings.sort_unstable_by(|left, right| {
            (
                left.backend.as_str(),
                left.phase2_plain_localizer,
                left.phase2_keyword_localizer,
            )
                .cmp(&(
                    right.backend.as_str(),
                    right.phase2_plain_localizer,
                    right.phase2_keyword_localizer,
                ))
        });
    }

    #[cfg(test)]
    fn test_route_timings(
        backends: impl IntoIterator<Item = (ScanBackend, Option<BackendTimingEvidence>)>,
    ) -> Vec<RouteTimingEvidence> {
        let mut routes = Vec::new();
        for (backend, timing) in backends {
            let Some(base) = timing else {
                continue;
            };
            for phase2_plain_localizer in [false, true] {
                for phase2_keyword_localizer in [false, true] {
                    let timing = if phase2_plain_localizer || phase2_keyword_localizer {
                        BackendTimingEvidence::constant_ms(
                            base.median_ms().saturating_add(1_000),
                            AUTOROUTE_CALIBRATION_TRIALS,
                        )
                    } else {
                        base.clone()
                    };
                    routes.push(RouteTimingEvidence::new(
                        MeasuredRoute {
                            backend,
                            phase2_plain_localizer,
                            phase2_keyword_localizer,
                        },
                        timing,
                    ));
                }
            }
        }
        routes
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
        // default an omitted explicit value to a clearly slower scalar route so
        // a nominal SIMD decision remains confidence-separated; missing-candidate
        // tests remove the field after construction.
        let cpu_duration_ms = match cpu_ms {
            Some(duration_ms) => duration_ms,
            None => simd_ms.saturating_add(1_000),
        };
        let cpu_timing = Some(BackendTimingEvidence::constant_ms(
            cpu_duration_ms,
            AUTOROUTE_CALIBRATION_TRIALS,
        ));
        let gpu_wgpu_timing =
            gpu_ms.map(|ms| BackendTimingEvidence::constant_ms(ms, AUTOROUTE_CALIBRATION_TRIALS));
        let mut route_timings = Self::test_route_timings([
            (ScanBackend::SimdCpu, Some(simd_timing)),
            (ScanBackend::CpuFallback, cpu_timing),
            (ScanBackend::GpuCuda, None),
            (ScanBackend::GpuWgpu, gpu_wgpu_timing),
        ]);
        Self::canonicalize_route_timings(&mut route_timings);
        let candidate_receipts = Self::candidate_receipts(0xA11D_0B57_A11D_0B57, &route_timings);
        Self {
            backend: backend.label().to_string(),
            phase2_plain_localizer: false,
            phase2_keyword_localizer: false,
            calibration_points: vec![AutorouteCalibrationPoint {
                sample_bytes,
                sample_chunks,
                candidate_receipts,
                calibrated_at_unix_ms: 1,
                route_timings,
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
        let mut route_timings = Self::test_route_timings([
            (ScanBackend::SimdCpu, Some(simd_timing)),
            (ScanBackend::CpuFallback, cpu_timing),
            (ScanBackend::GpuCuda, None),
            (ScanBackend::GpuWgpu, gpu_timing),
        ]);
        Self::canonicalize_route_timings(&mut route_timings);
        let candidate_receipts = Self::candidate_receipts(correctness_digest, &route_timings);
        Self {
            backend: backend.label().to_string(),
            phase2_plain_localizer: false,
            phase2_keyword_localizer: false,
            calibration_points: vec![AutorouteCalibrationPoint {
                sample_bytes,
                sample_chunks,
                candidate_receipts,
                calibrated_at_unix_ms,
                route_timings,
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
        mut route_timings: Vec<RouteTimingEvidence>,
    ) -> Self {
        Self::canonicalize_route_timings(&mut route_timings);
        let candidate_receipts = Self::candidate_receipts(correctness_digest, &route_timings);
        Self {
            backend: backend.label().to_string(),
            phase2_plain_localizer: false,
            phase2_keyword_localizer: false,
            calibration_points: vec![AutorouteCalibrationPoint {
                sample_bytes,
                sample_chunks,
                candidate_receipts,
                calibrated_at_unix_ms,
                route_timings,
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
        for (runtime_label, persistent_runtime, expected_route) in [
            ("one-shot", false, expected_one_shot),
            ("daemon", true, expected_daemon),
        ] {
            if !expected_route.backend.is_gpu() {
                continue;
            }
            let existing_recovery = self
                .resolved_recovery_route(expected_route.backend, persistent_runtime)
                .ok_or_else(|| {
                    format!(
                        "existing workload evidence has no unanimous {runtime_label} recovery route after {}",
                        expected_route.backend.label()
                    )
                })?;
            let measured_recovery = point
                .resolve_measured_route_excluding(persistent_runtime, Some(expected_route.backend))
                .ok_or_else(|| {
                    format!(
                        "new workload point has no {runtime_label} recovery route after {}",
                        expected_route.backend.label()
                    )
                })?;
            if existing_recovery != measured_recovery {
                return Err(format!(
                    "workload class changes fastest remaining {runtime_label} recovery route after {}: existing={}, new {}-byte/{}-chunk point={}; split the workload identity at this recovery crossover and recalibrate",
                    expected_route.backend.label(),
                    render_measured_route(existing_recovery),
                    point.sample_bytes,
                    point.sample_chunks,
                    render_measured_route(measured_recovery),
                ));
            }
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
            phase2_plain_localizer: self.phase2_plain_localizer,
            phase2_keyword_localizer: self.phase2_keyword_localizer,
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

    /// SIMD `(plain=false, keyword=false)` baseline in ms.
    pub(super) fn simd_baseline_ms(&self) -> u128 {
        self.primary_point()
            .baseline_timing_for_backend(ScanBackend::SimdCpu)
            .expect("validated calibration contains the SIMD baseline route")
            .median_ms()
    }

    /// CPU-fallback `(plain=false, keyword=false)` baseline in ms, if measured.
    pub(super) fn cpu_baseline_ms(&self) -> Option<u128> {
        self.primary_point()
            .baseline_timing_for_backend(ScanBackend::CpuFallback)
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
        let route = self.measured_route()?;
        route.backend.is_gpu().then_some(())?;
        self.primary_point()
            .timing_for_route(route)
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

    pub(super) fn baseline_timing_for_backend(
        &self,
        backend: ScanBackend,
    ) -> Option<&BackendTimingEvidence> {
        self.primary_point().baseline_timing_for_backend(backend)
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
    /// A route resolves only when its 95% interval lies entirely below every
    /// route of every peer backend. Equivalent plans within that backend are not
    /// fake backend competitors; the lowest measured-median proven plan wins.
    /// Cross-backend overlap is incomplete evidence, never permission to persist
    /// a measured-median guess as the fastest backend.
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

    /// Fastest measured-correct route after one backend becomes unhealthy.
    /// Every retained point in the workload class must agree, just as it must
    /// for the primary route. Excluding the backend, rather than only the one
    /// localizer variant, prevents a runtime device fault from being disguised
    /// as a second plan on the same unhealthy peer.
    pub(super) fn resolved_recovery_route(
        &self,
        failed_backend: ScanBackend,
        persistent_runtime: bool,
    ) -> Option<MeasuredRoute> {
        let selected = self
            .calibration_points
            .first()?
            .resolve_measured_route_excluding(persistent_runtime, Some(failed_backend))?;
        self.calibration_points
            .iter()
            .all(|point| {
                point.resolve_measured_route_excluding(persistent_runtime, Some(failed_backend))
                    == Some(selected)
            })
            .then_some(selected)
    }

    /// True iff one backend is provably fastest. The resolved route's 95% CI
    /// lies entirely below every route belonging to every peer backend.
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

    pub(super) fn confidence_diagnostic(&self, persistent_runtime: bool) -> String {
        let Some(point) = self.calibration_points.first() else {
            return "no measured calibration point".to_string();
        };
        point
            .route_confidence_intervals_for(persistent_runtime)
            .into_iter()
            .filter_map(|(route, interval)| {
                point
                    .route_median_ns(route, persistent_runtime)
                    .map(|median_ns| {
                        format!(
                            "{} median_ns={median_ns} ci95_ns=[{},{}]",
                            render_measured_route(route),
                            interval.low_ns,
                            interval.high_ns,
                        )
                    })
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

fn render_measured_route(route: MeasuredRoute) -> String {
    format!(
        "{}+phase2-plain-localizer={}+phase2-keyword-localizer={}",
        route.backend.label(),
        route.phase2_plain_localizer,
        route.phase2_keyword_localizer,
    )
}
