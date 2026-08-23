//! Autoroute backend decisions derived from measured timing evidence.

use keyhog_scanner::hw_probe::ScanBackend;
use serde::{Deserialize, Serialize};

mod match_identity;
mod timing;

pub(super) use match_identity::{
    canonical_match_differences, canonical_match_digest, canonical_matches,
    canonical_matches_equal_reference, differing_canonical_match_fields, CanonicalMatch,
};
#[cfg(test)]
pub(super) use timing::{paired_candidate_is_faster_95, ColdWarmStatisticalModel};
pub(super) use timing::{BackendTimingEvidence, TimingConfidenceInterval};

use super::workload::MeasurementShapeEvidence;
use super::{AUTOROUTE_ACCELERATOR_WARM_TRIALS, AUTOROUTE_CALIBRATION_TRIALS};

pub(super) const MAX_AUTOROUTE_MEASURED_POINTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MeasuredRoute {
    pub(super) backend: ScanBackend,
    pub(super) phase2_plain_localizer: bool,
    pub(super) phase2_keyword_localizer: bool,
    pub(super) gpu_pipeline_depth: u8,
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
            gpu_pipeline_depth: self.gpu_pipeline_depth,
        }
    }
}

/// Ordering used when measurement proves no backend faster than another: the
/// backend that needs no accelerator bring-up and always runs comes first.
const fn backend_route_complexity(backend: ScanBackend) -> u8 {
    match backend {
        ScanBackend::CpuFallback => 0,
        ScanBackend::SimdCpu => 1,
        ScanBackend::GpuCuda => 2,
        ScanBackend::GpuMetal => 3,
        _ => 4,
    }
}

/// Reconcile every measured point of a workload class into one route.
///
/// The plan on top of a backend was already reconciled rather than required to
/// match, because points that agreed on the backend and split on the plan were
/// splitting on noise, and discarding the class made every later scan of that
/// workload pay scalar recovery forever.
///
/// The backend used to demand unanimity, and that reintroduced the same bug one
/// level up. Two backends whose 95% intervals overlap have no measured winner,
/// so which of them a given point happens to pick is a coin flip. On a 16-core
/// AVX-512 host the 4 MiB through 32 MiB buckets landed exactly there: the
/// one-shot route was stable at cpu-fallback while the daemon route flipped
/// between simd-regex and cpu-fallback, and across three retries of the SAME
/// bucket the two backends swapped which side of the comparison they were on,
/// which is the signature of overlap and not of a crossover. Refusing the class
/// discarded it, refusing any class refused the whole generation, and the
/// installer could not complete: no cache was written, so every later scan
/// failed closed with exit 2.
///
/// Disagreement is therefore resolved the way the documented contract already
/// promises for overlapping timings: to the lowest-complexity NON-INFERIOR
/// route. A backend is non-inferior when no point proves a peer faster than it,
/// by the same 95% separation the point-level selector uses. When some point
/// does prove a peer faster, the disagreement is a real crossover, nothing is
/// non-inferior everywhere, and the class is still refused.
fn resolve_route_across_points(
    points: &[&AutorouteCalibrationPoint],
    persistent_runtime: bool,
    excluded_backend: Option<ScanBackend>,
) -> Option<MeasuredRoute> {
    let first = *points.first()?;
    let resolved: Vec<MeasuredRoute> = points
        .iter()
        .map(|point| point.resolve_selected_route_excluding(persistent_runtime, excluded_backend))
        .collect::<Option<Vec<_>>>()?;
    let selected = *resolved.first()?;

    let backend = if resolved
        .iter()
        .all(|route| route.backend == selected.backend)
    {
        if resolved.iter().all(|route| *route == selected) {
            return Some(selected);
        }
        selected.backend
    } else {
        // Every backend the points disagree over, cheapest first, keeping only
        // those measured at every point and proved worse at none.
        let mut contenders: Vec<ScanBackend> = resolved.iter().map(|route| route.backend).collect();
        contenders.sort_unstable_by_key(|backend| backend_route_complexity(*backend));
        contenders.dedup();
        contenders.into_iter().find(|backend| {
            points.iter().all(|point| {
                point
                    .measured_routes()
                    .iter()
                    .any(|route| route.backend == *backend)
                    && !point.backend_is_separated_loser(*backend, persistent_runtime)
            })
        })?
    };

    // One backend, but the points split on the plan. Fall back to the plan the
    // binary was compiled with: it certainly exists and certainly runs, and
    // every point must have measured that exact route.
    let default_plan = MeasuredRoute {
        backend,
        phase2_plain_localizer: first.compiled_default_phase2_plain_localizer,
        phase2_keyword_localizer: first.compiled_default_phase2_keyword_localizer,
        gpu_pipeline_depth: resolved
            .iter()
            .find(|route| route.backend == backend)
            .map_or(selected.gpu_pipeline_depth, |route| {
                route.gpu_pipeline_depth
            }),
    };
    points
        .iter()
        .all(|point| {
            point.compiled_default_phase2_plain_localizer == default_plan.phase2_plain_localizer
                && point.compiled_default_phase2_keyword_localizer
                    == default_plan.phase2_keyword_localizer
                && point.measured_routes().contains(&default_plan)
        })
        .then_some(default_plan)
}

/// Reconcile every measured band of one workload family into one route.
///
/// A family shares the detector corpus, decode state and set of source classes
/// and differs only in size band. Reconciling it pools the bands' calibration
/// points through [`resolve_route_across_points`], so a family is resolved by
/// exactly the rule a single class is: a backend must be measured at every
/// pooled point and proved slower at none, and points that agree on the backend
/// while splitting on the plan resolve to the compiled default plan.
///
/// Demanding full-route unanimity across bands instead reproduced, one level
/// up, the bug that rule was written for. On a 16-core AVX-512 host the six
/// measured decode-admitted bands of the default policy all selected
/// cpu-fallback and split three ways on the phase-2 localizer plan, which is a
/// sub-plan coin flip between routes within a millisecond of each other. Every
/// unmeasured band of that family then failed closed with exit 2 even though
/// nothing about the backend was ever in doubt.
pub(super) fn reconcile_route_across_decisions(
    members: &[&AutorouteDecision],
    persistent_runtime: bool,
) -> Option<MeasuredRoute> {
    let points: Vec<&AutorouteCalibrationPoint> = members
        .iter()
        .flat_map(|decision| decision.calibration_points.iter())
        .collect();
    resolve_route_across_points(&points, persistent_runtime, None)
}

fn paired_route_trials_are_faster(selected: &[u128], competitor: &[u128]) -> bool {
    if selected.len() != competitor.len() || selected.is_empty() {
        return false;
    }
    timing::paired_candidate_is_faster_95(selected, competitor)
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

fn accelerator_cold_warm_route_evidence(
    timing: &BackendTimingEvidence,
) -> Option<(u128, BackendTimingEvidence, u128)> {
    let model = timing.cold_warm_model()?;
    if model.warm_trials_ns.len() != AUTOROUTE_ACCELERATOR_WARM_TRIALS {
        return None;
    }
    let warm_timing = BackendTimingEvidence::from_trial_ns(model.warm_trials_ns.clone())?;
    if !warm_timing.is_valid_for_trials(AUTOROUTE_ACCELERATOR_WARM_TRIALS) {
        return None;
    }
    let route_ns = model.cold_one_shot_ns.max(model.warm_median_ns);
    Some((model.cold_one_shot_ns, warm_timing, route_ns))
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
    pub(super) gpu_pipeline_depth: u8,
    pub(super) gpu_dispatch_capability: Option<String>,
    pub(super) gpu_slot_input_capacity_bytes: Option<u64>,
    pub(super) gpu_slot_match_capacity: Option<u32>,
    pub(super) peer_identity: Option<String>,
    pub(super) correctness_digest: u64,
    pub(super) completed_trials: usize,
    pub(super) evidence_digest: u64,
}

impl BackendParityReceipt {
    fn new(
        route: MeasuredRoute,
        timing_entry: &RouteTimingEvidence,
        correctness_digest: u64,
    ) -> Self {
        let peer_identity = timing_entry.peer_identity.as_deref();
        let timing = &timing_entry.timing;
        let completed_trials = timing.trials_ns.len();
        let evidence_digest = Self::evidence_digest_for(
            route,
            peer_identity,
            correctness_digest,
            completed_trials,
            timing,
            timing_entry.gpu_dispatch_capability.as_deref(),
            timing_entry.gpu_slot_input_capacity_bytes,
            timing_entry.gpu_slot_match_capacity,
        );
        Self {
            backend: route.backend.label().to_string(),
            phase2_plain_localizer: route.phase2_plain_localizer,
            phase2_keyword_localizer: route.phase2_keyword_localizer,
            peer_identity: peer_identity.map(str::to_owned),
            gpu_pipeline_depth: route.gpu_pipeline_depth,
            gpu_dispatch_capability: timing_entry.gpu_dispatch_capability.clone(),
            gpu_slot_input_capacity_bytes: timing_entry.gpu_slot_input_capacity_bytes,
            gpu_slot_match_capacity: timing_entry.gpu_slot_match_capacity,
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
            self.peer_identity.as_deref(),
            self.correctness_digest,
            self.completed_trials,
            timing,
            self.gpu_dispatch_capability.as_deref(),
            self.gpu_slot_input_capacity_bytes,
            self.gpu_slot_match_capacity,
        )
    }

    fn evidence_digest_for(
        route: MeasuredRoute,
        peer_identity: Option<&str>,
        correctness_digest: u64,
        completed_trials: usize,
        timing: &BackendTimingEvidence,
        gpu_dispatch_capability: Option<&str>,
        gpu_slot_input_capacity_bytes: Option<u64>,
        gpu_slot_match_capacity: Option<u32>,
    ) -> u64 {
        let mut hasher = crate::stable_hash::StableHasher::new("autoroute-parity-receipt");
        hasher
            .field_str("backend", route.backend.label())
            .field_bool("phase2_plain_localizer", route.phase2_plain_localizer)
            .field_bool("phase2_keyword_localizer", route.phase2_keyword_localizer)
            .field_u64("gpu_pipeline_depth", u64::from(route.gpu_pipeline_depth))
            .field_bool(
                "gpu_dispatch_capability.present",
                gpu_dispatch_capability.is_some(),
            )
            .field_str(
                "gpu_dispatch_capability",
                gpu_dispatch_capability.unwrap_or(""),
            )
            .field_u64(
                "gpu_slot_input_capacity_bytes",
                gpu_slot_input_capacity_bytes.unwrap_or(0),
            )
            .field_u64(
                "gpu_slot_match_capacity",
                u64::from(gpu_slot_match_capacity.unwrap_or(0)),
            )
            .field_bool("peer_identity.present", peer_identity.is_some())
            // LAW10: canonical default; a preceding presence field distinguishes absence, and the empty string is only the digest payload for `None`.
            .field_str("peer_identity", peer_identity.unwrap_or(""))
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
    pub(super) gpu_pipeline_depth: u8,
    pub(super) calibration_points: Vec<AutorouteCalibrationPoint>,
}

/// Timing evidence for one exact backend and phase-two execution plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RouteTimingEvidence {
    pub(super) backend: String,
    pub(super) phase2_plain_localizer: bool,
    pub(super) phase2_keyword_localizer: bool,
    pub(super) gpu_pipeline_depth: u8,
    pub(super) gpu_dispatch_capability: Option<String>,
    pub(super) gpu_slot_input_capacity_bytes: Option<u64>,
    pub(super) gpu_slot_match_capacity: Option<u32>,
    pub(super) peer_identity: Option<String>,
    pub(super) ordered_device_route: Option<keyhog_scanner::gpu::device_set::OrderedGpuDeviceRoute>,
    pub(super) timing: BackendTimingEvidence,
}

impl RouteTimingEvidence {
    #[cfg(test)]
    pub(super) fn new(route: MeasuredRoute, timing: BackendTimingEvidence) -> Self {
        let peer_identity = route
            .backend
            .is_gpu()
            .then(|| format!("test-peer:{}", route.backend.label()));
        let gpu_pipeline = route.backend.is_gpu().then(|| {
            (
                if route.gpu_pipeline_depth == 1 {
                    "timed-resident"
                } else {
                    "async-submit-retire"
                }
                .to_string(),
                1024_u64 / u64::from(route.gpu_pipeline_depth),
                65_536_u32 / u32::from(route.gpu_pipeline_depth),
            )
        });
        Self::new_with_peer_identity(route, timing, peer_identity, gpu_pipeline)
    }

    pub(super) fn new_with_peer_identity(
        route: MeasuredRoute,
        timing: BackendTimingEvidence,
        peer_identity: Option<String>,
        gpu_pipeline: Option<(String, u64, u32)>,
    ) -> Self {
        let (gpu_dispatch_capability, gpu_slot_input_capacity_bytes, gpu_slot_match_capacity) =
            match gpu_pipeline {
                Some((capability, input_capacity, match_capacity)) => {
                    (Some(capability), Some(input_capacity), Some(match_capacity))
                }
                None => (None, None, None),
            };
        Self {
            backend: route.backend.label().to_string(),
            phase2_plain_localizer: route.phase2_plain_localizer,
            phase2_keyword_localizer: route.phase2_keyword_localizer,
            gpu_pipeline_depth: route.gpu_pipeline_depth,
            gpu_dispatch_capability,
            gpu_slot_input_capacity_bytes,
            gpu_slot_match_capacity,
            peer_identity,
            ordered_device_route: None,
            timing,
        }
    }

    #[allow(dead_code)]
    pub(super) fn bind_ordered_device_route(
        mut self,
        device_route: keyhog_scanner::gpu::device_set::OrderedGpuDeviceRoute,
    ) -> Result<Self, String> {
        device_route.validate()?;
        let measured = self
            .measured_route()
            .ok_or_else(|| "ordered GPU route names an unsupported backend".to_string())?;
        if !measured.backend.is_gpu() {
            return Err("ordered GPU device evidence cannot bind a host backend".to_string());
        }
        if device_route.devices.len() < 2 {
            return Err(
                "ordered multi-device autoroute evidence requires at least two devices".to_string(),
            );
        }
        if device_route
            .devices
            .iter()
            .any(|device| device.api.scan_backend() != measured.backend)
        {
            return Err(format!(
                "ordered device set does not use the measured {} backend on every device",
                measured.backend.label()
            ));
        }
        self.peer_identity = Some(format!(
            "ordered-device-set:{}",
            device_route.authenticated_digest
        ));
        self.ordered_device_route = Some(device_route);
        Ok(self)
    }

    pub(super) fn measured_route(&self) -> Option<MeasuredRoute> {
        Some(MeasuredRoute {
            backend: keyhog_scanner::hw_probe::parse_backend_str(&self.backend)?,
            phase2_plain_localizer: self.phase2_plain_localizer,
            phase2_keyword_localizer: self.phase2_keyword_localizer,
            gpu_pipeline_depth: self.gpu_pipeline_depth,
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
    pub(super) measurement_shape: MeasurementShapeEvidence,
    pub(super) compiled_default_phase2_plain_localizer: bool,
    pub(super) compiled_default_phase2_keyword_localizer: bool,
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

    pub(super) fn route_timing_for_route(
        &self,
        route: MeasuredRoute,
    ) -> Option<&RouteTimingEvidence> {
        self.route_timings
            .iter()
            .find(|entry| entry.measured_route() == Some(route))
    }

    pub(super) fn timing_for_route(&self, route: MeasuredRoute) -> Option<&BackendTimingEvidence> {
        self.route_timing_for_route(route)
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
            gpu_pipeline_depth: 1,
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

    pub(super) fn accelerator_cold_warm_route_for_measured(
        &self,
        route: MeasuredRoute,
    ) -> Option<(u128, BackendTimingEvidence, u128)> {
        match route.backend {
            ScanBackend::SimdCpu => self
                .timing_for_route(route)
                .and_then(simd_cold_warm_route_evidence),
            ScanBackend::GpuCuda | ScanBackend::GpuMetal | ScanBackend::GpuWgpu => {
                self.gpu_cold_warm_route_for_measured(route)
            }
            _ => None,
        }
    }

    pub(super) fn selected_route_has_confidence_for(
        &self,
        selected: MeasuredRoute,
        persistent_runtime: bool,
    ) -> bool {
        self.resolve_measured_route(persistent_runtime) == Some(selected)
    }

    pub(super) fn selected_route_has_exact_plan_confidence_for(
        &self,
        selected: MeasuredRoute,
        persistent_runtime: bool,
    ) -> bool {
        self.route_is_confidence_winner(selected, persistent_runtime, None)
    }

    /// Does this point PROVE some other backend faster than `candidate`?
    ///
    /// Proof is the same 95% separation the point-level selector demands: a
    /// peer route whose whole interval lies below every `candidate` route's
    /// interval. Anything less is overlap, and under overlap which backend
    /// posts the lower median is a coin flip that changes from run to run.
    ///
    /// This is the cross-point counterpart to
    /// [`Self::selected_route_has_confidence_for`]. That one asks "is this the
    /// route this point picks", which two indistinguishable backends answer
    /// differently at random. This one asks "is this route measurably wrong
    /// here", which they both answer no, and that is the question a class
    /// spanning several points can actually act on.
    pub(super) fn backend_is_separated_loser(
        &self,
        candidate: ScanBackend,
        persistent_runtime: bool,
    ) -> bool {
        let intervals = self.route_confidence_intervals_for(persistent_runtime);
        let Some(candidate_low) = intervals
            .iter()
            .filter(|(route, _)| route.backend == candidate)
            .map(|(_, interval)| interval.low_ns)
            .min()
        else {
            return false;
        };
        intervals
            .iter()
            .filter(|(route, _)| route.backend != candidate)
            .any(|(_, interval)| interval.high_ns < candidate_low)
    }

    pub(super) fn resolve_measured_route(&self, persistent_runtime: bool) -> Option<MeasuredRoute> {
        self.resolve_measured_route_excluding(persistent_runtime, None)
    }

    /// The route this point selects: separated evidence first, then the
    /// deterministic dead-heat resolution when nothing separates.
    ///
    /// Route selection, class reconciliation and cache validation all read
    /// this. [`Self::resolve_measured_route`] stays the strict proof and keeps
    /// backing `confidence_separated`, so an unseparated selection is still
    /// reported as one.
    pub(super) fn resolve_selected_route(&self, persistent_runtime: bool) -> Option<MeasuredRoute> {
        self.resolve_selected_route_excluding(persistent_runtime, None)
    }

    pub(super) fn resolve_selected_route_excluding(
        &self,
        persistent_runtime: bool,
        excluded_backend: Option<ScanBackend>,
    ) -> Option<MeasuredRoute> {
        self.resolve_measured_route_excluding(persistent_runtime, excluded_backend)
            .or_else(|| self.resolve_dead_heat_route(persistent_runtime, excluded_backend))
    }

    fn resolve_measured_route_excluding(
        &self,
        persistent_runtime: bool,
        excluded_backend: Option<ScanBackend>,
    ) -> Option<MeasuredRoute> {
        let candidates = self.route_candidates_for_runtime(persistent_runtime);
        candidates
            .iter()
            .copied()
            .filter(|(route, _)| Some(route.backend) != excluded_backend)
            .filter(|(route, _)| {
                self.route_is_confidence_winner(*route, persistent_runtime, excluded_backend)
            })
            .min_by_key(|(route, median_ns)| {
                (
                    *median_ns,
                    route.phase2_plain_localizer,
                    route.phase2_keyword_localizer,
                    route.gpu_pipeline_depth,
                )
            })
            .map(|(route, _)| route)
            .or_else(|| {
                self.resolve_peer_separated_tied_route(persistent_runtime, excluded_backend)
            })
    }

    fn resolve_peer_separated_tied_route(
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
            .filter(|(selected, selected_interval)| {
                let has_peer = intervals
                    .iter()
                    .any(|(route, _)| route.backend != selected.backend);
                (has_peer || excluded_backend.is_some())
                    && intervals
                        .iter()
                        .filter(|(route, _)| route.backend != selected.backend)
                        .all(|(_, competitor_interval)| {
                            selected_interval.high_ns < competitor_interval.low_ns
                        })
                    && intervals
                        .iter()
                        .filter(|(route, _)| {
                            route.backend == selected.backend && *route != *selected
                        })
                        .all(|(competitor, _)| {
                            !self.same_backend_plan_is_faster(
                                *competitor,
                                *selected,
                                persistent_runtime,
                            )
                        })
            })
            .min_by_key(|(route, _)| {
                (
                    route.phase2_plain_localizer != self.compiled_default_phase2_plain_localizer
                        || route.phase2_keyword_localizer
                            != self.compiled_default_phase2_keyword_localizer,
                    route.phase2_plain_localizer,
                    route.phase2_keyword_localizer,
                    route.gpu_pipeline_depth,
                )
            })
            .map(|(route, _)| *route)
    }

    /// Deterministic resolution for a measurement where nothing separates.
    ///
    /// [`Self::resolve_measured_route_excluding`] answers only when one route's
    /// 95% interval lies entirely below every peer's. Real trees frequently do
    /// not separate. Calibrating the homefield corpus measured cpu-fallback at
    /// 4.507 s [3.08, 11.49] against wgpu at 4.462 s [4.40, 4.92], with every
    /// interval overlapping every other. The old answer was no route at all, so
    /// nothing was persisted and every later scan of that tree fell into scalar
    /// correctness recovery: the slowest outcome reachable from a measurement
    /// whose entire content is that the backends are indistinguishable.
    ///
    /// A dead heat is resolved instead of discarded. A route stays in
    /// contention unless some peer is proved faster, meaning that peer's whole
    /// interval lies below the route's own. Among the routes still in
    /// contention only those whose median falls within the fastest route's own
    /// 95% upper bound are eligible, so a route can never win on the strength
    /// of a wide error bar while its central tendency is measurably worse. The
    /// eligible set is ordered by backend complexity first, because when
    /// nothing is proved faster the backend that needs no accelerator
    /// initialization and always runs is the honest choice, and it is the same
    /// choice on every rerun of the same evidence. Plan selection then prefers
    /// the plan the binary was compiled with.
    ///
    /// This subsumes the exact peer-median tie it replaces: equal medians leave
    /// both routes in contention and both inside the fastest bound, so the
    /// lower-complexity backend still wins.
    fn resolve_dead_heat_route(
        &self,
        persistent_runtime: bool,
        excluded_backend: Option<ScanBackend>,
    ) -> Option<MeasuredRoute> {
        let intervals = self
            .route_confidence_intervals_for(persistent_runtime)
            .into_iter()
            .filter(|(route, _)| Some(route.backend) != excluded_backend)
            .collect::<Vec<_>>();
        let contenders = intervals
            .iter()
            .filter_map(|(route, interval)| {
                self.route_median_ns(*route, persistent_runtime)
                    .map(|median_ns| (*route, median_ns, *interval))
            })
            .filter(|(_, _, interval)| {
                !intervals
                    .iter()
                    .any(|(_, peer_interval)| peer_interval.high_ns < interval.low_ns)
            })
            .collect::<Vec<_>>();
        let fastest_high_ns = contenders
            .iter()
            .min_by_key(|(route, median_ns, _)| {
                (
                    *median_ns,
                    backend_route_complexity(route.backend),
                    route.phase2_plain_localizer,
                    route.phase2_keyword_localizer,
                    route.gpu_pipeline_depth,
                )
            })
            .map(|(_, _, interval)| interval.high_ns)?;
        contenders
            .iter()
            .filter(|(_, median_ns, _)| *median_ns <= fastest_high_ns)
            .min_by_key(|(route, median_ns, _)| {
                (
                    backend_route_complexity(route.backend),
                    route.phase2_plain_localizer != self.compiled_default_phase2_plain_localizer
                        || route.phase2_keyword_localizer
                            != self.compiled_default_phase2_keyword_localizer,
                    *median_ns,
                    route.phase2_plain_localizer,
                    route.phase2_keyword_localizer,
                    route.gpu_pipeline_depth,
                )
            })
            .map(|(route, _, _)| *route)
    }

    /// One-shot cost of an accelerator route, per trial.
    ///
    /// An accelerator pays a fixed setup cost once (Hyperscan database load,
    /// GPU context and buffer creation) and then scans. Calibration measures
    /// setup+scan exactly ONCE, as trial zero, and the scan alone six more
    /// times. The one-shot cost of trial `i` is therefore that single measured
    /// setup plus the scan time of trial `i`.
    ///
    /// This used to be `cold_ns.max(warm_ns)`. Because setup dominates for
    /// SIMD, every trial collapsed to the identical `cold_ns`, which turned a
    /// distribution into a constant: measured across a real 158-class
    /// calibration, 929 of 940 SIMD one-shot intervals had zero width. A
    /// zero-width interval never overlaps a peer, so SIMD was declared a
    /// *separated* loser against cpu-fallback on every one-shot route of every
    /// host, even where its own warm trials were faster than cpu's.
    ///
    /// The median is unchanged: `setup + warm_median` is `cold_ns` whenever
    /// setup is positive, which is what `route_ns` already reported.
    fn accelerator_setup_ns(cold_ns: u128, warm_timing: &BackendTimingEvidence) -> u128 {
        cold_ns.saturating_sub(warm_timing.median_ns())
    }

    fn route_trial_ns_for(
        &self,
        route: MeasuredRoute,
        persistent_runtime: bool,
    ) -> Option<Vec<u128>> {
        if route.backend == ScanBackend::SimdCpu || route.backend.is_gpu() {
            let (cold_ns, warm_timing, _) = self.accelerator_cold_warm_route_for_measured(route)?;
            if persistent_runtime {
                return Some(warm_timing.trials_ns);
            }
            let setup_ns = Self::accelerator_setup_ns(cold_ns, &warm_timing);
            Some(
                warm_timing
                    .trials_ns
                    .into_iter()
                    .map(|warm_ns| warm_ns.saturating_add(setup_ns))
                    .collect(),
            )
        } else {
            self.timing_for_route(route)
                .map(|timing| timing.trials_ns.clone())
        }
    }

    fn route_is_confidence_winner(
        &self,
        selected: MeasuredRoute,
        persistent_runtime: bool,
        excluded_backend: Option<ScanBackend>,
    ) -> bool {
        let intervals = self
            .route_confidence_intervals_for(persistent_runtime)
            .into_iter()
            .filter(|(route, _)| Some(route.backend) != excluded_backend)
            .collect::<Vec<_>>();
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
            .all(|(competitor, competitor_interval)| {
                if competitor.backend != selected.backend {
                    return selected_interval.high_ns < competitor_interval.low_ns;
                }
                self.same_backend_plan_is_faster(selected, *competitor, persistent_runtime)
            })
    }

    fn route_median_ns(&self, route: MeasuredRoute, persistent_runtime: bool) -> Option<u128> {
        match route.backend {
            ScanBackend::CpuFallback => self
                .timing_for_route(route)
                .map(BackendTimingEvidence::median_ns),
            ScanBackend::SimdCpu
            | ScanBackend::GpuCuda
            | ScanBackend::GpuMetal
            | ScanBackend::GpuWgpu => {
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

    /// One execution plan beats another on the SAME backend only when its 95%
    /// interval lies entirely below the other's AND its paired trials win.
    ///
    /// The paired test alone was not reproducible. Calibrating the mirror
    /// corpus five times with an identical binary, corpus and host, the same
    /// 664,161-byte/4,096-chunk point resolved
    /// `phase2-plain-localizer=true+phase2-keyword-localizer=true` on three
    /// runs and `false+false` on two, and the merge check then rejected the
    /// whole calibration as a workload crossover. Two of those runs disagreed
    /// in opposite directions on that one point, which is the proof that the
    /// verdict was noise rather than a real crossing: the backend was
    /// `cpu-fallback` in every observation, and only the sub-plan flipped.
    ///
    /// Cross-backend comparisons already demand interval separation. Demanding
    /// it here too is a strictly higher bar, so it can never promote a plan the
    /// old rule rejected; it can only decline to promote one whose lead does not
    /// survive its own error bars. A near-tie then falls through to the
    /// deterministic compiled-default preference, which is stable by
    /// construction.
    fn same_backend_plan_is_faster(
        &self,
        faster: MeasuredRoute,
        slower: MeasuredRoute,
        persistent_runtime: bool,
    ) -> bool {
        let intervals = self.route_confidence_intervals_for(persistent_runtime);
        let interval_for = |route: MeasuredRoute| {
            intervals
                .iter()
                .find(|(candidate, _)| *candidate == route)
                .map(|(_, interval)| *interval)
        };
        let (Some(faster_interval), Some(slower_interval)) =
            (interval_for(faster), interval_for(slower))
        else {
            return false;
        };
        if faster_interval.high_ns >= slower_interval.low_ns {
            return false;
        }
        let (Some(faster_trials), Some(slower_trials)) = (
            self.route_trial_ns_for(faster, persistent_runtime),
            self.route_trial_ns_for(slower, persistent_runtime),
        ) else {
            return false;
        };
        paired_route_trials_are_faster(&faster_trials, &slower_trials)
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
                        // Setup was measured once, so it contributes a shift,
                        // not certainty. The width stays the warm width.
                        let setup_ns = Self::accelerator_setup_ns(cold_ns, &warm_timing);
                        TimingConfidenceInterval {
                            low_ns: warm_interval.low_ns.saturating_add(setup_ns),
                            high_ns: warm_interval.high_ns.saturating_add(setup_ns),
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
                    entry,
                    correctness_digest,
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
                left.gpu_pipeline_depth,
            )
                .cmp(&(
                    right.backend.as_str(),
                    right.phase2_plain_localizer,
                    right.phase2_keyword_localizer,
                    right.gpu_pipeline_depth,
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
                            gpu_pipeline_depth: 1,
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
            gpu_pipeline_depth: 1,
            calibration_points: vec![AutorouteCalibrationPoint {
                sample_bytes,
                sample_chunks,
                measurement_shape: super::workload::test_measurement_shape_evidence(
                    sample_bytes,
                    sample_chunks,
                ),
                compiled_default_phase2_plain_localizer: false,
                compiled_default_phase2_keyword_localizer: false,
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
            gpu_pipeline_depth: 1,
            calibration_points: vec![AutorouteCalibrationPoint {
                sample_bytes,
                sample_chunks,
                measurement_shape: super::workload::test_measurement_shape_evidence(
                    sample_bytes,
                    sample_chunks,
                ),
                compiled_default_phase2_plain_localizer: false,
                compiled_default_phase2_keyword_localizer: false,
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
        measurement_shape: MeasurementShapeEvidence,
        correctness_digest: u64,
        calibrated_at_unix_ms: u128,
        mut route_timings: Vec<RouteTimingEvidence>,
        compiled_default_phase2_plain_localizer: bool,
        compiled_default_phase2_keyword_localizer: bool,
    ) -> Self {
        Self::canonicalize_route_timings(&mut route_timings);
        let candidate_receipts = Self::candidate_receipts(correctness_digest, &route_timings);
        Self {
            backend: backend.label().to_string(),
            phase2_plain_localizer: false,
            phase2_keyword_localizer: false,
            gpu_pipeline_depth: 1,
            calibration_points: vec![AutorouteCalibrationPoint {
                sample_bytes,
                sample_chunks,
                measurement_shape,
                compiled_default_phase2_plain_localizer,
                compiled_default_phase2_keyword_localizer,
                candidate_receipts,
                calibrated_at_unix_ms,
                route_timings,
                trials: AUTOROUTE_CALIBRATION_TRIALS,
            }],
        }
    }

    pub(super) fn contains_measurement(
        &self,
        measurement_shape: &MeasurementShapeEvidence,
    ) -> bool {
        self.calibration_points
            .iter()
            .any(|point| point.measurement_shape.shape_digest == measurement_shape.shape_digest)
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
            .ok_or_else(|| "autoroute calibration envelope lost its only point".to_string())?;
        if self.contains_measurement(&point.measurement_shape) {
            return Ok(());
        }
        for incoming in &point.route_timings {
            let route = incoming
                .measured_route()
                .ok_or_else(|| "new workload point contains an unsupported route".to_string())?;
            let existing = self
                .calibration_points
                .first()
                .and_then(|point| point.route_timing_for_route(route))
                .ok_or_else(|| {
                    format!(
                        "new workload point contains route {} absent from existing evidence",
                        render_measured_route(route)
                    )
                })?;
            match (
                existing.ordered_device_route.as_ref(),
                incoming.ordered_device_route.as_ref(),
            ) {
                (None, None) => {}
                (Some(left), Some(right)) if left.has_same_device_set_identity(right) => {}
                (Some(_), Some(_)) => {
                    return Err(format!(
                        "workload class changes its ordered GPU device-set identity for {}",
                        render_measured_route(route)
                    ));
                }
                _ => {
                    return Err(format!(
                        "workload class changes between single-device and ordered multi-device evidence for {}",
                        render_measured_route(route)
                    ));
                }
            }
        }
        if self.calibration_points.len() >= MAX_AUTOROUTE_MEASURED_POINTS {
            return Err(format!(
                "autoroute workload class already contains the maximum {MAX_AUTOROUTE_MEASURED_POINTS} measured calibration points; split the workload identity before adding more evidence"
            ));
        }
        let expected_one_shot = self.resolved_routing_route().ok_or_else(|| {
            "existing workload evidence does not resolve one one-shot route across its measured points"
                .to_string()
        })?;
        let measured_one_shot = point
            .resolve_selected_route(false)
            .ok_or_else(|| "new workload point does not resolve one one-shot route".to_string())?;
        if declared_one_shot != measured_one_shot {
            return Err(format!(
                "new workload point declares {} but its timing evidence resolves {}; recalibrate the point",
                render_measured_route(declared_one_shot),
                render_measured_route(measured_one_shot)
            ));
        }
        let expected_daemon = self.resolved_persistent_route().ok_or_else(|| {
            "existing workload evidence does not resolve one daemon route across its measured points"
                .to_string()
        })?;
        let measured_daemon = point
            .resolve_selected_route(true)
            .ok_or_else(|| "new workload point does not resolve one daemon route".to_string())?;
        // A backend disagreement between points is only a crossover when the
        // measurements PROVE it. Ask whether the class including this point
        // still resolves: `resolve_route_across_points` reconciles a
        // disagreement whose backends overlap to the lowest-complexity
        // non-inferior route, and answers None only when some point proves a
        // peer faster, which is the genuine crossover this error describes.
        //
        // Comparing the backends directly here refused the reconcilable case
        // before the resolver ever saw it, and one refused class refused the
        // whole generation, so the installer could not finish.
        let mut merged: Vec<&AutorouteCalibrationPoint> = self.calibration_points.iter().collect();
        merged.push(&point);
        let (Some(reconciled_one_shot), Some(reconciled_daemon)) = (
            resolve_route_across_points(&merged, false, None),
            resolve_route_across_points(&merged, true, None),
        ) else {
            return Err(format!(
                "workload class changes its confidence-supported backend across measured points: existing one-shot={} daemon={}, new {}-byte/{}-chunk point one-shot={} daemon={}; the disagreeing backends are separated by measurement, so this is a real crossover: split the workload identity here and recalibrate",
                render_measured_route(expected_one_shot),
                render_measured_route(expected_daemon),
                point.sample_bytes,
                point.sample_chunks,
                render_measured_route(measured_one_shot),
                render_measured_route(measured_daemon),
            ));
        };
        let expected_one_shot = reconciled_one_shot;
        let expected_daemon = reconciled_daemon;
        for (runtime_label, persistent_runtime, expected_route) in [
            ("one-shot", false, expected_one_shot),
            ("daemon", true, expected_daemon),
        ] {
            if expected_route.backend == ScanBackend::CpuFallback {
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
                .resolve_selected_route_excluding(persistent_runtime, Some(expected_route.backend))
                .ok_or_else(|| {
                    format!(
                        "new workload point has no {runtime_label} recovery route after {}",
                        expected_route.backend.label()
                    )
                })?;
            // Same rule as the primary route above: a recovery disagreement
            // that the merged evidence can still reconcile is overlap, not a
            // crossover. Only refuse when nothing is non-inferior everywhere.
            if resolve_route_across_points(
                &merged,
                persistent_runtime,
                Some(expected_route.backend),
            )
            .is_none()
            {
                return Err(format!(
                    "workload class changes its confidence-supported remaining {runtime_label} recovery backend after {}: existing={}, new {}-byte/{}-chunk point={}; the disagreeing recovery backends are separated by measurement, so this is a real crossover: split the workload identity here and recalibrate",
                    expected_route.backend.label(),
                    render_measured_route(existing_recovery),
                    point.sample_bytes,
                    point.sample_chunks,
                    render_measured_route(measured_recovery),
                ));
            }
        }
        self.calibration_points.push(point);
        self.calibration_points.sort_unstable_by_key(|point| {
            (
                point.sample_bytes,
                point.sample_chunks,
                point.measurement_shape.shape_digest,
            )
        });
        // Adding a point can move the class's execution plan onto the compiled
        // default, so the declared route has to follow. Validation requires the
        // persisted fields to equal what `resolved_routing_route` computes, and
        // leaving the first point's plan behind here made a merged class fail
        // as "selected route is not supported by the persisted timing
        // evidence".
        let reconciled = self.resolved_routing_route().ok_or_else(|| {
            "merged workload evidence does not resolve one one-shot route".to_string()
        })?;
        self.backend = reconciled.backend.label().to_string();
        self.phase2_plain_localizer = reconciled.phase2_plain_localizer;
        self.phase2_keyword_localizer = reconciled.phase2_keyword_localizer;
        self.gpu_pipeline_depth = reconciled.gpu_pipeline_depth;
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
            gpu_pipeline_depth: self.gpu_pipeline_depth,
        })
    }

    #[allow(dead_code)]
    pub(super) fn peer_identity_for_route(&self, route: MeasuredRoute) -> Option<&str> {
        let first = self
            .calibration_points
            .first()?
            .route_timings
            .iter()
            .find(|entry| entry.measured_route() == Some(route))?
            .peer_identity
            .as_deref();
        self.calibration_points
            .iter()
            .all(|point| {
                point
                    .route_timings
                    .iter()
                    .find(|entry| entry.measured_route() == Some(route))
                    .and_then(|entry| entry.peer_identity.as_deref())
                    == first
            })
            .then_some(first)
            .flatten()
    }
    #[allow(dead_code)]
    pub(super) fn ordered_device_route_for_route(
        &self,
        route: MeasuredRoute,
    ) -> Option<&keyhog_scanner::gpu::device_set::OrderedGpuDeviceRoute> {
        let first = self
            .calibration_points
            .first()?
            .route_timing_for_route(route)?
            .ordered_device_route
            .as_ref()?;
        self.calibration_points
            .iter()
            .all(|point| {
                point
                    .route_timing_for_route(route)
                    .and_then(|entry| entry.ordered_device_route.as_ref())
                    .is_some_and(|candidate| first.has_same_device_set_identity(candidate))
            })
            .then_some(first)
    }

    pub(super) fn gpu_pipeline_identity_for_route(
        &self,
        route: MeasuredRoute,
    ) -> Option<(&str, u64, u32)> {
        let first = self
            .calibration_points
            .first()?
            .route_timings
            .iter()
            .find(|entry| entry.measured_route() == Some(route))?;
        let identity = (
            first.gpu_dispatch_capability.as_deref()?,
            first.gpu_slot_input_capacity_bytes?,
            first.gpu_slot_match_capacity?,
        );
        self.calibration_points
            .iter()
            .all(|point| {
                point
                    .route_timings
                    .iter()
                    .find(|entry| entry.measured_route() == Some(route))
                    .is_some_and(|entry| {
                        entry.gpu_dispatch_capability.as_deref() == Some(identity.0)
                            && entry.gpu_slot_input_capacity_bytes == Some(identity.1)
                            && entry.gpu_slot_match_capacity == Some(identity.2)
                    })
            })
            .then_some(identity)
    }

    pub(super) fn primary_point(&self) -> &AutorouteCalibrationPoint {
        // LAW10: fail-closed; validated decisions contain evidence, and an invariant violation aborts rather than selecting an unevidenced route.
        self.calibration_points.first().unwrap_or_else(|| {
            panic!("autoroute decisions are constructed and validated with evidence")
        })
    }

    #[cfg(test)]
    pub(super) fn primary_point_mut(&mut self) -> &mut AutorouteCalibrationPoint {
        self.calibration_points
            .first_mut()
            // LAW10: no runtime effect; test-only mutation aborts when its fixture lacks the validated primary point.
            .unwrap_or_else(|| panic!("test autoroute decision must contain evidence"))
    }

    // Derived evidence is computed on demand, never persisted a second time.

    /// SIMD `(plain=false, keyword=false)` baseline in ms.
    pub(super) fn simd_baseline_ms(&self) -> u128 {
        self.primary_point()
            .baseline_timing_for_backend(ScanBackend::SimdCpu)
            // LAW10: fail-closed; validated calibration requires the SIMD baseline, and an invariant violation cannot substitute another timing.
            .unwrap_or_else(|| panic!("validated calibration contains the SIMD baseline route"))
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
        self.selected_route_has_confidence_for(route, false)
    }

    /// Strict separated proof: every point must pick `selected` outright.
    ///
    /// This deliberately does NOT accept a merely non-inferior route. It backs
    /// `has_confidence_supported_route`, whose meaning is "the measurements
    /// separate", and a class can legitimately hold a resolved route without
    /// holding that proof. Reconciliation under overlap belongs in
    /// [`resolve_route_across_points`], which decides the route; this decides
    /// whether the evidence for it separated.
    fn selected_route_has_confidence_for(
        &self,
        selected: MeasuredRoute,
        persistent_runtime: bool,
    ) -> bool {
        self.calibration_points
            .iter()
            .all(|point| point.selected_route_has_confidence_for(selected, persistent_runtime))
    }

    /// The single deterministic source of truth for which route a persisted
    /// timing set routes to. Calibration SELECTS this; validation REQUIRES the
    /// persisted backend and localizer choice to equal it. It is a pure function
    /// of the measured timing evidence (each executable GPU driver and localizer
    /// mode has its own route and timing), so a cache that names any other route is rejected as
    /// tampered or non-deterministic.
    ///
    /// Prefer a route whose 95% interval lies entirely below every peer and
    /// whose paired same-backend trials prove its exact plan faster. An exact
    /// peer-median tie resolves to the lower-complexity backend. Overlapping
    /// unequal measurements are inconclusive and produce no route.
    pub(super) fn resolved_routing_route(&self) -> Option<MeasuredRoute> {
        self.resolve_class_route(false)
    }

    /// Reconcile every measured point in the class into one route.
    ///
    /// Points that disagree about the backend resolve to the lowest-complexity
    /// backend measured at every point and proved slower at none. A real
    /// crossover leaves nothing non-inferior everywhere and stays unresolved.
    ///
    /// The execution plan on top of that backend is reconciled rather than
    /// required to match. Points that agree on the backend but split on the
    /// plan used to discard the whole class, and in the field that is what
    /// happened: calibrating the mirror corpus with an identical binary, corpus
    /// and host persisted nothing on three of five runs, and two of those runs
    /// disagreed in opposite directions about the same measured point, which
    /// proves the split was noise. Every scan of that workload then paid scalar
    /// recovery forever because a sub-plan coin flip discarded a backend
    /// decision that was never once in doubt.
    ///
    /// Leaving the compiled default still takes unanimous separated evidence at
    /// every point. Disagreement resolves to the default the binary was built
    /// with, which is a plan that certainly exists and certainly runs, instead
    /// of to no decision at all.
    fn resolve_class_route(&self, persistent_runtime: bool) -> Option<MeasuredRoute> {
        let points: Vec<&AutorouteCalibrationPoint> = self.calibration_points.iter().collect();
        resolve_route_across_points(&points, persistent_runtime, None)
    }

    #[cfg(test)]
    pub(super) fn resolved_routing_backend(&self) -> Option<ScanBackend> {
        self.resolved_routing_route().map(|route| route.backend)
    }

    /// Fastest-correct backend once a long-lived daemon has initialized its
    /// accelerator state. The persisted trials contain both the real first GPU
    /// dispatch and the warm trials; daemon routing uses only the warm interval,
    /// while one-shot routing conservatively includes cold cost.
    ///
    /// Exact confidence separation wins first. An exact warm peer-median tie
    /// resolves deterministically to the lower-complexity backend. Overlapping
    /// unequal measurements are inconclusive and produce no route.
    pub(super) fn resolved_persistent_route(&self) -> Option<MeasuredRoute> {
        self.resolve_class_route(true)
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
        let points: Vec<&AutorouteCalibrationPoint> = self.calibration_points.iter().collect();
        resolve_route_across_points(&points, persistent_runtime, Some(failed_backend))
    }

    /// True when evidence resolves one execution route. Exact paired timing
    /// selects a plan when measurable. If same-backend plans are indistinguishable,
    /// confidence-separated backend evidence selects the compiled default plan.
    pub(super) fn has_confidence_supported_route(&self) -> bool {
        self.resolved_routing_route()
            .is_some_and(|winner| self.selected_route_has_confidence_for(winner, false))
    }

    /// Persistent-daemon counterpart of [`Self::has_confidence_supported_route`],
    /// evaluated with warm accelerator evidence.
    pub(super) fn has_confidence_supported_persistent_route(&self) -> bool {
        self.resolved_persistent_route()
            .is_some_and(|winner| self.selected_route_has_confidence_for(winner, true))
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
        "{}+phase2-plain-localizer={}+phase2-keyword-localizer={}+gpu-pipeline-depth={}",
        route.backend.label(),
        route.phase2_plain_localizer,
        route.phase2_keyword_localizer,
        route.gpu_pipeline_depth,
    )
}
