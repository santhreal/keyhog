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

/// A calibrated routing decision for one workload bucket.
///
/// PRIMARY EVIDENCE ONLY: the persisted state is the measured timing evidence
/// (`simd_timing` / `cpu_timing` / `gpu_timing`) plus the resolved `backend`,
/// calibration sample, digest, timestamp, and trial count. Every value that is a
/// pure function of that evidence — per-backend best-ms (`simd_ms()`/…), the GPU
/// cold/warm/route triple (`gpu_cold_warm_route()`), and the selected-backend
/// margin (`selected_margin_ns()`) — is DERIVED on demand through the accessors
/// below rather than stored a second time. This is the ONE-PLACE invariant: a
/// cache can never hold a derived value inconsistent with its own evidence,
/// because there is no stored copy to drift — which is why the old
/// `validate_decision_route_evidence` cross-field-mismatch checks no longer exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct AutorouteDecision {
    pub(super) backend: String,
    pub(super) sample_bytes: u64,
    pub(super) sample_chunks: usize,
    pub(super) correctness_digest: u64,
    pub(super) calibrated_at_unix_ms: u128,
    pub(super) simd_timing: BackendTimingEvidence,
    pub(super) cpu_timing: Option<BackendTimingEvidence>,
    pub(super) gpu_timing: Option<BackendTimingEvidence>,
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
        Self {
            backend: backend.label().to_string(),
            sample_bytes,
            sample_chunks,
            correctness_digest: 0xA11D_0B57_A11D_0B57,
            calibrated_at_unix_ms: 1,
            simd_timing,
            cpu_timing,
            gpu_timing,
            trials: AUTOROUTE_CALIBRATION_TRIALS,
        }
    }

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
            gpu_timing,
            trials: AUTOROUTE_CALIBRATION_TRIALS,
        }
    }

    pub(super) fn backend(&self) -> Option<ScanBackend> {
        keyhog_scanner::hw_probe::parse_backend_str(&self.backend)
    }

    // ── Derived evidence accessors (see the struct doc: primary-evidence-only) ──
    // Each is a pure function of the persisted timing set, computed on demand so
    // no stored copy can drift. These replace the former denormalized fields.

    /// Best (fastest-trial) SIMD backend time in ms.
    pub(super) fn simd_ms(&self) -> u128 {
        self.simd_timing.best_ms()
    }

    /// Best CPU-fallback backend time in ms, if CPU was measured.
    pub(super) fn cpu_ms(&self) -> Option<u128> {
        self.cpu_timing.as_ref().map(BackendTimingEvidence::best_ms)
    }

    /// Best GPU backend time in ms, if GPU was measured.
    pub(super) fn gpu_ms(&self) -> Option<u128> {
        self.gpu_timing.as_ref().map(BackendTimingEvidence::best_ms)
    }

    /// The GPU cold-start ns, warm timing evidence, and routing ns — all derived
    /// from the persisted `gpu_timing` through the single owner
    /// [`gpu_cold_warm_route_evidence`]. `None` when there is no GPU timing or it
    /// cannot produce valid cold/warm evidence (too few warm trials).
    pub(super) fn gpu_cold_warm_route(&self) -> Option<(u128, BackendTimingEvidence, u128)> {
        self.gpu_timing
            .as_ref()
            .and_then(gpu_cold_warm_route_evidence)
    }

    /// GPU cold-start ns, derived (see [`Self::gpu_cold_warm_route`]).
    pub(super) fn gpu_cold_ns(&self) -> Option<u128> {
        self.gpu_cold_warm_route().map(|(cold_ns, _, _)| cold_ns)
    }

    /// GPU warm best-ms, derived.
    pub(super) fn gpu_warm_ms(&self) -> Option<u128> {
        self.gpu_cold_warm_route()
            .map(|(_, warm_timing, _)| warm_timing.best_ms())
    }

    /// GPU routing ns (the cold-vs-warm route cost the router compares), derived.
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

    pub(super) fn timing_for_backend(
        &self,
        backend: ScanBackend,
    ) -> Option<&BackendTimingEvidence> {
        match backend {
            ScanBackend::SimdCpu => Some(&self.simd_timing),
            ScanBackend::CpuFallback => self.cpu_timing.as_ref(),
            ScanBackend::Gpu => self.gpu_timing.as_ref(),
            _ => None,
        }
    }

    pub(super) fn route_candidates(&self) -> Vec<(ScanBackend, u128)> {
        route_candidates_with_gpu_backend(
            &self.simd_timing,
            self.cpu_timing.as_ref(),
            self.gpu_route_ns(),
            ScanBackend::Gpu,
        )
    }

    pub(super) fn selected_backend_has_non_overlapping_confidence(
        &self,
        selected: ScanBackend,
    ) -> bool {
        let intervals = self.route_confidence_intervals();
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
    /// timing evidence (canonical `Gpu` label — this calibration path only ever
    /// measures `Gpu`), so a cache that names any other backend is rejected as
    /// tampered or non-deterministic.
    ///
    /// Policy:
    /// - If one backend is provably fastest (its 95% CI lies entirely below
    ///   every competitor's), that backend wins — the strongest evidence.
    /// - Otherwise the empirically-fastest backend is statistically TIED with
    ///   one or more competitors within measurement precision. A tie is itself a
    ///   *proven* conclusion that the tied-fastest routes are equivalent, so the
    ///   lowest-overhead member of the tied-fastest set wins (SimdCpu before
    ///   CpuFallback before Gpu): when GPU only ties, its launch/transfer cost
    ///   buys nothing, so the CPU/SIMD path is the sound, not the guessed, route.
    pub(super) fn resolved_routing_backend(&self) -> Option<ScanBackend> {
        // Lowest-overhead member of the statistically-tied fastest set (SimdCpu <
        // CpuFallback < Gpu). An empty winner set means no timing evidence, so
        // `min_by_key` yields `None`, propagated to the caller as "no persisted
        // route" — never silently defaulted to a backend.
        self.fastest_winner_set(false)
            .into_iter()
            .min_by_key(|backend| backend_overhead_rank(*backend))
    }

    /// Fastest-correct backend once a long-lived daemon has initialized its
    /// accelerator state. The persisted trials contain both the real first GPU
    /// dispatch and the warm trials; daemon routing uses only the warm interval,
    /// while one-shot routing conservatively includes cold cost.
    pub(super) fn resolved_persistent_backend(&self) -> Option<ScanBackend> {
        self.fastest_winner_set(true)
            .into_iter()
            .min_by_key(|backend| backend_overhead_rank(*backend))
    }

    /// True iff exactly one route is provably fastest. Equivalently, the
    /// resolved winner is separated from every competitor — its 95% CI lies
    /// entirely below theirs. When false, two or more routes tie within
    /// measurement precision and routing falls to the lowest-overhead tie-break.
    pub(super) fn has_separated_fastest_route(&self) -> bool {
        self.resolved_routing_backend()
            .is_some_and(|winner| self.selected_backend_has_non_overlapping_confidence(winner))
    }

    /// The set of routes that are NOT provably beaten by any competitor — i.e.
    /// no other route's 95% CI lies entirely below this route's CI. Routing is
    /// decided from confidence intervals, never a single `best_ns` trial, so a
    /// lucky outlier on a noisy backend can never win over a steadily-faster one.
    ///
    /// - Exactly one member  → that route is provably fastest.
    /// - Two or more members → they are mutually non-separated (a tie); the
    ///   lowest-overhead member is the sound route.
    fn fastest_winner_set(&self, persistent_runtime: bool) -> Vec<ScanBackend> {
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

    fn route_confidence_intervals(&self) -> Vec<(ScanBackend, TimingConfidenceInterval)> {
        self.route_confidence_intervals_for(false)
    }

    fn route_confidence_intervals_for(
        &self,
        persistent_runtime: bool,
    ) -> Vec<(ScanBackend, TimingConfidenceInterval)> {
        let mut intervals = vec![(
            ScanBackend::SimdCpu,
            self.simd_timing.confidence_interval_95_ns,
        )];
        if let Some(cpu_timing) = self.cpu_timing.as_ref() {
            intervals.push((
                ScanBackend::CpuFallback,
                cpu_timing.confidence_interval_95_ns,
            ));
        }
        if let Some((cold_ns, warm_timing, _route_ns)) = self.gpu_cold_warm_route() {
            let warm_interval = warm_timing.confidence_interval_95_ns;
            intervals.push((
                ScanBackend::Gpu,
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
        intervals
    }
}

fn route_candidates_with_gpu_backend(
    simd_timing: &BackendTimingEvidence,
    cpu_timing: Option<&BackendTimingEvidence>,
    gpu_route_ns: Option<u128>,
    gpu_backend: ScanBackend,
) -> Vec<(ScanBackend, u128)> {
    let mut candidates = vec![(ScanBackend::SimdCpu, simd_timing.best_ns)];
    if let Some(cpu_timing) = cpu_timing {
        candidates.push((ScanBackend::CpuFallback, cpu_timing.best_ns));
    }
    if let Some(gpu_route_ns) = gpu_route_ns {
        candidates.push((gpu_backend, gpu_route_ns));
    }
    candidates
}

/// Engagement-overhead rank used to break a statistical tie: lower wins. A tie
/// means the routes are equally fast within measurement precision, so the
/// cheapest-to-engage route is the sound choice — SimdCpu (reference, always
/// available, no GPU launch/transfer) before CpuFallback before any GPU route.
fn backend_overhead_rank(backend: ScanBackend) -> u8 {
    match backend {
        ScanBackend::SimdCpu => 0,
        ScanBackend::CpuFallback => 1,
        ScanBackend::Gpu => 2,
        _ => 3,
    }
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
        let trials_ns = vec![ms.saturating_mul(1_000_000); trials.max(1)];
        match Self::from_trial_ns(trials_ns) {
            Some(evidence) => evidence,
            // `trials.max(1) >= 1` makes the trial set non-empty, so
            // `from_trial_ns` (which only returns `None` for an empty set)
            // cannot fail here.
            None => unreachable!("a non-empty trial set always yields timing evidence"),
        }
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
        if self.trials_ns.len() < min_trials || self.trials_ns.iter().any(|&trial| trial == 0) {
            return false;
        }
        match Self::from_trial_ns(self.trials_ns.clone()) {
            Some(expected) => self == &expected,
            None => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
        let half_width =
            two_sided_95_student_t_critical(trials_ns.len()) * variance.sqrt() / count.sqrt();
        Self {
            low_ns: (mean - half_width).max(0.0).floor() as u128,
            high_ns: (mean + half_width).ceil() as u128,
        }
    }
}

fn two_sided_95_student_t_critical(sample_count: usize) -> f64 {
    match sample_count {
        0 | 1 => 0.0,
        2 => 12.706_204_736,
        3 => 4.302_652_73,
        4 => 3.182_446_305,
        5 => 2.776_445_105,
        6 => 2.570_581_836,
        7 => 2.446_911_851,
        8 => 2.364_624_252,
        9 => 2.306_004_135,
        10 => 2.262_157_163,
        11 => 2.228_138_852,
        12 => 2.200_985_16,
        13 => 2.178_812_83,
        14 => 2.160_368_656,
        15 => 2.144_786_688,
        16 => 2.131_449_546,
        17 => 2.119_905_299,
        18 => 2.109_815_578,
        19 => 2.100_922_04,
        20 => 2.093_024_054,
        21 => 2.085_963_447,
        22 => 2.079_613_845,
        23 => 2.073_873_068,
        24 => 2.068_657_61,
        25 => 2.063_898_562,
        26 => 2.059_538_553,
        27 => 2.055_529_439,
        28 => 2.051_830_516,
        29 => 2.048_407_142,
        30 => 2.045_229_642,
        31 => 2.042_272_456,
        // For larger future trial counts, keep the interval conservative
        // instead of silently reverting to the narrower normal 1.96 multiplier.
        _ => 2.042_272_456,
    }
}

pub(super) type CanonicalMatch<'a> = (
    usize,
    &'a str,
    keyhog_core::CredentialHash,
    Option<&'a str>,
    Option<usize>,
    usize,
);

pub(super) fn canonical_matches(matches: &[Vec<RawMatch>]) -> Vec<CanonicalMatch<'_>> {
    let mut out = Vec::with_capacity(canonical_match_count(matches));
    for (chunk_idx, chunk_matches) in matches.iter().enumerate() {
        for m in chunk_matches {
            out.push(canonical_match(chunk_idx, m));
        }
    }
    out.sort_unstable();
    out
}

pub(super) fn canonical_matches_equal_reference(
    matches: &[Vec<RawMatch>],
    reference: &[CanonicalMatch<'_>],
) -> bool {
    let match_count = canonical_match_count(matches);
    if match_count != reference.len() {
        return false;
    }
    if match_count == 0 {
        return true;
    }
    if match_count > 256 {
        return canonical_matches(matches) == reference;
    }

    let mut matched = [false; 256];
    for (chunk_idx, chunk_matches) in matches.iter().enumerate() {
        for m in chunk_matches {
            let canonical = canonical_match(chunk_idx, m);
            let Ok(mut idx) = reference.binary_search(&canonical) else {
                return false;
            };
            while idx > 0 && reference[idx - 1] == canonical {
                idx -= 1;
            }
            while idx < reference.len() && reference[idx] == canonical {
                if !matched[idx] {
                    matched[idx] = true;
                    break;
                }
                idx += 1;
            }
            if idx == reference.len() || reference[idx] != canonical {
                return false;
            }
        }
    }
    true
}

fn canonical_match_count(matches: &[Vec<RawMatch>]) -> usize {
    matches.iter().map(Vec::len).sum()
}

fn canonical_match(chunk_idx: usize, m: &RawMatch) -> CanonicalMatch<'_> {
    (
        chunk_idx,
        m.detector_id.as_ref(),
        m.credential_hash,
        m.location.file_path.as_deref(),
        m.location.line,
        m.location.offset,
    )
}

/// Render one canonical match identity for the reference-mismatch diff log.
/// Derived from [`canonical_match`] — the ONE owner of which fields make up a
/// match's calibration identity — so the diff that *explains* an equality
/// failure can never disagree with the equality itself about what was compared.
pub(super) fn render_canonical_match(
    (chunk_idx, detector_id, credential_hash, file_path, line, offset): &CanonicalMatch<'_>,
) -> String {
    let credential_hash_hex: String = credential_hash
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!(
        "chunk={chunk_idx} detector={detector_id} cred_hash={credential_hash_hex} \
         file={file_path:?} line={line:?} offset={offset}"
    )
}

pub(super) fn canonical_match_digest(matches: &[CanonicalMatch<'_>]) -> u64 {
    let mut h = crate::stable_hash::StableHasher::new("autoroute-correctness-digest");
    h.field_usize("matches.len", matches.len());
    for (chunk_idx, detector_id, credential_hash, file_path, line, offset) in matches {
        h.field_usize("match.chunk_idx", *chunk_idx);
        h.field_str("match.detector_id", detector_id);
        h.field_bytes("match.credential_hash", credential_hash.as_bytes());
        h.field_option_str("match.file_path", *file_path);
        h.field_option_usize("match.line", *line);
        h.field_usize("match.offset", *offset);
    }
    h.finish_u64()
}
