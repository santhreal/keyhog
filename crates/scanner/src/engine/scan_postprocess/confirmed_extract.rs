//! Confirmed-pattern extraction for the postprocess tail.
//!
//! Confirmed extraction owns suffix gating, shared-anchor localization, and the
//! direct-prefix duplicate filter. It stays separate from decode
//! recursion and ML scoring so the postprocess folder has one owner per job.

use super::{absolute_offset, scan_postprocess_profile, CompiledScanner};
use crate::types::{ScanState, ScannerPreprocessedText};
use keyhog_core::Chunk;
use std::cell::RefCell;
use std::sync::atomic::Ordering::Relaxed;

thread_local! {
    /// Per-worker scratch for [`CompiledScanner::extract_confirmed_patterns`],
    /// reused across every chunk the worker handles so the confirmed pass makes
    /// no per-chunk heap allocation for either of its two lookup structures.
    static CONFIRMED_SCRATCH: RefCell<ConfirmedScratch> =
        RefCell::new(ConfirmedScratch::default());
}

/// Two dense bitsets the confirmed pass probes once per candidate.
///
/// They replace a per-chunk `HashSet<usize>` (suffix-literal presence) and a
/// `binary_search` over `confirmed_patterns` (active-pattern membership). Both
/// describe exactly the same sets as the structures they replace, so the set of
/// patterns admitted to extraction is unchanged; only allocation and probe cost
/// differ.
#[derive(Default)]
struct ConfirmedScratch {
    /// One bit per `ac_map` index, set when that pattern is in this chunk's
    /// `confirmed_patterns` slice.
    active: Vec<u64>,
    /// One bit per `suffix_gate_ac` literal id, set when that literal occurs in
    /// this chunk.
    suffix: Vec<u64>,
    /// One bit per `ac_map` index, set when the companion gate still allows the
    /// pattern. Replaces a per-chunk `vec![true; ac_map.len()]`.
    companion: Vec<u64>,
}

impl ConfirmedScratch {
    /// Rebuild the active-pattern bitset for one chunk. `clear` + `resize`
    /// zeroes in place and keeps the capacity from the previous chunk.
    fn load_active(&mut self, pattern_count: usize, confirmed_patterns: &[usize]) {
        let words = crate::engine::trigger_bitmap::words_for(pattern_count);
        self.active.clear();
        self.active.resize(words, 0);
        for &pat_idx in confirmed_patterns {
            if let Some(slot) = self.active.get_mut(pat_idx / 64) {
                *slot |= 1u64 << (pat_idx % 64);
            }
        }
    }

    #[inline]
    fn contains_active(&self, pat_idx: usize) -> bool {
        self.active
            .get(pat_idx / 64)
            .is_some_and(|word| word & (1u64 << (pat_idx % 64)) != 0)
    }

    fn clear_suffix(&mut self, literal_count: usize) {
        let words = crate::engine::trigger_bitmap::words_for(literal_count);
        self.suffix.clear();
        self.suffix.resize(words, 0);
    }

    #[inline]
    fn mark_suffix(&mut self, literal_id: usize) {
        if let Some(slot) = self.suffix.get_mut(literal_id / 64) {
            *slot |= 1u64 << (literal_id % 64);
        }
    }

    #[inline]
    fn contains_suffix(&self, literal_id: usize) -> bool {
        self.suffix
            .get(literal_id / 64)
            .is_some_and(|word| word & (1u64 << (literal_id % 64)) != 0)
    }

    /// Allow every pattern (companion fail-open default), then denials clear bits.
    fn reset_companion_allow_all(&mut self, pattern_count: usize) {
        let words = crate::engine::trigger_bitmap::words_for(pattern_count);
        self.companion.clear();
        self.companion.resize(words, u64::MAX);
    }

    #[inline]
    fn deny_companion(&mut self, pat_idx: usize) {
        if let Some(slot) = self.companion.get_mut(pat_idx / 64) {
            *slot &= !(1u64 << (pat_idx % 64));
        }
    }

    #[inline]
    fn companion_allows(&self, pat_idx: usize) -> bool {
        self.companion
            .get(pat_idx / 64)
            .is_some_and(|word| word & (1u64 << (pat_idx % 64)) != 0)
    }
}

impl CompiledScanner {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn extract_confirmed_patterns(
        &self,
        confirmed_patterns: &[usize],
        preprocessed: &ScannerPreprocessedText<'_>,
        line_index: &crate::context::LineContextIndex,
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
        confirmed_anchor_literal_matches: Option<&[(u32, u32)]>,
    ) {
        let prof = scan_postprocess_profile::confirmed_prof_enabled();
        let total = self.ac_map.len() + self.phase2_patterns.len();
        // Borrow this worker's scratch bitsets for the whole pass; they go back
        // to the pool at the end so the next chunk reuses the same allocation.
        let mut scratch_owned = CONFIRMED_SCRATCH.with(|cell| cell.take());
        scratch_owned.load_active(self.ac_map.len(), confirmed_patterns);
        // Suffix gate: one AC pass marks which required-suffix literals are
        // present in the chunk; a triggered pattern whose suffix literals are
        // ALL absent cannot match (every match ends with one of them), so its
        // whole-chunk regex run is skipped. `None` when the gate is disabled or
        // no pattern is gateable.
        let needs_suffix_gate = self.tuning.confirmed_suffix_gate_enabled()
            && confirmed_patterns.iter().any(|&pat_idx| {
                self.ac_suffix_gate
                    .get(pat_idx)
                    .is_some_and(|gate| !gate.is_empty())
            });
        let suffix_gate_active = if needs_suffix_gate {
            match self
                .suffix_gate_ac
                .as_ref()
                .and_then(super::scan_postprocess_suffix_gate::LazyConfirmedSuffixGate::get)
            {
                Some(ac) => {
                    let t0 = prof.then(std::time::Instant::now);
                    scratch_owned.clear_suffix(ac.patterns_len());
                    for mat in ac.find_overlapping_iter(&*preprocessed.text) {
                        scratch_owned.mark_suffix(mat.pattern().as_usize());
                    }
                    if let Some(t0) = t0 {
                        scan_postprocess_profile::confirmed_prof_record(
                            scan_postprocess_profile::ConfirmedStage::SuffixGate,
                            t0.elapsed(),
                        );
                    }
                    true
                }
                None => false,
            }
        } else {
            false
        };
        // Companion gate: skip patterns whose required mid-literals are all
        // absent (short phase-1 triggers like "123"/"ip" on inert padding).
        let companion_t0 = prof.then(std::time::Instant::now);
        scratch_owned.reset_companion_allow_all(self.ac_map.len());
        let companion_patterns: Vec<(usize, &str)> = confirmed_patterns
            .iter()
            .filter_map(|&pat_idx| {
                self.ac_map
                    .get(pat_idx)
                    .map(|entry| (pat_idx, entry.regex.as_str()))
            })
            .collect();
        super::scan_postprocess_companion_gate::companions_deny_absent(
            self.detector_digest,
            &companion_patterns,
            &preprocessed.text,
            |pat_idx| scratch_owned.deny_companion(pat_idx),
        );
        if let Some(companion_t0) = companion_t0 {
            scan_postprocess_profile::confirmed_prof_record(
                scan_postprocess_profile::ConfirmedStage::CompanionGate,
                companion_t0.elapsed(),
            );
        }
        // Freeze the scratch for the rest of the pass: every use below is a
        // read, so the closures share one immutable borrow.
        let scratch = &scratch_owned;
        let pattern_allows = |pat_idx: usize| -> bool {
            if !scratch.companion_allows(pat_idx) {
                return false;
            }
            if !suffix_gate_active {
                return true;
            }
            match self.ac_suffix_gate.get(pat_idx) {
                Some(gate) if !gate.is_empty() => {
                    gate.iter().any(|id| scratch.contains_suffix(*id as usize))
                }
                _ => true,
            }
        };
        let hot_direct_offsets = self.hot_direct_emitted_offsets(confirmed_patterns, scan_state);
        if let Some(anchor_index) = &self.confirmed_anchor_index {
            let has_active_anchored = confirmed_patterns
                .iter()
                .any(|&pat_idx| anchor_index.is_eligible(pat_idx) && pattern_allows(pat_idx));
            if has_active_anchored {
                super::with_candidate_scratch(|candidates| {
                    let collect_t0 = prof.then(std::time::Instant::now);
                    // `confirmed_patterns` is the set bits of this chunk's
                    // trigger bitmap, so membership is one word load instead of
                    // the binary search this probe used to run for every
                    // (literal hit x pattern sharing that literal).
                    let is_active =
                        |pat_idx: usize| scratch.contains_active(pat_idx) && pattern_allows(pat_idx);
                    if let Some(literal_matches) = confirmed_anchor_literal_matches {
                        anchor_index.collect_candidates_from_literal_matches(
                            literal_matches,
                            is_active,
                            candidates,
                        );
                    } else {
                        anchor_index.collect_candidates(
                            &preprocessed.text,
                            confirmed_patterns,
                            is_active,
                            candidates,
                        );
                    }
                    if let Some(collect_t0) = collect_t0 {
                        scan_postprocess_profile::confirmed_prof_record(
                            scan_postprocess_profile::ConfirmedStage::AnchorCollect,
                            collect_t0.elapsed(),
                        );
                    }
                    let mut i = 0usize;
                    let mut deadline_tick = 0usize;
                    while i < candidates.len() {
                        if crate::deadline::expired_on_cadence(
                            deadline,
                            deadline_tick,
                            crate::deadline::HOT_LOOP_DEADLINE_CADENCE,
                        ) {
                            break;
                        }
                        deadline_tick += 1;
                        let pat_idx = candidates[i].0 as usize;
                        let mut j = i + 1;
                        while j < candidates.len() && candidates[j].0 as usize == pat_idx {
                            j += 1;
                        }
                        let group = &candidates[i..j];
                        if let Some(entry) = self.ac_map.get(pat_idx) {
                            let mut filtered_group = Vec::new();
                            let group = if self.is_hot_confirmed_pattern(pat_idx) {
                                if let Some(offsets) = hot_direct_offsets.as_ref() {
                                    let detector_index = entry.detector_index;
                                    filtered_group.reserve(group.len());
                                    filtered_group.extend(group.iter().copied().filter(
                                        |&(_, pos)| {
                                            // Overflow (impossible on real input) can't collide
                                            // with an already-emitted hot offset: keep it.
                                            absolute_offset(
                                                chunk.metadata.base_offset,
                                                pos as usize,
                                            )
                                            .map_or(true, |ao| {
                                                !offsets.contains(&(detector_index, ao))
                                            })
                                        },
                                    ));
                                    if filtered_group.is_empty() {
                                        i = j;
                                        continue;
                                    }
                                    filtered_group.as_slice()
                                } else {
                                    group
                                }
                            } else {
                                group
                            };
                            let t0 = if prof {
                                Some(std::time::Instant::now())
                            } else {
                                None
                            };
                            match anchor_index.anchored_regex(pat_idx) {
                                Some(re) => self.extract_anchored(
                                    entry,
                                    re,
                                    group,
                                    preprocessed,
                                    line_index,
                                    chunk,
                                    scan_state,
                                    deadline,
                                ),
                                None => self.extract_matches_inner(
                                    entry,
                                    preprocessed,
                                    line_index,
                                    chunk,
                                    scan_state,
                                    None,
                                    deadline,
                                ),
                            }
                            if let Some(t0) = t0 {
                                let elapsed = t0.elapsed();
                                scan_postprocess_profile::confirmed_prof_record(
                                    scan_postprocess_profile::ConfirmedStage::Extract,
                                    elapsed,
                                );
                                let (ns, runs) =
                                    scan_postprocess_profile::confirmed_prof_vecs(total);
                                if let (Some(n), Some(r)) = (ns.get(pat_idx), runs.get(pat_idx)) {
                                    n.fetch_add(elapsed.as_nanos() as u64, Relaxed);
                                    r.fetch_add(1, Relaxed);
                                }
                            }
                        }
                        i = j;
                    }
                });
            }
        }
        for (deadline_tick, &pat_idx) in confirmed_patterns.iter().enumerate() {
            if crate::deadline::expired_on_cadence(
                deadline,
                deadline_tick,
                crate::deadline::HOT_LOOP_DEADLINE_CADENCE,
            ) {
                break;
            }
            // Skip a gated ac_map pattern whose required suffix literal is absent.
            if !pattern_allows(pat_idx) {
                continue;
            }
            if self
                .confirmed_anchor_index
                .as_ref()
                .is_some_and(|anchor_index| anchor_index.is_eligible(pat_idx))
            {
                continue;
            }
            // `confirmed_patterns` is ac_map-only: every production caller
            // filters `idx < ac_map.len()` (backend_triggered.rs). This bound is
            // load-bearing: `is_hot_confirmed_pattern` and
            // `hot_confirmed_by_pattern` are index-parallel to `ac_map`
            // and panic on any phase-2 index. Assert the contract; fail closed
            // (skip) in release rather than index out of bounds.
            debug_assert!(
            pat_idx < self.ac_map.len(),
            "extract_confirmed_patterns got phase-2 index {pat_idx} (ac_map len {}); callers must filter to ac_map-only",
            self.ac_map.len()
        );
            let Some(entry) = self.ac_map.get(pat_idx) else {
                continue;
            };
            let t0 = if prof {
                Some(std::time::Instant::now())
            } else {
                None
            };
            self.extract_matches_inner(
                entry,
                preprocessed,
                line_index,
                chunk,
                scan_state,
                None,
                deadline,
            );
            if let Some(t0) = t0 {
                let elapsed = t0.elapsed();
                scan_postprocess_profile::confirmed_prof_record(
                    scan_postprocess_profile::ConfirmedStage::Extract,
                    elapsed,
                );
                let (ns, runs) = scan_postprocess_profile::confirmed_prof_vecs(total);
                if let (Some(n), Some(r)) = (ns.get(pat_idx), runs.get(pat_idx)) {
                    n.fetch_add(elapsed.as_nanos() as u64, Relaxed);
                    r.fetch_add(1, Relaxed);
                }
            }
        }
        CONFIRMED_SCRATCH.with(|cell| cell.replace(scratch_owned));
    }

    fn hot_direct_emitted_offsets(
        &self,
        confirmed_patterns: &[usize],
        scan_state: &ScanState,
    ) -> Option<std::collections::HashSet<(usize, usize)>> {
        // The map below hashes one detector-id string per hot triggered
        // pattern, and the walk that follows can only find an offset if some
        // earlier lane already produced a match. On a chunk where nothing was
        // produced (the overwhelming majority) the result is provably `None`,
        // so settle that before paying for the map.
        let mut produced_any = false;
        scan_state.for_each_produced_match(|_| produced_any = true);
        if !produced_any {
            return None;
        }
        let detector_by_id: std::collections::HashMap<&str, usize> = confirmed_patterns
            .iter()
            .filter_map(|&pat_idx| {
                if !self.is_hot_confirmed_pattern(pat_idx) {
                    return None;
                }
                self.ac_map.get(pat_idx).map(|entry| entry.detector_index)
            })
            .map(|detector_index| {
                let plan = self.detector_plans.get(detector_index);
                (plan.metadata.0.as_ref(), detector_index)
            })
            .collect();
        if detector_by_id.is_empty() {
            return None;
        }
        let mut offsets = std::collections::HashSet::new();
        scan_state.for_each_produced_match(|produced| {
            if let Some(&detector_index) = detector_by_id.get(produced.detector_id) {
                offsets.insert((detector_index, produced.offset));
            }
        });
        (!offsets.is_empty()).then_some(offsets)
    }

    fn is_hot_confirmed_pattern(&self, pat_idx: usize) -> bool {
        match self.hot_confirmed_by_pattern.get(pat_idx) {
            Some(is_hot) => *is_hot,
            None => {
                panic!(
                    "internal invariant violation: missing hot-confirmed detector classification for pattern index {pat_idx}"
                );
            }
        }
    }
}
