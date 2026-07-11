//! Confirmed-pattern extraction for the postprocess tail.
//!
//! Confirmed extraction owns suffix gating, shared-anchor localization, and the
//! Stripe direct-prefix duplicate filter. It stays separate from decode
//! recursion and ML scoring so the postprocess folder has one owner per job.

use super::{scan_postprocess, scan_postprocess_profile, CompiledScanner};
use crate::types::{ScanState, ScannerPreprocessedText};
use keyhog_core::Chunk;
use std::sync::atomic::Ordering::Relaxed;

impl CompiledScanner {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn extract_confirmed_patterns(
        &self,
        confirmed_patterns: &[usize],
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
        confirmed_anchor_literal_matches: Option<&[(u32, u32)]>,
    ) {
        let prof = scan_postprocess_profile::confirmed_prof_enabled();
        let total = self.ac_map.len() + self.phase2_patterns.len();
        // Suffix gate: one AC pass marks which required-suffix literals are
        // present in the chunk; a triggered pattern whose suffix literals are
        // ALL absent cannot match (every match ends with one of them), so its
        // whole-chunk regex run is skipped. `None` when the gate is disabled or
        // no pattern is gateable.
        let needs_suffix_gate = self.tuning.confirmed_suffix_gate_enabled()
            && confirmed_patterns.iter().any(|&pat_idx| {
                let anchored = self
                    .confirmed_anchor_index
                    .as_ref()
                    .is_some_and(|anchor_index| anchor_index.is_eligible(pat_idx));
                self.ac_suffix_gate
                    .get(pat_idx)
                    .is_some_and(|gate| !gate.is_empty() && !anchored)
            });
        let suffix_present: Option<std::collections::HashSet<usize>> = match &self.suffix_gate_ac {
            Some(ac) if needs_suffix_gate => {
                let t0 = prof.then(std::time::Instant::now);
                let present = ac
                    .find_overlapping_iter(&*preprocessed.text)
                    .map(|m| m.pattern().as_usize())
                    .collect();
                if let Some(t0) = t0 {
                    scan_postprocess_profile::confirmed_prof_record(
                        scan_postprocess_profile::ConfirmedStage::SuffixGate,
                        t0.elapsed(),
                    );
                }
                Some(present)
            }
            _ => None,
        };
        let suffix_allows = |pat_idx: usize| -> bool {
            if let Some(present) = &suffix_present {
                if let Some(gate) = self.ac_suffix_gate.get(pat_idx) {
                    if !gate.is_empty() && !gate.iter().any(|id| present.contains(&(*id as usize)))
                    {
                        return false;
                    }
                }
            }
            true
        };
        let stripe_hot_offsets = self.stripe_direct_emitted_offsets(confirmed_patterns, scan_state);
        if let Some(anchor_index) = &self.confirmed_anchor_index {
            let has_active_anchored = confirmed_patterns
                .iter()
                .any(|&pat_idx| anchor_index.is_eligible(pat_idx) && suffix_allows(pat_idx));
            if has_active_anchored {
                scan_postprocess::confirmed_anchor::CONFIRMED_ANCHOR_CANDIDATES.with(|cell| {
                    let mut candidates = cell.borrow_mut();
                    let collect_t0 = prof.then(std::time::Instant::now);
                    let is_active = |pat_idx| {
                        confirmed_patterns.binary_search(&pat_idx).is_ok() && suffix_allows(pat_idx)
                    };
                    if let Some(literal_matches) = confirmed_anchor_literal_matches {
                        anchor_index.collect_candidates_from_literal_matches(
                            literal_matches,
                            is_active,
                            &mut candidates,
                        );
                    } else {
                        anchor_index.collect_candidates(
                            &preprocessed.text,
                            is_active,
                            &mut candidates,
                        );
                    }
                    if let Some(collect_t0) = collect_t0 {
                        scan_postprocess_profile::confirmed_prof_record(
                            scan_postprocess_profile::ConfirmedStage::AnchorCollect,
                            collect_t0.elapsed(),
                        );
                    }
                    let mut i = 0usize;
                    while i < candidates.len() {
                        if let Some(deadline) = deadline {
                            if std::time::Instant::now() > deadline {
                                break;
                            }
                        }
                        let pat_idx = candidates[i].0 as usize;
                        let mut j = i + 1;
                        while j < candidates.len() && candidates[j].0 as usize == pat_idx {
                            j += 1;
                        }
                        let group = &candidates[i..j];
                        if let Some(entry) = self.ac_map.get(pat_idx) {
                            let mut filtered_group = Vec::new();
                            let group = if self.is_stripe_hot_confirmed_pattern(pat_idx) {
                                if let Some(offsets) = stripe_hot_offsets.as_ref() {
                                    filtered_group.reserve(group.len());
                                    filtered_group.extend(group.iter().copied().filter(
                                        |&(_, pos)| {
                                            let absolute_offset =
                                                pos as usize + chunk.metadata.base_offset;
                                            !offsets.contains(&absolute_offset)
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
                                    line_offsets,
                                    code_lines,
                                    documentation_lines,
                                    chunk,
                                    scan_state,
                                    deadline,
                                ),
                                None => self.extract_matches(
                                    entry,
                                    preprocessed,
                                    line_offsets,
                                    code_lines,
                                    documentation_lines,
                                    chunk,
                                    scan_state,
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
        for &pat_idx in confirmed_patterns {
            if let Some(deadline) = deadline {
                if std::time::Instant::now() > deadline {
                    break;
                }
            }
            // Skip a gated ac_map pattern whose required suffix literal is absent.
            if !suffix_allows(pat_idx) {
                continue;
            }
            if self
                .confirmed_anchor_index
                .as_ref()
                .is_some_and(|anchor_index| anchor_index.is_eligible(pat_idx))
            {
                continue;
            }
            let entry = if pat_idx < self.ac_map.len() {
                &self.ac_map[pat_idx]
            } else {
                let phase2_idx = pat_idx - self.ac_map.len();
                if phase2_idx >= self.phase2_patterns.len() {
                    continue;
                }
                &self.phase2_patterns[phase2_idx].0
            };
            let t0 = if prof {
                Some(std::time::Instant::now())
            } else {
                None
            };
            self.extract_matches(
                entry,
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
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
    }

    fn stripe_direct_emitted_offsets(
        &self,
        confirmed_patterns: &[usize],
        scan_state: &ScanState,
    ) -> Option<std::collections::HashSet<usize>> {
        if !confirmed_patterns
            .iter()
            .any(|&pat_idx| self.is_stripe_hot_confirmed_pattern(pat_idx))
        {
            return None;
        }
        let offsets: std::collections::HashSet<usize> = scan_state
            .matches
            .iter()
            .filter(|m| m.detector_id.as_ref() == crate::detector_ids::STRIPE_SECRET_KEY)
            .map(|m| m.location.offset)
            .collect();
        (!offsets.is_empty()).then_some(offsets)
    }

    fn is_stripe_hot_confirmed_pattern(&self, pat_idx: usize) -> bool {
        match self.stripe_hot_confirmed_by_pattern.get(pat_idx) {
            Some(is_hot) => *is_hot,
            None => {
                panic!(
                    "internal invariant violation: missing Stripe hot-confirmed classification for pattern index {pat_idx}"
                );
            }
        }
    }
}
