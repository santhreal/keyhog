//! Shared-anchor localization for the confirmed pass.
//!
//! Confirmed patterns are already gated by phase-1 literal presence, but the
//! old path still ran every triggered pattern's full regex over the whole scan
//! window. For patterns whose regex has a finite required prefix, one shared
//! Aho-Corasick pass can collect candidate start positions and then verify each
//! candidate with the same anchored regex machinery used by phase-2. Patterns
//! without a proven prefix keep the whole-chunk path.
//!
//! When only a handful of eligible patterns are active on a chunk, searching
//! those patterns' required-prefix literals directly is cheaper than running
//! the full shared automaton (measured: anchor-collect dominated confirmed
//! time on large inert files that triggered only two patterns).

use super::super::phase2_anchor::{
    required_prefix_literals_with_cap, CONFIRMED_MAX_LITERALS_PER_PATTERN,
};
use super::super::phase2_first_bigram::FirstBigramSet;
use super::super::CompiledScanner;
use crate::anchored_regex::AnchoredRegex;
use crate::types::CompiledPattern;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind, MatchKind};
use std::sync::OnceLock;

/// Sparse collect is only cheaper when the active needle set is tiny. Gate on
/// unique required-prefix literals (not patterns): each literal is one full
/// haystack walk, and a pattern may carry up to
/// `CONFIRMED_MAX_LITERALS_PER_PATTERN` of them.
const SPARSE_ACTIVE_LITERAL_MAX: usize = 8;

impl CompiledScanner {
    #[cfg(test)]
    pub(crate) fn disable_confirmed_anchor_for_test(&mut self) {
        self.confirmed_anchor_index = None;
    }

    #[cfg(test)]
    pub(crate) fn confirmed_anchor_eligible_count_for_test(&self) -> usize {
        self.confirmed_anchor_index
            .as_ref()
            .map_or(0, ConfirmedAnchorIndex::eligible_count)
    }

    #[cfg(test)]
    pub(crate) fn confirmed_anchor_kind_for_test(&self) -> Option<AhoCorasickKind> {
        self.confirmed_anchor_index
            .as_ref()
            .map(ConfirmedAnchorIndex::anchor_kind)
    }
}

pub(crate) struct ConfirmedAnchorIndex {
    anchor_ac: OnceLock<AhoCorasick>,
    anchor_first_bigram: FirstBigramSet,
    anchor_literals: Box<[String]>,
    literal_patterns: super::super::CsrU32,
    /// Reverse of `literal_patterns`: per confirmed pattern, the shared-anchor
    /// literal ids that localize it. Drives the sparse active-set collect path.
    pattern_literals: super::super::CsrU32,
    eligible: Box<[bool]>,
    anchored: Box<[Option<AnchoredRegex>]>,
    eligible_count: usize,
}

impl ConfirmedAnchorIndex {
    pub(crate) fn build(ac_map: &[CompiledPattern]) -> Option<Self> {
        Self::build_with_hints(ac_map, None)
    }

    pub(crate) fn build_with_hints(
        ac_map: &[CompiledPattern],
        localization_hints: Option<Vec<Option<Vec<String>>>>,
    ) -> Option<Self> {
        if localization_hints.is_none() {
            crate::execution_pack::matcher_sections::record_runtime_localization_hint_fallback();
        }
        let mut localization_hints = localization_hints.map(Vec::into_iter);
        let mut literal_ids: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut literals: Vec<String> = Vec::new();
        let mut literal_pattern_pairs = Vec::new();
        let mut pattern_literal_pairs = Vec::new();
        let mut eligible = vec![false; ac_map.len()];
        let mut anchored: Vec<Option<AnchoredRegex>> = (0..ac_map.len()).map(|_| None).collect();

        for (idx, pattern) in ac_map.iter().enumerate() {
            let pattern_literals = match localization_hints.as_mut() {
                // LAW10: authenticated hint cardinality drift is a loud build-invariant panic.
                Some(hints) => hints.next().unwrap_or_else(|| {
                    panic!(
                        "BUILD-INVARIANT VIOLATION: confirmed localization hint cardinality is shorter than the compiled pattern set"
                    )
                }),
                None => required_prefix_literals_with_cap(
                    pattern.regex.as_str(),
                    CONFIRMED_MAX_LITERALS_PER_PATTERN,
                ),
            };
            let Some(pattern_literals) = pattern_literals else {
                continue;
            };
            let ci = pattern.regex.is_case_insensitive();
            for lit in &pattern_literals {
                let id = super::register_literal(&mut literals, &mut literal_ids, lit);
                literal_pattern_pairs.push((id, idx));
                pattern_literal_pairs.push((idx, id));
            }
            eligible[idx] = true;
            anchored[idx] = Some(AnchoredRegex::new(pattern.regex.as_str(), ci));
        }

        let literal_patterns =
            super::super::CsrU32::from_pairs(literals.len(), literal_pattern_pairs);
        let pattern_literals =
            super::super::CsrU32::from_pairs(ac_map.len(), pattern_literal_pairs);

        let eligible_count = eligible.iter().filter(|&&value| value).count();
        if eligible_count == 0 {
            return None;
        }

        let anchor_first_bigram =
            FirstBigramSet::from_literals(literals.iter().map(String::as_bytes), true);

        let anchor_ac = OnceLock::new();

        Some(Self {
            anchor_ac,
            anchor_first_bigram,
            anchor_literals: literals.into_boxed_slice(),
            literal_patterns,
            pattern_literals,
            eligible: eligible.into_boxed_slice(),
            anchored: anchored.into_boxed_slice(),
            eligible_count,
        })
    }

    pub(crate) fn eligible_count(&self) -> usize {
        self.eligible_count
    }

    pub(crate) fn anchor_literals(&self) -> &[String] {
        &self.anchor_literals
    }
    pub(crate) fn materialize(&self) -> bool {
        let already_initialized = self.anchor_ac.get().is_some();
        self.anchor();
        !already_initialized
    }

    fn anchor(&self) -> &AhoCorasick {
        self.anchor_ac.get_or_init(|| {
            AhoCorasickBuilder::new()
                .match_kind(MatchKind::Standard)
                .kind(Some(AhoCorasickKind::ContiguousNFA))
                .ascii_case_insensitive(true)
                .build(&self.anchor_literals)
                // LAW10: automaton compilation failure is a loud build-invariant panic, never a weaker scan path.
                .unwrap_or_else(|error| {
                    panic!(
                        "BUILD-INVARIANT VIOLATION: confirmed shared-anchor Aho-Corasick failed to compile: {error}"
                    )
                })
        })
    }

    #[cfg(test)]
    pub(crate) fn anchor_kind(&self) -> AhoCorasickKind {
        self.anchor().kind()
    }

    #[inline]
    pub(crate) fn is_eligible(&self, ac_idx: usize) -> bool {
        matches!(self.eligible.get(ac_idx), Some(true))
    }

    pub(crate) fn anchored_regex(&self, ac_idx: usize) -> Option<&AnchoredRegex> {
        let anchored = self.anchored.get(ac_idx)?.as_ref()?;
        // The slot's presence IS eligibility; `AnchoredRegex::get()` is now
        // fail-closed (compiles-or-panics, never None), so no compile pre-check.
        Some(anchored)
    }

    /// Collect `(pattern, start)` candidates for the active confirmed set.
    ///
    /// `active_patterns` is the chunk's confirmed trigger list (ac_map indices).
    /// `is_active` applies any extra gate (suffix presence). When few eligible
    /// patterns survive, their required-prefix literals are searched directly;
    /// otherwise the shared automaton runs. Both paths emit the same
    /// `(pattern, start)` set for a given active mask.
    pub(crate) fn collect_candidates(
        &self,
        text: &str,
        active_patterns: &[usize],
        is_active: impl Fn(usize) -> bool,
        out: &mut Vec<(u32, u32)>,
        sparse: &mut Vec<usize>,
        sparse_literal_ids: &mut Vec<u32>,
    ) {
        out.clear();
        sparse.clear();
        sparse_literal_ids.clear();
        for &pat_idx in active_patterns {
            if !(self.is_eligible(pat_idx) && is_active(pat_idx)) {
                continue;
            }
            sparse.push(pat_idx);
            if let Some(literal_ids) = self.pattern_literals.get(pat_idx) {
                for &literal_id in literal_ids {
                    sparse_literal_ids.push(literal_id);
                }
            }
        }
        if sparse.is_empty() {
            return;
        }
        // Shared bigram reject applies to both collect paths.
        if !self.anchor_first_bigram.may_have_match(text) {
            return;
        }
        sparse_literal_ids.sort_unstable();
        sparse_literal_ids.dedup();
        if sparse_literal_ids.len() <= SPARSE_ACTIVE_LITERAL_MAX {
            self.collect_candidates_sparse(text, &sparse, &sparse_literal_ids, out);
            return;
        }
        for mat in self.anchor().find_overlapping_iter(text) {
            let literal_idx = mat.pattern().as_usize();
            let pos = mat.start() as u32;
            if let Some(patterns) = self.literal_patterns.get(literal_idx) {
                for &pattern in patterns {
                    let pattern = pattern as usize;
                    if is_active(pattern) {
                        out.push((pattern as u32, pos));
                    }
                }
            }
        }
        out.sort_unstable();
        out.dedup();
    }

    fn collect_candidates_sparse(
        &self,
        text: &str,
        active_eligible: &[usize],
        unique_literal_ids: &[u32],
        out: &mut Vec<(u32, u32)>,
    ) {
        let haystack = text.as_bytes();
        // Search each unique literal once, then fan out to active eligible owners.
        for &literal_id in unique_literal_ids {
            let Some(literal) = self.anchor_literals.get(literal_id as usize) else {
                continue;
            };
            let Some(owners) = self.literal_patterns.get(literal_id as usize) else {
                continue;
            };
            for pos in crate::ascii_ci::ci_find_iter(haystack, literal.as_bytes()) {
                for &pattern in owners {
                    let pattern = pattern as usize;
                    if active_eligible.contains(&pattern) {
                        out.push((pattern as u32, pos as u32));
                    }
                }
            }
        }
        out.sort_unstable();
        out.dedup();
    }

    pub(crate) fn collect_candidates_from_literal_matches(
        &self,
        literal_matches: &[(u32, u32)],
        is_active: impl Fn(usize) -> bool,
        out: &mut Vec<(u32, u32)>,
    ) {
        out.clear();
        for &(literal_idx, pos) in literal_matches {
            if let Some(patterns) = self.literal_patterns.get(literal_idx as usize) {
                for &pattern in patterns {
                    let pattern = pattern as usize;
                    if is_active(pattern) {
                        out.push((pattern as u32, pos));
                    }
                }
            }
        }
        out.sort_unstable();
        out.dedup();
    }
}
