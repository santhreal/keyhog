//! Shared-anchor localization for the confirmed pass.
//!
//! Confirmed patterns are already gated by phase-1 literal presence, but the
//! old path still ran every triggered pattern's full regex over the whole scan
//! window. For patterns whose regex has a finite required prefix, one shared
//! Aho-Corasick pass can collect candidate start positions and then verify each
//! candidate with the same anchored regex machinery used by phase-2. Patterns
//! without a proven prefix keep the whole-chunk path.

use super::super::phase2_anchor::{
    required_prefix_literals_with_cap, CONFIRMED_MAX_LITERALS_PER_PATTERN,
};
use super::super::phase2_first_bigram::FirstBigramSet;
use super::super::CompiledScanner;
use crate::anchored_regex::AnchoredRegex;
use crate::types::CompiledPattern;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind, MatchKind};
use std::sync::OnceLock;

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
    anchor_literals: Vec<String>,
    literal_patterns: super::super::CsrU32,
    eligible: Vec<bool>,
    anchored: Vec<Option<AnchoredRegex>>,
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
                let id = *literal_ids.entry(lit.clone()).or_insert_with(|| {
                    literals.push(lit.clone());
                    literals.len() - 1
                });
                literal_pattern_pairs.push((id, idx));
            }
            eligible[idx] = true;
            anchored[idx] = Some(AnchoredRegex::new(pattern.regex.as_str(), ci));
        }

        let literal_patterns =
            super::super::CsrU32::from_pairs(literals.len(), literal_pattern_pairs);

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
            anchor_literals: literals,
            literal_patterns,
            eligible,
            anchored,
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

    pub(crate) fn collect_candidates(
        &self,
        text: &str,
        is_active: impl Fn(usize) -> bool,
        out: &mut Vec<(u32, u32)>,
    ) {
        out.clear();
        if !self.anchor_first_bigram.may_have_match(text) {
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
