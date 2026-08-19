//! Always-active phase-2 prefilter construction and marking.
mod dispatch_plan;
mod gating;
mod trigger_evidence;

use super::phase2::*;
#[cfg(feature = "simd")]
use super::phase2_hs::Phase2HsEngine;
use super::phase2_truncate::truncate_for_prefilter;
use super::*;
use crate::scanner_config::ResolvedScannerTuningConfig;
use aho_corasick::AhoCorasick;
use dispatch_plan::{BatchMatcher, DispatchConfig, DispatchPlan, PrefilterScope};
use gating::{combined_gate_decision, CombinedGateDecision};
use keyhog_profile::{add_counter, CounterId};
use std::sync::atomic::Ordering::Relaxed;

pub(crate) fn canonical_phase2_scope_indices(
    phase2_patterns: &[(CompiledPattern, Vec<String>)],
    always_active_indices: &[usize],
    anchor_index: Option<&super::phase2_anchor::Phase2AnchorIndex>,
) -> [Vec<usize>; 3] {
    let anchor_residual = always_active_indices
        .iter()
        .copied()
        .filter(|&index| {
            !anchor_index.is_some_and(|anchors| anchors.is_always_active_eligible(index))
        })
        .collect::<Vec<_>>();
    let localized_residual = anchor_residual
        .iter()
        .copied()
        .filter(|&index| phase2_patterns[index].0.regex.is_case_insensitive())
        .collect::<Vec<_>>();
    [
        always_active_indices.to_vec(),
        anchor_residual,
        localized_residual,
    ]
}

impl Phase2AlwaysActivePrefilter {
    /// Patterns per RegexSet batch. A single set over all ~2.7k always-active
    /// patterns blows the compiled-program size limit, so the set is batched.
    ///
    /// Batch size is a direct cost lever, not just a size guard. Reporting
    /// WHICH patterns matched has no lazy-DFA implementation, so a batch that
    /// contains any match pays a PikeVM pass proportional to the batch's whole
    /// NFA. Small batches confine that pass to the patterns near the match and
    /// let the cheap `is_match` pre-check clear the rest. Measured on a real
    /// source tree (5,583 files, 44 MiB, portable CPU route): 512 -> 4.93 s,
    /// 256 -> 4.64 s, 128 -> 3.40 s, 64 -> 3.20 s, 32 -> 3.20 s. 64 is the knee;
    /// smaller only adds per-batch scans for no further gain.
    const BATCH_SIZE: usize = 64;
    /// Generous per-batch COMPILED-PROGRAM budget. Larger than the per-pattern
    /// `REGEX_SIZE_LIMIT_BYTES` because a batch holds many patterns. This one
    /// only decides whether a batch compiles at all; a batch that exceeds it
    /// falls into `ungated_indices` and runs unconditionally, so the result
    /// stays recall-equivalent either way.
    const BATCH_SIZE_LIMIT_BYTES: usize = 64 << 20;
    /// Per-batch lazy-DFA cache ceiling. This is a PER-THREAD, PER-REGEXSET
    /// allocation: every worker that runs a batch gets its own transition
    /// cache, so a ceiling shared with the compile budget above meant a
    /// nominal 64 MiB of scratch per batch per worker. The DFA cache size only
    /// affects how much of the automaton is memoized, never which patterns the
    /// set reports, so lowering it stays match-equivalent.
    ///
    /// 4 MiB is four times the per-pattern ceiling
    /// (`crate::types::REGEX_SIZE_LIMIT_BYTES`), which keeps headroom for a
    /// 64-pattern batch while bounding worker scratch. Going far below a
    /// batch's real working set is counter-productive rather than cheaper: the
    /// lazy DFA thrashes and the meta engine falls back to slower engines that
    /// allocate comparable per-thread state (measured on the per-pattern
    /// ceiling: 1 MiB -> 64 KiB left peak RSS unchanged and cost ~5x wall).
    const BATCH_DFA_CACHE_LIMIT_BYTES: usize = 4 << 20;

    /// Build from the always-active phase-2 indices. Always returns `Some` for
    /// a non-empty input: patterns in batches that fail to compile fall into
    /// `ungated_indices` and run unconditionally, so the result is always
    /// recall-equivalent to running every always-active pattern.
    pub(crate) fn build(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        always_active_indices: &[usize],
        anchor_index: Option<&super::phase2_anchor::Phase2AnchorIndex>,
    ) -> Option<Self> {
        if always_active_indices.is_empty() {
            return None;
        }
        debug_assert!(
            always_active_indices
                .iter()
                .all(|&index| index < phase2_patterns.len()),
            "compiled scanner invariant violation: phase-2 always-active index out of range"
        );
        let [valid_always_active_indices, anchor_residual_indices, localized_residual_indices] =
            canonical_phase2_scope_indices(phase2_patterns, always_active_indices, anchor_index);
        Some(Self {
            valid_always_active_indices,
            anchor_residual_indices,
            localized_residual_indices,
            portable: std::sync::OnceLock::new(),
            portable_anchor_residual: std::sync::OnceLock::new(),
            portable_localized_residual: std::sync::OnceLock::new(),
            combined_gate: std::sync::OnceLock::new(),
            combined_gate_anchor_residual: std::sync::OnceLock::new(),
            combined_gate_localized_residual: std::sync::OnceLock::new(),
            #[cfg(feature = "simd")]
            hs: std::sync::OnceLock::new(),
            #[cfg(feature = "simd")]
            packed_hs: std::sync::Mutex::new(None),
            #[cfg(feature = "simd")]
            hs_anchor_residual: std::sync::OnceLock::new(),
            #[cfg(feature = "simd")]
            packed_hs_anchor_residual: std::sync::Mutex::new(None),
            #[cfg(feature = "simd")]
            hs_localized_residual: std::sync::OnceLock::new(),
            #[cfg(feature = "simd")]
            packed_hs_localized_residual: std::sync::Mutex::new(None),
        })
    }

    #[cfg(feature = "simd")]
    pub(crate) fn hyperscan_initialized(&self) -> bool {
        [
            &self.hs,
            &self.hs_anchor_residual,
            &self.hs_localized_residual,
        ]
        .into_iter()
        .any(|slot| slot.get().is_some_and(Option::is_some))
    }

    #[cfg(feature = "simd")]
    pub(crate) fn install_hyperscan_programs(
        &self,
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        programs: Vec<crate::execution_pack::simd_program::HyperscanPhase2ScopeProgram>,
    ) -> std::result::Result<(), String> {
        if programs.len() != 3 {
            return Err(format!(
                "packed SIMD program has {} phase-two scopes; exactly 3 are required",
                programs.len()
            ));
        }
        let slots = [
            (
                crate::execution_pack::simd_program::HyperscanPhase2Scope::Full,
                PrefilterScope::Full,
                &self.packed_hs,
            ),
            (
                crate::execution_pack::simd_program::HyperscanPhase2Scope::AnchorResidual,
                PrefilterScope::AnchorResidual,
                &self.packed_hs_anchor_residual,
            ),
            (
                crate::execution_pack::simd_program::HyperscanPhase2Scope::LocalizedResidual,
                PrefilterScope::LocalizedResidual,
                &self.packed_hs_localized_residual,
            ),
        ];
        for (program, (expected_scope, runtime_scope, packed_slot)) in
            programs.into_iter().zip(slots)
        {
            if program.scope != expected_scope {
                return Err(format!(
                    "packed phase-two scope ordering is invalid: expected {expected_scope:?}, found {:?}",
                    program.scope
                ));
            }
            Phase2HsEngine::validate_program(
                phase2_patterns,
                self.indices_for(runtime_scope),
                &program,
            )?;
            let mut packed = packed_slot
                .lock()
                // LAW10: poison recovery retains the complete packed program slot for validation.
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if packed.replace(program).is_some() {
                return Err(format!(
                    "packed phase-two scope {expected_scope:?} was installed more than once"
                ));
            }
        }
        Ok(())
    }

    fn combined_gate<'a>(
        &'a self,
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        scope: PrefilterScope,
    ) -> Option<&'a CombinedNoCandidateGate> {
        let slot = match scope {
            PrefilterScope::Full => &self.combined_gate,
            PrefilterScope::AnchorResidual => &self.combined_gate_anchor_residual,
            PrefilterScope::LocalizedResidual => &self.combined_gate_localized_residual,
        };
        slot.get_or_init(|| Self::build_combined_gate(phase2_patterns, self.indices_for(scope)))
            .as_ref()
    }

    fn indices_for(&self, scope: PrefilterScope) -> &[usize] {
        match scope {
            PrefilterScope::Full => &self.valid_always_active_indices,
            PrefilterScope::AnchorResidual => &self.anchor_residual_indices,
            PrefilterScope::LocalizedResidual => &self.localized_residual_indices,
        }
    }

    fn portable_for<'a>(
        &'a self,
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        scope: PrefilterScope,
    ) -> &'a PortablePrefilter {
        let slot = match scope {
            PrefilterScope::Full => &self.portable,
            PrefilterScope::AnchorResidual => &self.portable_anchor_residual,
            PrefilterScope::LocalizedResidual => &self.portable_localized_residual,
        };
        slot.get_or_init(|| Self::compile_portable(phase2_patterns, self.indices_for(scope)))
    }

    #[cfg(feature = "simd")]
    fn hs_for<'a>(
        &'a self,
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        scope: PrefilterScope,
    ) -> Option<&'a Phase2HsEngine> {
        let (slot, packed_slot) = match scope {
            PrefilterScope::Full => (&self.hs, &self.packed_hs),
            PrefilterScope::AnchorResidual => {
                (&self.hs_anchor_residual, &self.packed_hs_anchor_residual)
            }
            PrefilterScope::LocalizedResidual => (
                &self.hs_localized_residual,
                &self.packed_hs_localized_residual,
            ),
        };
        slot.get_or_init(|| {
            let packed = packed_slot
                .lock()
                // LAW10: poison recovery retains the complete packed program slot for one-time hydration.
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            match packed {
                Some(program) => match Phase2HsEngine::from_program(
                    phase2_patterns,
                    self.indices_for(scope),
                    program,
                ) {
                    Ok(engine) => engine,
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            "packed HS always-active prefilter initialization failed; using RegexSet path"
                        );
                        None
                    }
                },
                None => match Phase2HsEngine::build(phase2_patterns, self.indices_for(scope)) {
                    Ok(engine) => engine,
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            "HS always-active prefilter exceeded its memory bound; using the bounded RegexSet path"
                        );
                        None
                    }
                },
            }
        })
        .as_ref()
    }

    fn compile_portable(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        indices: &[usize],
    ) -> PortablePrefilter {
        // Keep batches homogeneous by case flags and homoglyph-variant status.
        let mut ci: Vec<usize> = Vec::new();
        let mut plain_homoglyph: Vec<usize> = Vec::new();
        let mut plain_other: Vec<usize> = Vec::new();
        for &index in indices {
            let (pattern, _) = &phase2_patterns[index];
            if pattern.regex.is_case_insensitive() {
                ci.push(index);
            } else if pattern.homoglyph_variant {
                plain_homoglyph.push(index);
            } else {
                plain_other.push(index);
            }
        }
        let mut batches = Vec::new();
        let mut ci_gate_lits: Vec<Vec<u8>> = Vec::new();
        let mut plain_gate_lits: Vec<Vec<u8>> = Vec::new();
        Self::build_partition(
            phase2_patterns,
            &ci,
            true,
            false,
            &mut batches,
            &mut ci_gate_lits,
        );
        Self::build_partition(
            phase2_patterns,
            &plain_other,
            false,
            false,
            &mut batches,
            &mut plain_gate_lits,
        );
        Self::build_partition(
            phase2_patterns,
            &plain_homoglyph,
            false,
            true,
            &mut batches,
            &mut plain_gate_lits,
        );
        PortablePrefilter {
            batches,
            ci_gate: Self::build_gate_ac(&ci_gate_lits, true),
            plain_gate: Self::build_gate_ac(&plain_gate_lits, false),
        }
    }

    /// The gate's skip path checks each non-anchorable always-active pattern with
    /// its own regex. That is recall-safe and cheap when the set is small, but if
    /// MOST always-active patterns were non-anchorable the skip path would run
    /// hundreds of individual regexes, worse than the one batched HS scan it
    /// replaces. So the builder declines the gate (`None`, full body runs) only in
    /// that degenerate case: when the non-anchorable set is BOTH a large fraction
    /// (> 1/2) of the always-active set AND large in absolute terms (> the absolute
    /// ceiling). In practice almost every credential detector carries a required
    /// prefix (and every homoglyph variant folds to one), so the non-anchorable set
    /// is a small minority and the gate engages.
    const MAX_NON_ANCHORABLE_FRACTION_NUM: usize = 1;
    const MAX_NON_ANCHORABLE_FRACTION_DEN: usize = 2;
    /// Absolute ceiling on the non-anchorable skip-path regex count before the
    /// fraction test can decline the gate (below this, the per-pattern checks are
    /// cheap enough that the gate is always worth keeping).
    const MAX_NON_ANCHORABLE_ABS: usize = 256;

    /// Build the combined no-candidate gate. `None` means the full body runs.
    fn build_combined_gate(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        always_active_indices: &[usize],
    ) -> Option<CombinedNoCandidateGate> {
        if always_active_indices.is_empty() {
            return None;
        }
        let mut lits: Vec<Vec<u8>> = Vec::new();
        // The non-anchorable always-active patterns, carried with exact runtime
        // matchers and homoglyph ownership for the proven ASCII skip.
        let mut non_anchorable: Vec<(usize, LazyRegex, bool)> = Vec::new();
        for &index in always_active_indices {
            let (pattern, _) = phase2_patterns.get(index)?;
            let case_insensitive = pattern.regex.is_case_insensitive();
            match Self::pattern_gate_literals(phase2_patterns, index, case_insensitive) {
                Some(pat_lits) => {
                    for lit in pat_lits {
                        lits.push(lit.to_ascii_lowercase());
                    }
                }
                // Clone the `LazyRegex` (Arc-shared compile cache) and retain
                // homoglyph ownership so ASCII plans can omit the variant.
                None => {
                    non_anchorable.push((index, pattern.regex.clone(), pattern.homoglyph_variant))
                }
            }
        }
        if lits.is_empty() {
            return None;
        }
        if non_anchorable.len() > Self::MAX_NON_ANCHORABLE_ABS
            && non_anchorable.len() * Self::MAX_NON_ANCHORABLE_FRACTION_DEN
                > always_active_indices.len() * Self::MAX_NON_ANCHORABLE_FRACTION_NUM
        {
            // Disables the optimization (recall-safe: the full body runs), but
            // Law 10 forbids a SILENT degrade and the speed cost is far more than a
            // rounding error (every chunk now runs the full phase-2 body), so
            // surface it LOUDLY, exactly like the Aho-Corasick build-failure twin below.
            tracing::warn!(
                non_anchorable = non_anchorable.len(),
                always_active = always_active_indices.len(),
                "phase-2 combined no-candidate gate declined: non-anchorable \
                 always-active set too large to gate efficiently; gate disabled, \
                 prefilter runs unconditionally (recall preserved, SWE-101 fast path off)"
            );
            return None;
        }
        lits.sort_unstable();
        lits.dedup();
        // Build the first-bigram prescreen before moving `lits` into the AC builder.
        let anchor_first_bigram =
            FirstBigramSet::from_literals(lits.iter().map(Vec::as_slice), true);
        match AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&lits)
        {
            Ok(anchor_ac) => Some(CombinedNoCandidateGate {
                anchor_ac,
                non_anchorable,
                anchor_first_bigram,
            }),
            Err(error) => {
                // Build failure disables the optimization (recall-safe: the full
                // body runs), but Law 10 forbids a SILENT degrade (surface it).
                tracing::warn!(
                    literals = lits.len(),
                    %error,
                    "phase-2 combined no-candidate gate Aho-Corasick build failed; \
                     gate disabled, prefilter runs unconditionally (recall preserved, \
                     SWE-101 fast path off)"
                );
                None
            }
        }
    }

    /// Compute a pattern's gate-eligible required boundary literals for the
    /// given case partition. Prefer prefixes, which are also reusable by the
    /// anchor localizer, then fall back to finite required suffixes for patterns
    /// that have no usable prefix. Either boundary is a sound absence proof.
    ///
    /// Plain (homoglyph) patterns are matched on the ASCII path via their
    /// ASCII-FOLDED form, so literals must be extracted from that folded source.
    /// `None` means the pattern is not gate-eligible and must run
    /// unconditionally.
    fn pattern_gate_literals(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        index: usize,
        case_insensitive: bool,
    ) -> Option<Vec<Vec<u8>>> {
        let (pattern, _) = phase2_patterns.get(index)?;
        let folded;
        let source = if case_insensitive {
            pattern.regex.as_str()
        } else {
            folded = ascii_fold_regex_src(pattern.regex.as_str());
            &folded
        };
        gate_prefix_literals(source).or_else(|| {
            let suffixes = super::suffix_gate_literals(source);
            (!suffixes.is_empty()).then(|| suffixes.into_iter().map(String::into_bytes).collect())
        })
    }

    fn build_partition(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        indices: &[usize],
        case_insensitive: bool,
        homoglyph: bool,
        batches: &mut Vec<PrefilterBatch>,
        gate_lits: &mut Vec<Vec<u8>>,
    ) {
        // Split the partition into homogeneous batches. A `gateable` batch
        // contains only patterns that provably require one of their boundary
        // literals, making the combined-AC no-hit a sound skip oracle.
        let mut eligible: Vec<usize> = Vec::new();
        let mut other: Vec<usize> = Vec::new();
        for &i in indices {
            if Self::pattern_gate_literals(phase2_patterns, i, case_insensitive).is_some() {
                eligible.push(i);
            } else {
                other.push(i);
            }
        }
        // Ungateable patterns: always-run batches (gateable = false).
        Self::build_batches(&other, case_insensitive, false, homoglyph, batches);
        // Eligible patterns: gateable batches, which contribute their literals to
        // the combined gate. A plain batch whose ASCII fold fails to compile is
        // detected at match time and runs ungated there, so the gate stays sound
        // without needing the fold to be compiled here.
        let first_new = batches.len();
        Self::build_batches(&eligible, case_insensitive, true, homoglyph, batches);
        for batch in &batches[first_new..] {
            if !batch.gateable {
                continue;
            }
            for &idx in &batch.phase2_indices {
                if let Some(lits) =
                    Self::pattern_gate_literals(phase2_patterns, idx, case_insensitive)
                {
                    gate_lits.extend(lits);
                }
            }
        }
    }

    /// Partition `indices` into batches with the given `gateable` intent.
    ///
    /// No matcher is compiled here. Each batch compiles exactly the variant a
    /// chunk selects, on first use, so a batch that every chunk skips costs
    /// nothing. Compile failures are handled where they surface: an
    /// unavailable matcher makes the caller mark every index in the batch, and
    /// a plain batch whose ASCII fold does not compile runs ungated, both of
    /// which are the recall-safe supersets the eager path produced.
    fn build_batches(
        indices: &[usize],
        case_insensitive: bool,
        gateable: bool,
        homoglyph: bool,
        batches: &mut Vec<PrefilterBatch>,
    ) {
        for chunk in indices.chunks(Self::BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            batches.push(PrefilterBatch {
                phase2_indices: chunk.to_vec(),
                case_insensitive,
                gateable,
                homoglyph_skippable: homoglyph,
                set: std::sync::OnceLock::new(),
                ascii_set: std::sync::OnceLock::new(),
                set_trunc: std::sync::OnceLock::new(),
                ascii_set_trunc: std::sync::OnceLock::new(),
            });
        }
    }

    /// The batch's pattern sources, in set-entry order.
    fn batch_sources<'a>(
        phase2_patterns: &'a [(CompiledPattern, Vec<String>)],
        indices: &[usize],
    ) -> Vec<&'a str> {
        indices
            .iter()
            .map(|&index| phase2_patterns[index].0.regex.as_str())
            .collect()
    }

    /// Compile the unicode form. `None` on failure, which makes the caller mark
    /// every index in the batch rather than lose recall.
    fn compile_batch_set(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        batch: &PrefilterBatch,
    ) -> Option<regex::RegexSet> {
        let srcs = Self::batch_sources(phase2_patterns, &batch.phase2_indices);
        match Self::compile_set(&srcs, batch.case_insensitive) {
            Ok(set) => Some(set),
            Err(error) => {
                tracing::warn!(
                    batch_size = batch.phase2_indices.len(),
                    case_insensitive = batch.case_insensitive,
                    %error,
                    "phase-2 RegexSet batch compile failed; every pattern in the batch is marked unconditionally (recall preserved)"
                );
                None
            }
        }
    }

    /// Compile the truncated unicode form, falling back to the full form.
    fn compile_batch_set_trunc(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        batch: &PrefilterBatch,
    ) -> Option<regex::RegexSet> {
        let srcs = Self::batch_sources(phase2_patterns, &batch.phase2_indices);
        let trunc_srcs: Vec<String> = srcs
            .iter()
            .map(|s| truncate_for_prefilter(s).unwrap_or_else(|| (*s).to_string())) // LAW10: truncation is a prefilter perf-opt over a SUPERSET; un-truncatable => full form, recall-safe (never under-matches)
            .collect();
        match Self::compile_truncated_or_full_set(&srcs, &trunc_srcs, batch.case_insensitive) {
            Ok(set) => Some(set),
            Err(error) => {
                tracing::warn!(
                    batch_size = batch.phase2_indices.len(),
                    case_insensitive = batch.case_insensitive,
                    %error,
                    "phase-2 truncated RegexSet batch compile failed; every pattern in the batch is marked unconditionally (recall preserved)"
                );
                None
            }
        }
    }

    /// The unicode matcher for `batch` under the active truncation setting.
    pub(super) fn batch_unicode_matcher<'b>(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        batch: &'b PrefilterBatch,
        truncate: bool,
    ) -> Option<&'b regex::RegexSet> {
        if truncate {
            batch
                .set_trunc
                .get_or_init(|| Self::compile_batch_set_trunc(phase2_patterns, batch))
                .as_ref()
        } else {
            batch
                .set
                .get_or_init(|| Self::compile_batch_set(phase2_patterns, batch))
                .as_ref()
        }
    }

    /// The ASCII-folded matcher for a plain batch under the active truncation
    /// setting. `None` for a case-insensitive batch (it has no fold) and on
    /// fold-compile failure, which makes the caller run the unicode form
    /// ungated because the folded literal gate no longer describes it.
    pub(super) fn batch_folded_matcher<'b>(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        batch: &'b PrefilterBatch,
        truncate: bool,
    ) -> Option<&'b regex::RegexSet> {
        if batch.case_insensitive {
            return None;
        }
        let slot = if truncate {
            &batch.ascii_set_trunc
        } else {
            &batch.ascii_set
        };
        slot.get_or_init(|| {
            if truncate {
                Self::build_ascii_alternate_trunc(phase2_patterns, &batch.phase2_indices)
                    .or_else(|| Self::build_ascii_alternate(phase2_patterns, &batch.phase2_indices))
            } else {
                Self::build_ascii_alternate(phase2_patterns, &batch.phase2_indices)
            }
        })
        .as_ref()
    }

    fn compile_set(
        srcs: &[&str],
        case_insensitive: bool,
    ) -> std::result::Result<regex::RegexSet, regex::Error> {
        regex::RegexSetBuilder::new(srcs)
            .case_insensitive(case_insensitive)
            .size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
            .dfa_size_limit(Self::BATCH_DFA_CACHE_LIMIT_BYTES)
            .crlf(case_insensitive)
            .build()
    }

    pub(crate) fn compile_truncated_or_full_set(
        srcs: &[&str],
        trunc_srcs: &[String],
        case_insensitive: bool,
    ) -> std::result::Result<regex::RegexSet, regex::Error> {
        regex::RegexSetBuilder::new(trunc_srcs)
            .case_insensitive(case_insensitive)
            .size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
            .dfa_size_limit(Self::BATCH_DFA_CACHE_LIMIT_BYTES)
            .crlf(case_insensitive)
            .build()
            .or_else(|_| {
                // LAW10: truncated RegexSet compile failure reuses the full set; recall-preserving
                tracing::warn!(
                    batch_size = trunc_srcs.len(),
                    case_insensitive,
                    "truncated phase-2 RegexSet batch failed to compile; using full set (perf-only impact)"
                );
                Self::compile_set(srcs, case_insensitive)
            })
    }

    /// Build the combined skip-gate Aho-Corasick over `literals`. `ci` selects
    /// ASCII case-insensitive matching (for the detector-regex partition).
    /// `None` when there are no literals to gate on.
    fn build_gate_ac(literals: &[Vec<u8>], ci: bool) -> Option<AhoCorasick> {
        if literals.is_empty() {
            return None;
        }
        match AhoCorasick::builder()
            .ascii_case_insensitive(ci)
            .build(literals)
        {
            Ok(ac) => Some(ac),
            Err(error) => {
                tracing::warn!(
                    literals = literals.len(),
                    ci,
                    %error,
                    "phase-2 prefix-gate Aho-Corasick build failed; prefix-gate optimization disabled (recall preserved)"
                );
                None
            }
        }
    }

    /// Build the ASCII-folded alternate RegexSet for a plain (homoglyph) batch:
    /// each homoglyph regex with every non-ASCII codepoint removed, in the SAME
    /// entry order. Match-equivalent to the unicode form on pure-ASCII text.
    /// `None` if any fold fails to compile (the unicode set is used instead).
    fn build_ascii_alternate(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        indices: &[usize],
    ) -> Option<regex::RegexSet> {
        let folded = Self::ascii_folded_sources(phase2_patterns, indices, false)?;
        match regex::RegexSetBuilder::new(&folded)
            .case_insensitive(false)
            .size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
            .dfa_size_limit(Self::BATCH_DFA_CACHE_LIMIT_BYTES)
            .build()
        {
            Ok(set) => Some(set),
            Err(error) => {
                tracing::warn!(
                    batch_size = indices.len(),
                    %error,
                    "ASCII-folded phase-2 RegexSet failed to compile; plain batch runs unicode form (perf-only impact)"
                );
                None
            }
        }
    }

    /// As `build_ascii_alternate`, but each folded source is additionally passed
    /// through `truncate_for_prefilter` (truncate the FOLDED form so the matcher
    /// that runs on ASCII text stays on the lazy-DFA). SAME entry order; `None`
    /// if any fold or the truncated set fails to compile.
    fn build_ascii_alternate_trunc(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        indices: &[usize],
    ) -> Option<regex::RegexSet> {
        let folded = Self::ascii_folded_sources(phase2_patterns, indices, true)?;
        match regex::RegexSetBuilder::new(&folded)
            .case_insensitive(false)
            .size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
            .dfa_size_limit(Self::BATCH_DFA_CACHE_LIMIT_BYTES)
            .build()
        {
            Ok(set) => Some(set),
            Err(error) => {
                tracing::warn!(
                    batch_size = indices.len(),
                    %error,
                    "ASCII-folded truncated phase-2 RegexSet failed to compile; using unicode full set (perf-only impact)"
                );
                None
            }
        }
    }

    fn ascii_folded_sources(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        indices: &[usize],
        truncate: bool,
    ) -> Option<Vec<String>> {
        let mut folded = Vec::with_capacity(indices.len());
        for &index in indices {
            let (pattern, _) = &phase2_patterns[index];
            let source = ascii_fold_regex_src(pattern.regex.as_str());
            if truncate {
                folded.push(truncate_for_prefilter(&source).unwrap_or(source)); // LAW10: truncation is a prefilter perf-opt over a SUPERSET; un-truncatable => full form, recall-safe (never under-matches)
            } else {
                folded.push(source);
            }
        }
        Some(folded)
    }

    /// Mark every always-active phase-2 pattern whose regex can match `match_text`.
    /// `match_text` MUST be the text the per-pattern extraction runs on
    /// (`preprocessed.text`) for the prefilter to stay sound under unicode
    /// normalization.
    /// `anchor_mode`: the main required-prefix localizer owns its eligible
    /// always-active patterns, so this prefilter marks only its residual set.
    /// `localize_plain`: the caller (the shared-anchor path) handles the plain
    /// (homoglyph) patterns on pure-ASCII chunks via the localized AC, so they
    /// are SKIPPED here (no whole-chunk RegexSet pass). When false, plain
    /// batches run their ASCII-folded alternate (the order-preserving fold)
    /// the safety-net path that is always recall-correct.
    pub(crate) fn mark_matches(
        &self,
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        match_text: &str,
        scratch: &mut ActivePatternsScratch,
        anchor_mode: bool,
        localize_plain: bool,
        tuning: &ResolvedScannerTuningConfig,
        allow_hyperscan: bool,
    ) {
        #[cfg(not(feature = "simd"))]
        let _ = allow_hyperscan; // LAW10: recall is preserved because non-SIMD builds have no accelerator to degrade from and use the exact portable matcher.
        record_mark_call();
        let plan = DispatchPlan::for_mark(
            match_text,
            anchor_mode,
            localize_plain,
            allow_hyperscan,
            DispatchConfig::from_tuning(tuning),
        );
        let scope_indices = self.indices_for(plan.scope());
        if scope_indices.is_empty()
            || (plan.skip_homoglyph()
                && scope_indices
                    .iter()
                    .all(|&index| phase2_patterns[index].0.homoglyph_variant))
        {
            record_mark_gate_skip();
            return;
        }
        let combined_gate = if tuning.no_candidate_gate {
            self.combined_gate(phase2_patterns, plan.scope())
        } else {
            None
        };
        if let (CombinedGateDecision::NonAnchorableOnly, Some(gate)) = (
            combined_gate_decision(plan.chunk(), tuning.no_candidate_gate, combined_gate),
            combined_gate,
        ) {
            gate.mark_non_anchorable(match_text, scratch, scope_indices, plan.skip_homoglyph());
            record_mark_gate_skip();
            return;
        }

        record_mark_perpattern_work();
        #[cfg(feature = "simd")]
        if plan.try_hyperscan() {
            if let Some(hs) = self.hs_for(phase2_patterns, plan.scope()) {
                match hs.mark(match_text, scratch, plan.skip_homoglyph()) {
                    Ok(()) => {
                        record_mark_hs_served();
                        return;
                    }
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            "HS always-active prefilter failed; using RegexSet path for this chunk"
                        );
                    }
                }
            }
        }

        record_mark_regexset_served();
        let portable = self.portable_for(phase2_patterns, plan.scope());
        let gates = plan.portable_gates(portable);
        let prof = phase2_pattern_prof_enabled();
        if prof {
            GATE_CALLS.fetch_add(1, Relaxed);
            add_counter(CounterId::Phase2PrefilterMarkCalls, 1);
        }
        for batch in &portable.batches {
            if plan.skip_homoglyph_batch(batch) {
                continue;
            }
            if batch.gateable && !plan.run_gateable_batch(batch, !batch.case_insensitive, &gates) {
                if prof {
                    GATE_BATCH_SKIPS.fetch_add(1, Relaxed);
                    add_counter(CounterId::Phase2PrefilterGateSkips, 1);
                }
                continue;
            }
            let matcher = match plan.matcher_for(batch, phase2_patterns) {
                BatchMatcher::Run(set) => set,
                BatchMatcher::Unavailable => {
                    for &index in &batch.phase2_indices {
                        scratch.mark(index);
                    }
                    continue;
                }
            };
            if prof && batch.gateable {
                GATE_BATCH_RUNS.fetch_add(1, Relaxed);
            }
            // `RegexSet::matches` has no lazy-DFA implementation: reporting
            // WHICH patterns matched forces the meta engine onto PikeVM, which
            // walks every NFA state for every byte. `is_match` takes the normal
            // fast path, and "no pattern matched" is the overwhelmingly common
            // answer on real source, so proving emptiness first skips the
            // PikeVM pass entirely. The result is identical by definition: an
            // empty `is_match` means `matches` reports nothing.
            if !matcher.is_match(match_text) {
                continue;
            }
            for set_idx in matcher.matches(match_text).iter() {
                scratch.mark(batch.phase2_indices[set_idx]);
            }
        }
    }

    /// True iff ANY always-active pattern can fire on `match_text`: the BOOLEAN
    /// companion to [`mark_matches`](Self::mark_matches) for the no-phase-1-hit
    /// admission gate (`has_active_phase2_patterns_for_chunk`), which needs only
    /// "is the active set non-empty?", not the full marked set. Early-exits at the
    /// first active pattern; the marked set is the measured #1 scan cost and the
    /// gate would otherwise build it in full only to call `.is_empty()` (then have
    /// extraction build it AGAIN). It uses the same full-scope dispatch plan as
    /// `mark_matches(anchor_mode = false)`, including the exact combined and
    /// portable prefix evidence. A portable batch is skipped only when its
    /// required-prefix automaton supplies exact negative evidence; unavailable
    /// evidence fails closed and runs the batch. Thus admission computes the
    /// same active-set membership while avoiding materializing that set.
    ///
    /// Like `mark_matches`, it consults the cheap SWE-101 `combined_gate` first: on
    /// a pure-ASCII chunk where the combined required-literal AC finds nothing, NO
    /// always-active pattern can fire, so it returns `false` at AC-`is_match` cost
    /// instead of running the HS / RegexSet body, the admission gate then pays ~ns
    /// on the no-candidate chunks it is built to reject.
    ///
    /// Called by `has_active_phase2_patterns_for_chunk` for every backend's
    /// shared no-hit admission proof.
    pub(crate) fn any_active_match(
        &self,
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        match_text: &str,
        tuning: &ResolvedScannerTuningConfig,
        allow_hyperscan: bool,
    ) -> bool {
        #[cfg(not(feature = "simd"))]
        let _ = allow_hyperscan; // LAW10: recall is preserved because non-SIMD builds have no accelerator to degrade from and use the exact portable matcher.
        let plan = DispatchPlan::for_admission(
            match_text,
            allow_hyperscan,
            DispatchConfig::from_tuning(tuning),
        );
        let combined_gate = if tuning.no_candidate_gate {
            self.combined_gate(phase2_patterns, plan.scope())
        } else {
            None
        };
        if let (CombinedGateDecision::NonAnchorableOnly, Some(gate)) = (
            combined_gate_decision(plan.chunk(), tuning.no_candidate_gate, combined_gate),
            combined_gate,
        ) {
            return gate.any_non_anchorable_match(match_text, plan.skip_homoglyph());
        }

        #[cfg(feature = "simd")]
        if plan.try_hyperscan() {
            if let Some(hs) = self.hs_for(phase2_patterns, plan.scope()) {
                match hs.any_match(match_text, plan.skip_homoglyph()) {
                    Ok(hit) => return hit,
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            "HS always-active admission gate failed; using RegexSet path for this chunk"
                        );
                    }
                }
            }
        }

        let portable = self.portable_for(phase2_patterns, plan.scope());
        let gates = plan.portable_gates(portable);
        for batch in &portable.batches {
            if plan.skip_homoglyph_batch(batch) {
                continue;
            }
            if batch.gateable && !plan.run_gateable_batch(batch, !batch.case_insensitive, &gates) {
                continue;
            }
            let matcher = match plan.matcher_for(batch, phase2_patterns) {
                BatchMatcher::Run(set) => set,
                // Marking would mark every pattern in the batch, so the active
                // set is non-empty by construction.
                BatchMatcher::Unavailable => return true,
            };
            if matcher.is_match(match_text) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
#[path = "../../tests/unit/phase2_prefilter/mod.rs"]
mod tests;
