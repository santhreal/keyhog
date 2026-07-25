//! Always-active phase-2 prefilter construction and marking.
mod dispatch_plan;
mod gating;
mod trigger_evidence;

use dispatch_plan::{DispatchConfig, DispatchPlan, PrefilterScope};
use gating::{combined_gate_decision, CombinedGateDecision};
use super::phase2::*;
#[cfg(feature = "simd")]
use super::phase2_hs::Phase2HsEngine;
use super::phase2_truncate::truncate_for_prefilter;
use super::*;
use crate::scanner_config::ResolvedRuntimeTuningConfig;
use aho_corasick::AhoCorasick;
use std::sync::atomic::Ordering::Relaxed;


impl Phase2AlwaysActivePrefilter {
    /// Patterns per RegexSet batch. A single set over all ~2.7k always-active
    /// patterns blows the compiled-program size limit; batching keeps each
    /// set's NFA bounded while still collapsing thousands of full-chunk regex
    /// walks into a handful of linear set passes.
    const BATCH_SIZE: usize = 512;
    /// Generous per-batch compiled-program + lazy-DFA budget. Larger than the
    /// per-pattern `REGEX_SIZE_LIMIT_BYTES` because a batch holds many patterns;
    /// size/DFA limits only affect compile success and cache size, never which
    /// matches are reported, so a larger limit here stays match-equivalent.
    const BATCH_SIZE_LIMIT_BYTES: usize = 64 << 20;

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
        let anchor_residual_indices = always_active_indices
            .iter()
            .copied()
            .filter(|&index| {
                !anchor_index.is_some_and(|anchors| anchors.is_always_active_eligible(index))
            })
            .collect::<Vec<_>>();
        let localized_residual_indices = anchor_residual_indices
            .iter()
            .copied()
            .filter(|&index| phase2_patterns[index].0.regex.is_case_insensitive())
            .collect::<Vec<_>>();
        Some(Self {
            valid_always_active_indices: always_active_indices.to_vec(),
            anchor_residual_indices,
            localized_residual_indices,
            portable: std::sync::OnceLock::new(),
            portable_anchor_residual: std::sync::OnceLock::new(),
            portable_localized_residual: std::sync::OnceLock::new(),
            combined_gate: std::sync::OnceLock::new(),
            #[cfg(feature = "simd")]
            hs: std::sync::OnceLock::new(),
            #[cfg(feature = "simd")]
            hs_anchor_residual: std::sync::OnceLock::new(),
            #[cfg(feature = "simd")]
            hs_localized_residual: std::sync::OnceLock::new(),
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

    fn combined_gate<'a>(
        &'a self,
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
    ) -> Option<&'a CombinedNoCandidateGate> {
        self.combined_gate
            .get_or_init(|| {
                Self::build_combined_gate(phase2_patterns, &self.valid_always_active_indices)
            })
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
        let slot = match scope {
            PrefilterScope::Full => &self.hs,
            PrefilterScope::AnchorResidual => &self.hs_anchor_residual,
            PrefilterScope::LocalizedResidual => &self.hs_localized_residual,
        };
        slot.get_or_init(|| Phase2HsEngine::build(phase2_patterns, self.indices_for(scope)))
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
        let mut ungated_indices = Vec::new();
        let mut ci_gate_lits: Vec<Vec<u8>> = Vec::new();
        let mut plain_gate_lits: Vec<Vec<u8>> = Vec::new();
        Self::build_partition(
            phase2_patterns,
            &ci,
            true,
            false,
            &mut batches,
            &mut ungated_indices,
            &mut ci_gate_lits,
        );
        Self::build_partition(
            phase2_patterns,
            &plain_other,
            false,
            false,
            &mut batches,
            &mut ungated_indices,
            &mut plain_gate_lits,
        );
        Self::build_partition(
            phase2_patterns,
            &plain_homoglyph,
            false,
            true,
            &mut batches,
            &mut ungated_indices,
            &mut plain_gate_lits,
        );
        PortablePrefilter {
            batches,
            ungated_indices,
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
        // The non-anchorable always-active patterns (no required prefix literal),
        // carried as `(index, own-compiled-regex)` so the skip path checks each
        // with its EXACT runtime matcher, byte-for-byte match-equivalent to the
        // full body, no over- or under-marking.
        let mut non_anchorable: Vec<(usize, LazyRegex)> = Vec::new();
        for &index in always_active_indices {
            let (pattern, _) = phase2_patterns.get(index)?;
            let case_insensitive = pattern.regex.is_case_insensitive();
            match Self::pattern_gate_literals(phase2_patterns, index, case_insensitive) {
                Some(pat_lits) => {
                    for lit in pat_lits {
                        lits.push(lit.to_ascii_lowercase());
                    }
                }
                // Clone the `LazyRegex` (Arc-shared compile cache, so this shares
                // the already-compiled regex (no recompile, no extra memory)).
                None => non_anchorable.push((index, pattern.regex.clone())),
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

    /// Compute a pattern's gate-eligible required-prefix literals for the given
    /// case partition. Plain (homoglyph) patterns are matched on the ASCII path
    /// via their ASCII-FOLDED form, so their prefix literals must be extracted
    /// from that folded source, extracting from the unicode form would yield
    /// non-ASCII members that never appear in folded matching. `None` => the
    /// pattern is NOT gate-eligible and must run unconditionally.
    fn pattern_gate_literals(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        index: usize,
        case_insensitive: bool,
    ) -> Option<Vec<Vec<u8>>> {
        let (pattern, _) = phase2_patterns.get(index)?;
        if case_insensitive {
            gate_prefix_literals(pattern.regex.as_str())
        } else {
            // Plain batch: gate on the ASCII-folded form (the matcher used on
            // ASCII chunks). The fold MUST equal what `build_ascii_alternate`
            // compiles so the gate describes the running matcher, hence the one
            // shared `ascii_fold_regex_src`.
            let folded = ascii_fold_regex_src(pattern.regex.as_str());
            gate_prefix_literals(&folded)
        }
    }

    fn build_partition(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        indices: &[usize],
        case_insensitive: bool,
        homoglyph: bool,
        batches: &mut Vec<PrefilterBatch>,
        ungated_indices: &mut Vec<usize>,
        gate_lits: &mut Vec<Vec<u8>>,
    ) {
        // Split the partition into gate-eligible vs not so each compiled batch is
        // homogeneous: a `gateable` batch contains ONLY patterns that provably
        // require one of their prefix literals, making the combined-AC no-hit a
        // sound skip oracle for the whole batch.
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
        Self::build_batches(
            phase2_patterns,
            &other,
            case_insensitive,
            false,
            homoglyph,
            batches,
            ungated_indices,
        );
        // Eligible patterns: gateable batches. Only contribute their literals to
        // the combined gate when the batch was actually built as `gateable` (a
        // plain batch missing its `ascii_set`, or a compile failure, downgrades
        // to always-run, and then its literals must NOT gate anything).
        let first_new = batches.len();
        Self::build_batches(
            phase2_patterns,
            &eligible,
            case_insensitive,
            true,
            homoglyph,
            batches,
            ungated_indices,
        );
        // Re-derive contributed literals from the batches that ended up gateable,
        // so a downgraded batch (ascii_set None / compile failure) is excluded.
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

    /// Compile `indices` into RegexSet batches with the given `gateable` intent.
    /// A plain batch is only marked gateable when its `ascii_set` compiles (the
    /// folded matcher the gate describes); otherwise it downgrades to always-run.
    fn build_batches(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        indices: &[usize],
        case_insensitive: bool,
        gateable: bool,
        homoglyph: bool,
        batches: &mut Vec<PrefilterBatch>,
        ungated_indices: &mut Vec<usize>,
    ) {
        for chunk in indices.chunks(Self::BATCH_SIZE) {
            let mut srcs = Vec::with_capacity(chunk.len());
            for &index in chunk {
                let (pattern, _) = &phase2_patterns[index];
                srcs.push(pattern.regex.as_str());
            }
            if srcs.is_empty() {
                continue;
            }
            let built = Self::compile_set(&srcs, case_insensitive);
            match built {
                Ok(set) => {
                    let ascii_set = if case_insensitive {
                        None
                    } else {
                        Self::build_ascii_alternate(phase2_patterns, chunk)
                    };
                    let trunc_srcs: Vec<String> = srcs
                        .iter()
                        .map(|s| truncate_for_prefilter(s).unwrap_or_else(|| (*s).to_string())) // LAW10: truncation is a prefilter perf-opt over a SUPERSET; un-truncatable => full form, recall-safe (never under-matches)
                        .collect();
                    let set_trunc = match Self::compile_truncated_or_full_set(
                        &srcs,
                        &trunc_srcs,
                        case_insensitive,
                    ) {
                        Ok(set) => set,
                        Err(error) => {
                            tracing::warn!(
                                batch_size = chunk.len(),
                                case_insensitive,
                                %error,
                                "phase-2 RegexSet batch recompile failed; batch will run ungated (recall preserved)"
                            );
                            ungated_indices.extend_from_slice(chunk);
                            continue;
                        }
                    };
                    let ascii_set_trunc = ascii_set
                        .as_ref()
                        .and_then(|_| Self::build_ascii_alternate_trunc(phase2_patterns, chunk))
                        .or_else(|| ascii_set.clone());
                    // A plain gateable batch needs its folded matcher present for
                    // the (ASCII-path) gate to describe what actually runs. If the
                    // fold failed to compile, the unicode `set` runs on ASCII text
                    // and the folded-literal gate would be unsound -> downgrade.
                    let batch_gateable = gateable && (case_insensitive || ascii_set.is_some());
                    batches.push(PrefilterBatch {
                        set,
                        ascii_set,
                        set_trunc,
                        ascii_set_trunc,
                        phase2_indices: chunk.to_vec(),
                        gateable: batch_gateable,
                        homoglyph_skippable: homoglyph,
                    });
                }
                Err(error) => {
                    tracing::warn!(
                        batch_size = chunk.len(),
                        case_insensitive,
                        %error,
                        "phase-2 RegexSet batch compile failed; batch will run ungated (recall preserved)"
                    );
                    ungated_indices.extend_from_slice(chunk);
                }
            }
        }
    }

    fn compile_set(
        srcs: &[&str],
        case_insensitive: bool,
    ) -> std::result::Result<regex::RegexSet, regex::Error> {
        regex::RegexSetBuilder::new(srcs)
            .case_insensitive(case_insensitive)
            .size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
            .dfa_size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
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
            .dfa_size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
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
            .dfa_size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
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
            .dfa_size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
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
        tuning: &ResolvedRuntimeTuningConfig,
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
        let combined_gate = if tuning.no_candidate_gate {
            self.combined_gate(phase2_patterns)
        } else {
            None
        };
        if let (CombinedGateDecision::NonAnchorableOnly, Some(gate)) = (
            combined_gate_decision(plan.chunk(), tuning.no_candidate_gate, combined_gate),
            combined_gate,
        ) {
            gate.mark_non_anchorable(match_text, scratch, self.indices_for(plan.scope()));
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
        }
        for batch in &portable.batches {
            if plan.skip_homoglyph_batch(batch) {
                continue;
            }
            if batch.gateable {
                if !plan.run_gateable_batch(batch, gates) {
                    if prof {
                        GATE_BATCH_SKIPS.fetch_add(1, Relaxed);
                    }
                    continue;
                }
                if prof {
                    GATE_BATCH_RUNS.fetch_add(1, Relaxed);
                }
            }
            for set_idx in plan.matcher_for(batch).matches(match_text).iter() {
                scratch.mark(batch.phase2_indices[set_idx]);
            }
        }
        for &index in &portable.ungated_indices {
            scratch.mark(index);
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
        tuning: &ResolvedRuntimeTuningConfig,
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
            self.combined_gate(phase2_patterns)
        } else {
            None
        };
        if let (CombinedGateDecision::NonAnchorableOnly, Some(gate)) = (
            combined_gate_decision(plan.chunk(), tuning.no_candidate_gate, combined_gate),
            combined_gate,
        ) {
            return gate.any_non_anchorable_match(match_text);
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
        if !portable.ungated_indices.is_empty() {
            return true;
        }
        let gates = plan.portable_gates(portable);
        for batch in &portable.batches {
            if plan.skip_homoglyph_batch(batch) || !plan.run_gateable_batch(batch, gates) {
                continue;
            }
            if plan.matcher_for(batch).is_match(match_text) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
#[path = "../../tests/unit/phase2_prefilter/mod.rs"]
mod tests;
