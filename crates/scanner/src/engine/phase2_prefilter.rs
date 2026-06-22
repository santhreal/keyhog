//! Always-active phase-2 prefilter construction and marking.
use super::phase2::*;
#[cfg(feature = "simd")]
use super::phase2_hs::Phase2HsEngine;
use super::phase2_truncate::truncate_for_prefilter;
use super::*;
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
    ) -> Option<Self> {
        if always_active_indices.is_empty() {
            return None;
        }
        // Keep batches homogeneous by case flags and homoglyph-variant status.
        let mut ci: Vec<usize> = Vec::new();
        let mut plain_homoglyph: Vec<usize> = Vec::new();
        let mut plain_other: Vec<usize> = Vec::new();
        let mut valid_always_active_indices: Vec<usize> =
            Vec::with_capacity(always_active_indices.len());
        for &index in always_active_indices {
            match phase2_patterns.get(index) {
                Some((pattern, _)) if pattern.regex.is_case_insensitive() => {
                    valid_always_active_indices.push(index);
                    ci.push(index);
                }
                Some((pattern, _)) if pattern.homoglyph_variant => {
                    valid_always_active_indices.push(index);
                    plain_homoglyph.push(index);
                }
                Some(_) => {
                    valid_always_active_indices.push(index);
                    plain_other.push(index);
                }
                None => {
                    crate::telemetry::record_invalid_pattern_index_skip();
                    tracing::warn!(
                        index,
                        patterns = phase2_patterns.len(),
                        "phase-2 always-active prefilter received out-of-range pattern index; invalid index ignored before batch construction"
                    );
                }
            }
        }
        if valid_always_active_indices.is_empty() {
            return None;
        }
        // HS covers small chunks; RegexSet batches cover large/no-simd chunks.
        #[cfg(feature = "simd")]
        let hs = Phase2HsEngine::build(phase2_patterns, &valid_always_active_indices);
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
        let combined_gate =
            Self::build_combined_gate(phase2_patterns, &valid_always_active_indices);
        Some(Self {
            batches,
            ungated_indices,
            ci_gate: Self::build_gate_ac(&ci_gate_lits, true),
            plain_gate: Self::build_gate_ac(&plain_gate_lits, false),
            combined_gate,
            // Reuse the `hs` built above; both engines are always present so
            // `mark_matches` can size-dispatch between them.
            #[cfg(feature = "simd")]
            hs,
        })
    }

    /// The gate's skip path checks each non-anchorable always-active pattern with
    /// its own regex. That is recall-safe and cheap when the set is small, but if
    /// MOST always-active patterns were non-anchorable the skip path would run
    /// hundreds of individual regexes — worse than the one batched HS scan it
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
        // with its EXACT runtime matcher — byte-for-byte match-equivalent to the
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
                // the already-compiled regex — no recompile, no extra memory).
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
            // rounding error (every chunk now runs the full phase-2 body) — so
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
                // body runs), but Law 10 forbids a SILENT degrade — surface it.
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
    /// from that folded source — extracting from the unicode form would yield
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
            // ASCII chunks). `ascii_fold_src` must equal what `build_ascii_
            // alternate` compiles so the gate describes the running matcher.
            let folded: String = pattern
                .regex
                .as_str()
                .chars()
                .filter(char::is_ascii)
                .collect();
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
            let mut valid_indices = Vec::with_capacity(chunk.len());
            let mut srcs = Vec::with_capacity(chunk.len());
            for &index in chunk {
                let Some((pattern, _)) = phase2_patterns.get(index) else {
                    crate::telemetry::record_invalid_pattern_index_skip();
                    tracing::warn!(
                        index,
                        patterns = phase2_patterns.len(),
                        "phase-2 RegexSet batch received out-of-range pattern index; dropping invalid index before building batch"
                    );
                    continue;
                };
                valid_indices.push(index);
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
                        Self::build_ascii_alternate(phase2_patterns, &valid_indices)
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
                                batch_size = valid_indices.len(),
                                case_insensitive,
                                %error,
                                "phase-2 RegexSet batch recompile failed; batch will run ungated (recall preserved)"
                            );
                            ungated_indices.extend_from_slice(&valid_indices);
                            continue;
                        }
                    };
                    let ascii_set_trunc = ascii_set
                        .as_ref()
                        .and_then(|_| {
                            Self::build_ascii_alternate_trunc(phase2_patterns, &valid_indices)
                        })
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
                        phase2_indices: valid_indices,
                        gateable: batch_gateable,
                        homoglyph_skippable: homoglyph,
                    });
                }
                Err(error) => {
                    tracing::warn!(
                        batch_size = valid_indices.len(),
                        case_insensitive,
                        %error,
                        "phase-2 RegexSet batch compile failed; batch will run ungated (recall preserved)"
                    );
                    ungated_indices.extend_from_slice(&valid_indices);
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
            let Some((pattern, _)) = phase2_patterns.get(index) else {
                crate::telemetry::record_invalid_pattern_index_skip();
                tracing::warn!(
                    index,
                    patterns = phase2_patterns.len(),
                    truncate,
                    "ASCII-folded phase-2 RegexSet received out-of-range pattern index; folded alternate disabled"
                );
                return None;
            };
            let source: String = pattern
                .regex
                .as_str()
                .chars()
                .filter(char::is_ascii)
                .collect();
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
    /// `localize_plain`: the caller (the shared-anchor path) handles the plain
    /// (homoglyph) patterns on pure-ASCII chunks via the localized AC, so they
    /// are SKIPPED here (no whole-chunk RegexSet pass). When false, plain
    /// batches run their ASCII-folded alternate (the order-preserving fold) —
    /// the safety-net path that is always recall-correct.
    pub(crate) fn mark_matches(
        &self,
        match_text: &str,
        scratch: &mut ActivePatternsScratch,
        localize_plain: bool,
        tuning: &ScannerTuning,
    ) {
        record_mark_call();
        // SWE-101 no-candidate gate (the user's #1 issue: "phase-2 must NEVER
        // eat runtime — not 0.000000001s"). The per-pattern body below — the HS
        // `scan_each` enumeration + its HS-incompatible whole-chunk-regex loop, or
        // the `regex::RegexSet` batch loop — ran UNCONDITIONALLY on every chunk
        // (~10µs/chunk × 518k chunks ≈ 5.3s of pure no-candidate overhead).
        // `combined_gate.anchor_present` is the ONE fast combined prefilter: an
        // exact first-bigram prescreen before one `ascii_case_insensitive`
        // Aho-Corasick over the ANCHORABLE always-active patterns'
        // required-prefix literals. On a PURE-ASCII chunk where it finds none, no
        // anchorable pattern can fire, so the whole body is skipped; only the small
        // NON-anchorable set (patterns that can match with no required literal) is
        // checked, each with its OWN regex, marking exactly those that match — the
        // same active set the full body would produce for them. Findings are
        // unchanged (recall-neutral), pinned by `phase2_no_candidate_zero_work` +
        // the HS/RegexSet findings-parity gates. ASCII-only: the folded plain literals
        // describe the homoglyph matcher only on ASCII text. A non-ASCII chunk, a
        // degraded build (`None`), or a real candidate fall through to the full
        // body — never a silent skip (Law 10).
        if tuning.no_candidate_gate_enabled() {
            if let Some(gate) = &self.combined_gate {
                if match_text.is_ascii() && !gate.anchor_present(match_text) {
                    // No anchorable pattern can fire; mark only the non-anchorable
                    // patterns that actually match (precise, recall-identical).
                    gate.mark_non_anchorable(match_text, scratch);
                    record_mark_gate_skip();
                    return;
                }
            }
        }
        // Past the gate: a candidate is possible, so the per-pattern marking body
        // below is real work, not no-candidate overhead.
        record_mark_perpattern_work();
        // SIMD fast path: one Hyperscan scan replaces the whole-chunk RegexSet
        // batch loop below (the measured #1 scan cost). `localize_plain` is a
        // RegexSet-batch optimization (skip plain batches the shared-anchor AC
        // covers); the HS path marks the full matching set instead — a sound
        // SUPERSET (eligible patterns still route through the AC+verify path,
        // non-eligible through whole-chunk extraction), proven findings-identical.
        #[cfg(feature = "simd")]
        if let Some(hs) = &self.hs {
            // Size-dispatch: HS wins on SMALL chunks (its near-constant per-scan
            // cost beats the RegexSet's per-call lazy-DFA setup), but its unicode
            // automaton over MANY bytes loses to the folded/truncated RegexSet on
            // large chunks. Above the threshold, fall through to the batches.
            if tuning.phase2_hs_enabled() && match_text.len() <= tuning.hs_prefilter_max_len() {
                let _ = localize_plain; // LAW10: unused-binding marker (signature/borrowck/cfg/compile-time assert); no runtime effect, not a fallback
                match hs.mark(match_text, scratch) {
                    Ok(()) => return,
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            "HS always-active prefilter failed; using RegexSet path for this chunk"
                        );
                    }
                }
            }
        }
        let use_ascii = tuning.homoglyph_gate_enabled() && match_text.is_ascii();

        // Prefix-literal skip gate (KH decode-recursion lever). A `gateable`
        // batch's patterns ALL provably require one of their prefix literals; if
        // the combined Aho-Corasick over those literals finds NONE in the chunk,
        // the batch cannot produce a single match and its whole-chunk RegexSet
        // pass is skipped. `is_match` early-exits at the first literal, so the
        // full O(text) scan only happens on chunks that have none — exactly the
        // skip case (the dominant decode-recursion sub-chunk shape, and most
        // low-density source). `present == true` means "run gateable batches as
        // before" — recall is identical, only dead work is removed.
        let gate_on = tuning.phase2_prefix_gate_enabled();
        // ci batches run `set` on every chunk -> the ci gate applies always.
        let ci_present = !gate_on
            || self
                .ci_gate
                .as_ref()
                .is_none_or(|ac| ac.is_match(match_text));
        // plain batches are gated only on the ASCII path (the folded-literal gate
        // describes the folded matcher); on a non-ASCII chunk the unicode `set`
        // runs unconditionally, so `plain_present` is forced true there.
        let plain_present = !gate_on
            || !use_ascii
            || self
                .plain_gate
                .as_ref()
                .is_none_or(|ac| ac.is_match(match_text));

        let prof = phase2_pattern_prof_enabled();
        if prof {
            GATE_CALLS.fetch_add(1, Relaxed);
        }
        // Truncated (lazy-DFA) marking sets: a sound SUPERSET — over-marks at
        // most, extraction with the full pattern filters. The win is keeping the
        // RegexSet off PikeVM on `{N,}` bodies.
        let truncate = tuning.prefilter_truncate_enabled();
        let ascii = match_text.is_ascii();
        for batch in &self.batches {
            let is_plain = batch.ascii_set.is_some();
            // A HOMOGLYPH-variant batch on a pure-ASCII chunk: skip entirely. Each
            // variant's base ASCII prefix is in the AC/confirmed path
            // (compiler_build.rs pushes both) AND that path now CONFIRMS it even
            // when the literal is shadowed by a longer one, because phase-1 marks
            // triggers with OVERLAPPING AC matching (collect_triggered_patterns_cpu)
            // — the missing half that previously let the always-active variant be
            // the sole matcher for e.g. generic-password on `client_secret="…"`. A
            // chunk with no non-ASCII bytes has no homoglyph for the variant to
            // catch, so on ASCII it adds nothing the base AC doesn't. This removes
            // the dominant `phase2:prefilter` cost on all-ASCII source (~13% of scan).
            // Proven recall-neutral by `homoglyph_ascii_skip_parity_default` (now a
            // live gate, not `#[ignore]`). Generic/case-sensitive plain fallbacks
            // (no base AC) are in non-skippable batches and are unaffected.
            if batch.homoglyph_skippable && ascii && tuning.homoglyph_ascii_skip_enabled() {
                continue;
            }
            // Or: the caller's localizer covers this plain batch.
            if is_plain && localize_plain && use_ascii {
                continue;
            }
            // Skip a gateable batch whose required prefix literals are all absent.
            if batch.gateable {
                let present = if is_plain { plain_present } else { ci_present };
                if !present {
                    if prof {
                        GATE_BATCH_SKIPS.fetch_add(1, Relaxed);
                    }
                    continue;
                }
                if prof {
                    GATE_BATCH_RUNS.fetch_add(1, Relaxed);
                }
            }
            let set = match (
                truncate,
                use_ascii,
                &batch.ascii_set,
                &batch.ascii_set_trunc,
            ) {
                (true, true, Some(_), Some(ascii_trunc)) => ascii_trunc,
                (false, true, Some(ascii), _) => ascii,
                (true, _, _, _) => &batch.set_trunc,
                (false, _, _, _) => &batch.set,
            };
            for set_idx in set.matches(match_text).iter() {
                scratch.mark(batch.phase2_indices[set_idx]);
            }
        }
        for &index in &self.ungated_indices {
            scratch.mark(index);
        }
    }

    /// True iff ANY always-active pattern can fire on `match_text` — the BOOLEAN
    /// companion to [`mark_matches`](Self::mark_matches) for the no-phase-1-hit
    /// admission gate (`has_active_phase2_patterns_for_chunk`), which needs only
    /// "is the active set non-empty?", not the full marked set. Early-exits at the
    /// first active pattern; the marked set is the measured #1 scan cost and the
    /// gate would otherwise build it in full only to call `.is_empty()` (then have
    /// extraction build it AGAIN). Mirrors `mark_matches`'s engine dispatch with
    /// `localize_plain = false` (the gate runs `anchor_mode = false`): in the
    /// default config this computes EXACTLY the same active-set membership (HS marks
    /// the full set; no prune applies), so admission and extraction share one
    /// contract. It never applies the optional measurement-only prunes
    /// (`phase2_prefix_gate` / `homoglyph_ascii_skip`), so it answers over the
    /// marking SUPERSET except for the proven homoglyph ASCII skip — sound (it can
    /// never reject a chunk the scan would mark, so no finding is lost), at most
    /// over-admitting an inert chunk to the extraction that already filters it.
    ///
    /// Like `mark_matches`, it consults the cheap SWE-101 `combined_gate` first: on
    /// a pure-ASCII chunk where the combined required-literal AC finds nothing, NO
    /// always-active pattern can fire, so it returns `false` at AC-`is_match` cost
    /// instead of running the HS / RegexSet body — the admission gate then pays ~ns
    /// on the no-candidate chunks it is built to reject.
    ///
    /// Gated to its sole caller (`has_active_phase2_patterns_for_chunk`, the
    /// no-phase-1-hit admission gate that exists only on the `simd`/`gpu` phase-2
    /// tail) so non-`simd` profiles don't carry it as dead code (Law 11).
    #[cfg(any(feature = "simd", feature = "gpu"))]
    pub(crate) fn any_active_match(&self, match_text: &str, tuning: &ScannerTuning) -> bool {
        // Same no-candidate gate as `mark_matches`: on a pure-ASCII no-anchor chunk
        // no anchorable pattern can fire, so the active set is non-empty iff some
        // non-anchorable pattern matches — checked precisely with each pattern's
        // OWN regex, so the admission gate never over- or under-admits. The whole
        // check costs one exact first-bigram prescreen, one possible AC
        // `is_match`, and a handful of per-pattern `is_match` calls instead of
        // the full ~2,700-pattern HS/RegexSet scan.
        if tuning.no_candidate_gate_enabled() {
            if let Some(gate) = &self.combined_gate {
                if match_text.is_ascii() && !gate.anchor_present(match_text) {
                    return gate.any_non_anchorable_match(match_text);
                }
            }
        }
        // Patterns whose batch failed to compile run unconditionally on the full
        // marking path, so a chunk that reaches this point must be admitted.
        // Keep this AFTER the combined no-candidate gate: a pure-ASCII no-anchor
        // chunk can still be rejected exactly, because even ungated patterns with
        // required literals cannot match and non-anchorable ones are checked by
        // their own regexes in the gate.
        if !self.ungated_indices.is_empty() {
            return true;
        }
        #[cfg(feature = "simd")]
        if let Some(hs) = &self.hs {
            if tuning.phase2_hs_enabled() && match_text.len() <= tuning.hs_prefilter_max_len() {
                match hs.any_match(match_text) {
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
        // RegexSet reference path (HS absent / over the size gate): the active
        // set is non-empty iff some batch's set matches. `is_match` early-exits
        // at the first matching pattern within the batch.
        let truncate = tuning.prefilter_truncate_enabled();
        let ascii = match_text.is_ascii();
        let use_ascii = tuning.homoglyph_gate_enabled() && ascii;
        for batch in &self.batches {
            if batch.homoglyph_skippable && ascii && tuning.homoglyph_ascii_skip_enabled() {
                continue;
            }
            let set = match (
                truncate,
                use_ascii,
                &batch.ascii_set,
                &batch.ascii_set_trunc,
            ) {
                (true, true, Some(_), Some(ascii_trunc)) => ascii_trunc,
                (false, true, Some(ascii), _) => ascii,
                (true, _, _, _) => &batch.set_trunc,
                (false, _, _, _) => &batch.set,
            };
            if set.is_match(match_text) {
                return true;
            }
        }
        false
    }
}
