//! `impl AlwaysActiveFallbackPrefilter`, extracted from `fallback.rs`. The
//! `AlwaysActiveFallbackPrefilter`/`PrefilterBatch` structs are defined in
//! `fallback.rs`; this is a satellite impl block (same pattern as
//! `fallback_compiled.rs`). Builds the RegexSet/Hyperscan batches and marks the
//! always-active set into the caller's scratch. Pure move, no behaviour change.
use super::fallback::*;
use super::fallback_truncate::truncate_for_prefilter;
use super::*;
use aho_corasick::AhoCorasick;
use std::sync::atomic::Ordering::Relaxed;
#[cfg(feature = "simd")]
use super::fallback_hs::HsFallbackEngine;

impl AlwaysActiveFallbackPrefilter {
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

    /// Build from the always-active fallback indices. Always returns `Some` for
    /// a non-empty input: patterns in batches that fail to compile fall into
    /// `ungated_indices` and run unconditionally, so the result is always
    /// recall-equivalent to running every always-active pattern.
    pub(crate) fn build(
        fallback: &[(CompiledPattern, Vec<String>)],
        always_active_indices: &[usize],
    ) -> Option<Self> {
        if always_active_indices.is_empty() {
            return None;
        }
        // The HS engine is the fast path for SMALL chunks; the `regex::RegexSet`
        // batches below stay as the LARGE-chunk path (HS's unicode-homoglyph
        // automaton over many bytes loses to the folded/truncated RegexSet) and
        // the no-`simd` fallback. `mark_matches` dispatches by chunk length, so
        // BOTH are load-bearing — the batches are not dead weight.
        #[cfg(feature = "simd")]
        let hs = HsFallbackEngine::build(fallback, always_active_indices);
        // Partition by regex flags so each batch is built match-equivalent to
        // its patterns' own compilation (case-insensitive detector regexes vs
        // plain homoglyph variants).
        // Partition by (a) regex case flags and (b) homoglyph-variant status, so
        // each batch is homogeneous: case-insensitive detector regexes; plain
        // homoglyph VARIANTS (skippable on ASCII — base AC covers them); and other
        // plain (generic/case-sensitive) fallbacks that have NO base AC pattern
        // and must run on every chunk.
        let mut ci: Vec<usize> = Vec::new();
        let mut plain_homoglyph: Vec<usize> = Vec::new();
        let mut plain_other: Vec<usize> = Vec::new();
        for &index in always_active_indices {
            match fallback.get(index) {
                Some((pattern, _)) if pattern.regex.is_case_insensitive() => ci.push(index),
                Some((pattern, _)) if pattern.homoglyph_variant => plain_homoglyph.push(index),
                Some(_) => plain_other.push(index),
                // Out-of-range index (shouldn't happen): run it unconditionally.
                None => {}
            }
        }
        let mut batches = Vec::new();
        let mut ungated_indices = Vec::new();
        let mut ci_gate_lits: Vec<Vec<u8>> = Vec::new();
        let mut plain_gate_lits: Vec<Vec<u8>> = Vec::new();
        Self::build_partition(
            fallback,
            &ci,
            true,
            false,
            &mut batches,
            &mut ungated_indices,
            &mut ci_gate_lits,
        );
        Self::build_partition(
            fallback,
            &plain_other,
            false,
            false,
            &mut batches,
            &mut ungated_indices,
            &mut plain_gate_lits,
        );
        Self::build_partition(
            fallback,
            &plain_homoglyph,
            false,
            true,
            &mut batches,
            &mut ungated_indices,
            &mut plain_gate_lits,
        );
        Some(Self {
            batches,
            ungated_indices,
            ci_gate: Self::build_gate_ac(&ci_gate_lits, true),
            plain_gate: Self::build_gate_ac(&plain_gate_lits, false),
            // Reuse the `hs` built above; both engines are always present so
            // `mark_matches` can size-dispatch between them.
            #[cfg(feature = "simd")]
            hs,
        })
    }

    /// Compute a pattern's gate-eligible required-prefix literals for the given
    /// case partition. Plain (homoglyph) patterns are matched on the ASCII path
    /// via their ASCII-FOLDED form, so their prefix literals must be extracted
    /// from that folded source — extracting from the unicode form would yield
    /// non-ASCII members that never appear in folded matching. `None` => the
    /// pattern is NOT gate-eligible and must run unconditionally.
    fn pattern_gate_literals(
        fallback: &[(CompiledPattern, Vec<String>)],
        index: usize,
        case_insensitive: bool,
    ) -> Option<Vec<Vec<u8>>> {
        let (pattern, _) = fallback.get(index)?;
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
        fallback: &[(CompiledPattern, Vec<String>)],
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
            if Self::pattern_gate_literals(fallback, i, case_insensitive).is_some() {
                eligible.push(i);
            } else {
                other.push(i);
            }
        }
        // Ungateable patterns: always-run batches (gateable = false).
        Self::build_batches(
            fallback,
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
            fallback,
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
            for &idx in &batch.fallback_indices {
                if let Some(lits) = Self::pattern_gate_literals(fallback, idx, case_insensitive) {
                    gate_lits.extend(lits);
                }
            }
        }
    }

    /// Compile `indices` into RegexSet batches with the given `gateable` intent.
    /// A plain batch is only marked gateable when its `ascii_set` compiles (the
    /// folded matcher the gate describes); otherwise it downgrades to always-run.
    fn build_batches(
        fallback: &[(CompiledPattern, Vec<String>)],
        indices: &[usize],
        case_insensitive: bool,
        gateable: bool,
        homoglyph: bool,
        batches: &mut Vec<PrefilterBatch>,
        ungated_indices: &mut Vec<usize>,
    ) {
        for chunk in indices.chunks(Self::BATCH_SIZE) {
            let srcs: Vec<&str> = chunk
                .iter()
                .filter_map(|&i| fallback.get(i).map(|(p, _)| p.regex.as_str()))
                .collect();
            let built = Self::compile_set(&srcs, case_insensitive);
            match built {
                Ok(set) => {
                    let ascii_set = if case_insensitive {
                        None
                    } else {
                        Self::build_ascii_alternate(fallback, chunk)
                    };
                    // Truncated SUPERSET variants (lazy-DFA-friendly): each entry
                    // through `truncate_for_prefilter` (fallback to verbatim), SAME
                    // order. If the truncated set fails to compile, reuse the full
                    // set (truncation is a perf opt, never a correctness need).
                    let trunc_srcs: Vec<String> = srcs
                        .iter()
                        .map(|s| truncate_for_prefilter(s).unwrap_or_else(|| s.to_string()))
                        .collect();
                    let set_trunc = match Self::compile_set_owned(&trunc_srcs, case_insensitive) {
                        Some(trunc) => trunc,
                        // Truncated form failed to compile: reuse the full set as
                        // the (sound-superset) trunc gate by recompiling it — it
                        // already compiled above as `set`. If even that anomalously
                        // fails, never unwrap in production: degrade this batch to
                        // always-run (ungated) so a compile anomaly costs perf, not
                        // recall.
                        None => match Self::compile_set(&srcs, case_insensitive) {
                            Ok(full) => full,
                            Err(_) => {
                                ungated_indices.extend_from_slice(chunk);
                                continue;
                            }
                        },
                    };
                    let ascii_set_trunc = ascii_set
                        .as_ref()
                        .and_then(|_| Self::build_ascii_alternate_trunc(fallback, chunk))
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
                        fallback_indices: chunk.to_vec(),
                        gateable: batch_gateable,
                        homoglyph_skippable: homoglyph,
                    });
                }
                Err(_) => ungated_indices.extend_from_slice(chunk),
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

    fn compile_set_owned(srcs: &[String], case_insensitive: bool) -> Option<regex::RegexSet> {
        regex::RegexSetBuilder::new(srcs)
            .case_insensitive(case_insensitive)
            .size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
            .dfa_size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
            .crlf(case_insensitive)
            .build()
            .ok()
    }

    /// Build the combined skip-gate Aho-Corasick over `literals`. `ci` selects
    /// ASCII case-insensitive matching (for the detector-regex partition).
    /// `None` when there are no literals to gate on.
    fn build_gate_ac(literals: &[Vec<u8>], ci: bool) -> Option<AhoCorasick> {
        if literals.is_empty() {
            return None;
        }
        AhoCorasick::builder()
            .ascii_case_insensitive(ci)
            .build(literals)
            .ok()
    }

    /// Build the ASCII-folded alternate RegexSet for a plain (homoglyph) batch:
    /// each homoglyph regex with every non-ASCII codepoint removed, in the SAME
    /// entry order. Match-equivalent to the unicode form on pure-ASCII text.
    /// `None` if any fold fails to compile (the unicode set is used instead).
    fn build_ascii_alternate(
        fallback: &[(CompiledPattern, Vec<String>)],
        indices: &[usize],
    ) -> Option<regex::RegexSet> {
        let folded: Vec<String> = indices
            .iter()
            .filter_map(|&i| fallback.get(i))
            .map(|(p, _)| p.regex.as_str().chars().filter(char::is_ascii).collect())
            .collect();
        if folded.len() != indices.len() {
            return None;
        }
        regex::RegexSetBuilder::new(&folded)
            .case_insensitive(false)
            .size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
            .dfa_size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
            .build()
            .ok()
    }

    /// As `build_ascii_alternate`, but each folded source is additionally passed
    /// through `truncate_for_prefilter` (truncate the FOLDED form so the matcher
    /// that runs on ASCII text stays on the lazy-DFA). SAME entry order; `None`
    /// if any fold or the truncated set fails to compile.
    fn build_ascii_alternate_trunc(
        fallback: &[(CompiledPattern, Vec<String>)],
        indices: &[usize],
    ) -> Option<regex::RegexSet> {
        let folded: Vec<String> = indices
            .iter()
            .filter_map(|&i| fallback.get(i))
            .map(|(p, _)| {
                let f: String = p.regex.as_str().chars().filter(char::is_ascii).collect();
                truncate_for_prefilter(&f).unwrap_or(f)
            })
            .collect();
        if folded.len() != indices.len() {
            return None;
        }
        regex::RegexSetBuilder::new(&folded)
            .case_insensitive(false)
            .size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
            .dfa_size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
            .build()
            .ok()
    }

    /// Mark every always-active fallback whose regex can match `match_text`.
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
    ) {
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
            if fallback_hs_enabled() && match_text.len() <= hs_prefilter_max_len() {
                let _ = localize_plain;
                hs.mark(match_text, scratch);
                return;
            }
        }
        let use_ascii = homoglyph_gate_enabled() && match_text.is_ascii();

        // Prefix-literal skip gate (KH decode-recursion lever). A `gateable`
        // batch's patterns ALL provably require one of their prefix literals; if
        // the combined Aho-Corasick over those literals finds NONE in the chunk,
        // the batch cannot produce a single match and its whole-chunk RegexSet
        // pass is skipped. `is_match` early-exits at the first literal, so the
        // full O(text) scan only happens on chunks that have none — exactly the
        // skip case (the dominant decode-recursion sub-chunk shape, and most
        // low-density source). `present == true` means "run gateable batches as
        // before" — recall is identical, only dead work is removed.
        let gate_on = fallback_prefix_gate_enabled();
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

        let prof = fallback_pat_prof_enabled();
        if prof {
            GATE_CALLS.fetch_add(1, Relaxed);
        }
        // Truncated (lazy-DFA) marking sets: a sound SUPERSET — over-marks at
        // most, extraction with the full pattern filters. The win is keeping the
        // RegexSet off PikeVM on `{N,}` bodies.
        let truncate = prefilter_truncate_enabled();
        let ascii = match_text.is_ascii();
        for batch in &self.batches {
            let is_plain = batch.ascii_set.is_some();
            // A HOMOGLYPH-variant batch on a pure-ASCII chunk: skip entirely. Each
            // variant's base ASCII prefix is in the AC/confirmed path
            // (compiler_build.rs pushes both), and a chunk with no non-ASCII bytes
            // has no homoglyph for the variant to catch — so it adds nothing the
            // base AC doesn't. This removes the dominant `fb:prefilter` cost on
            // all-ASCII source. Proven recall-neutral by `homoglyph_ascii_skip_parity`.
            // Generic/case-sensitive plain fallbacks (no base AC) are in
            // non-skippable batches and are unaffected.
            if batch.homoglyph_skippable && ascii && homoglyph_ascii_skip_enabled() {
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
                scratch.mark(batch.fallback_indices[set_idx]);
            }
        }
        for &index in &self.ungated_indices {
            scratch.mark(index);
        }
    }
}
