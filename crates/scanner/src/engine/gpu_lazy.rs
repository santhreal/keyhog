use super::*;

impl CompiledScanner {
    /// Lazily compile the GPU literal-set on first call. Returns `None`
    /// when no compatible adapter was detected at probe time.
    ///
    /// Persists the compiled matcher to `~/.cache/keyhog/programs/<hash>.bin`.
    /// On a cache hit the matcher is loaded from disk and the GPU
    /// recompile is skipped entirely - biggest cold-start win on
    /// `keyhog scan` / `scan-system` runs that re-launch repeatedly.
    /// Cache misses (no file, version-mismatch, corrupt blob) silently
    /// recompile and re-cache.
    pub fn gpu_matcher(&self) -> Option<&vyre_libs::scan::GpuLiteralSet> {
        self.gpu_matcher
            .get_or_init(|| {
                let Some(literals) = &self.gpu_literals else {
                    return None;
                };
                let literal_refs: Vec<&[u8]> = literals.iter().map(|v| v.as_slice()).collect();
                let cache_dir = super::gpu_cache::gpu_matcher_cache_dir()?;
                let cache_key = format!(
                    "lit-{}",
                    super::gpu_cache::gpu_matcher_cache_key(&literal_refs)
                );
                let started = std::time::Instant::now();
                // One-line lego-block cache wiring courtesy of
                // `vyre_libs::scan::cached_load_or_compile`. The
                // helper handles atomic-rename, stale-blob deletion,
                // and silent fall-through on cache-side I/O errors -
                // every behaviour the previous hand-rolled
                // load/save pair tried to match. We log compile cost
                // here so the operator can still see warm-vs-cold
                // start latency in `--verbose` output.
                let matcher =
                    vyre_libs::scan::cached_load_or_compile(&cache_dir, &cache_key, || {
                        vyre_libs::scan::GpuLiteralSet::compile(&literal_refs)
                    });
                tracing::debug!(
                    target: "keyhog::routing",
                    patterns = literal_refs.len(),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "GpuLiteralSet ready (warm cache or compiled)"
                );
                Some(matcher)
            })
            .as_ref()
    }

    /// Lazily build the Aho-Corasick bounded-ranges dispatch Program
    /// from the GpuLiteralSet's CompiledDfa. The two engines share the
    /// same DFA - only the dispatch Program (and therefore the
    /// per-byte algorithm) differs:
    ///
    /// * `gpu_matcher().program` - `build_literal_set_program`:
    ///   walks every pattern × every literal byte per haystack
    ///   position. `O(N × L) per byte`. Works for any pattern set
    ///   that fits the DFA budget.
    /// * `ac_gpu_program()` - `classic_ac_bounded_ranges_program`:
    ///   walks the AC transition table forward `L_max` bytes per
    ///   position, emits every pattern in the accepting state's
    ///   flat output_links. `O(L_max) per byte` regardless of N.
    ///
    /// Selected at scan time via `KEYHOG_GPU_KERNEL=ac`. Returns
    /// `None` when no GPU matcher is available; callers fall through
    /// to the literal-set path or non-GPU backend.
    ///
    /// Cap of `super::rule_pipeline::AC_GPU_MAX_MATCHES_PER_DISPATCH` triples per shard
    /// dispatch matches the existing literal-set output-buffer cap.
    /// Truncation (count > cap on readback) is handled by the same
    /// fall-back-to-CPU branch the literal-set path uses.
    pub fn ac_gpu_program(&self) -> Option<&vyre::Program> {
        self.ac_gpu_program
            .get_or_init(|| {
                let matcher = self.gpu_matcher()?;
                let pattern_count = matcher.pattern_lengths.len() as u32;
                // Pick the match-append strategy. The subgroup form
                // (subgroup_ballot + subgroup_shuffle producing
                // _vyre_match_leader) was originally gated to wgpu
                // only because vyre-driver-cuda rejects it during
                // canonical pre-emit lowering. Runtime testing on
                // Apple Silicon M4 Pro with vyre v0.4.2 confirmed
                // the SAME "_vyre_match_leader referenced before
                // binding" rejection on the wgpu path: the lowering
                // gap is in vyre's substrate-neutral pre-emit step,
                // not the driver-specific emitter. Until the IR gap
                // is closed, use_subgroup_coalesce stays false on
                // every backend. We lose the ~32x atomic-contention
                // reduction the subgroup form would have provided
                // (Innovation I.17), but recall and correctness are
                // preserved; the plain append_match path produces
                // bit-identical match output, just with more atomic
                // pressure on the shared count buffer.
                let backend_id = self.gpu_backend.as_ref().map(|b| b.id()).unwrap_or("none");
                let use_subgroup_coalesce = false;
                let program = vyre_libs::scan::classic_ac::build_ac_bounded_ranges_program_ext(
                    &matcher.dfa,
                    pattern_count,
                    super::rule_pipeline::AC_GPU_MAX_MATCHES_PER_DISPATCH,
                    use_subgroup_coalesce,
                );
                tracing::debug!(
                    target: "keyhog::routing",
                    pattern_count,
                    state_count = matcher.dfa.state_count,
                    max_pattern_len = matcher.dfa.max_pattern_len,
                    backend = backend_id,
                    use_subgroup_coalesce,
                    "AC GPU dispatch Program built"
                );
                Some(program)
            })
            .as_ref()
    }

    /// Lazily compile the regex-NFA `RulePipeline` on first call.
    /// Returns `None` once the OnceLock has fired when the regex
    /// compile failed - typically because the combined NFA exceeds
    /// vyre's per-subgroup state cap (`LANES * 32`) or because one
    /// of the detector regexes uses a feature the byte-NFA frontend
    /// can't represent (Unicode classes, lookaround, backrefs).
    /// Callers should fall back to the literal-set GPU dispatch on
    /// `None`.
    ///
    /// Pipeline is sized for [`super::rule_pipeline::megascan_input_len()`] bytes; batches
    /// larger than that must take a different path. The orchestrator
    /// caps batches at the same value (256 MiB default, up to 1 GiB
    /// on 24+ GiB-VRAM cards) so this matches normal scan flow.
    pub fn rule_pipeline(&self) -> Option<&vyre_libs::scan::RulePipeline> {
        self.rule_pipeline
            .get_or_init(|| {
                let pattern_strs: Vec<&str> = self
                    .ac_map
                    .iter()
                    .map(|p| p.regex.as_str())
                    .chain(self.fallback.iter().map(|(p, _)| p.regex.as_str()))
                    .collect();
                if pattern_strs.is_empty() {
                    return None;
                }
                let started = std::time::Instant::now();
                let input_cap = super::rule_pipeline::megascan_input_len();
                match super::rule_pipeline::rule_pipeline_cached(&pattern_strs, input_cap as u32) {
                    Ok(pipe) => {
                        tracing::info!(
                            target: "keyhog::routing",
                            patterns = pattern_strs.len(),
                            input_len = input_cap,
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "MegaScan RulePipeline compiled"
                        );
                        Some(pipe)
                    }
                    Err(error) => {
                        // Demoted from `warn` to `debug` - the
                        // fallback to literal-set GPU dispatch is the
                        // designed degradation when vyre's byte-NFA
                        // frontend can't represent every pattern (e.g.
                        // lookaround in pattern 990 of the bundled
                        // detector corpus). The user can't fix it, and
                        // hitting this WARN once per `--backend mega-
                        // scan` invocation creates noise without
                        // signal. kimi-dogfood-3 #138.
                        tracing::debug!(
                            patterns = pattern_strs.len(),
                            error = %format!("{error:?}"),
                            "MegaScan RulePipeline compile failed - falling back to literal-set GPU dispatch. \
                             Common causes: regex set exceeds vyre's per-subgroup state cap, or one or more \
                             patterns use Unicode classes / lookaround / backrefs that the byte-NFA frontend \
                             can't represent."
                        );
                        None
                    }
                }
            })
            .as_ref()
    }

    /// Lazily build fused GPU decode→scan programs (base64 + hex).
    ///
    /// Returns `None` when no GPU matcher is available (no literals, no
    /// adapter). The fused programs share the same DFA transition tables
    /// as the literal-set engine but prepend an on-GPU decode stage,
    /// eliminating the CPU→GPU round-trip for encoded content.
    pub fn fused_decode_programs(
        &self,
    ) -> Option<&super::gpu_decode_scan::FusedDecodeScanPrograms> {
        self.fused_decode_programs
            .get_or_init(|| {
                let matcher = self.gpu_matcher()?;
                let state_count = matcher.dfa.state_count;
                let input_len = super::rule_pipeline::megascan_input_len() as u32;
                let programs = super::gpu_decode_scan::build_fused_programs(state_count, input_len);
                if programs.any_available() {
                    tracing::info!(
                        target: "keyhog::gpu",
                        base64 = programs.base64_program.is_some(),
                        hex = programs.hex_program.is_some(),
                        state_count,
                        input_len,
                        "fused decode+scan programs built"
                    );
                    Some(programs)
                } else {
                    tracing::debug!(
                        target: "keyhog::gpu",
                        "fused decode+scan programs not available - CPU decode path will be used"
                    );
                    None
                }
            })
            .as_ref()
    }
}
