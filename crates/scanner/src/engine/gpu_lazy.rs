use super::*;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

fn append_match_bound_slot(
    hits_buffer: &str,
    count_buffer: &str,
    tag: impl Into<Expr>,
    start: impl Into<Expr>,
    end: impl Into<Expr>,
) -> Node {
    let slot_name = "_keyhog_match_slot";
    let max_hits = Expr::div(Expr::buf_len(hits_buffer), Expr::u32(3));

    Node::block(vec![
        Node::let_bind(
            slot_name,
            Expr::atomic_add(count_buffer, Expr::u32(0), Expr::u32(1)),
        ),
        Node::if_then(
            Expr::lt(Expr::var(slot_name), max_hits),
            vec![
                Node::store(
                    hits_buffer,
                    Expr::mul(Expr::var(slot_name), Expr::u32(3)),
                    tag.into(),
                ),
                Node::store(
                    hits_buffer,
                    Expr::add(Expr::mul(Expr::var(slot_name), Expr::u32(3)), Expr::u32(1)),
                    start.into(),
                ),
                Node::store(
                    hits_buffer,
                    Expr::add(Expr::mul(Expr::var(slot_name), Expr::u32(3)), Expr::u32(2)),
                    end.into(),
                ),
            ],
        ),
    ])
}

fn build_ac_bounded_ranges_program_bound_atomic(
    dfa: &vyre_libs::scan::dfa::CompiledDfa,
    pattern_count: u32,
    max_matches: u32,
) -> Option<Program> {
    let output_records_len = u32::try_from(dfa.output_records.len()).ok()?;
    let max_pattern_len = dfa.max_pattern_len.max(1);

    let haystack = "haystack";
    let transitions = "transitions";
    let output_offsets = "output_offsets";
    let output_records = "output_records";
    let pattern_lengths = "pattern_lengths";
    let haystack_len = "haystack_len";
    let match_count = "match_count";
    let matches = "matches";

    let i = Expr::var("i");
    let end = Expr::add(i.clone(), Expr::u32(1));
    let scan_start = Expr::select(
        Expr::lt(i.clone(), Expr::u32(max_pattern_len - 1)),
        Expr::u32(0),
        Expr::sub(end.clone(), Expr::u32(max_pattern_len)),
    );
    let (load_step_byte, step_byte) =
        vyre_libs::scan::builders::load_packed_byte(haystack, Expr::var("step"));

    let walk_body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::load(haystack_len, Expr::u32(0))),
            vec![
                Node::let_bind("state", Expr::u32(0)),
                Node::let_bind("scan_start", scan_start),
                Node::let_bind("scan_end", end),
                Node::loop_for(
                    "step",
                    Expr::var("scan_start"),
                    Expr::var("scan_end"),
                    vec![
                        load_step_byte,
                        Node::assign(
                            "state",
                            Expr::load(
                                transitions,
                                Expr::add(Expr::mul(Expr::var("state"), Expr::u32(256)), step_byte),
                            ),
                        ),
                    ],
                ),
                Node::let_bind("out_begin", Expr::load(output_offsets, Expr::var("state"))),
                Node::let_bind(
                    "out_end",
                    Expr::load(output_offsets, Expr::add(Expr::var("state"), Expr::u32(1))),
                ),
                Node::loop_for(
                    "out_idx",
                    Expr::var("out_begin"),
                    Expr::var("out_end"),
                    vec![
                        Node::let_bind(
                            "pattern_id",
                            Expr::load(output_records, Expr::var("out_idx")),
                        ),
                        Node::let_bind(
                            "pat_len",
                            Expr::load(pattern_lengths, Expr::var("pattern_id")),
                        ),
                        Node::let_bind(
                            "match_start",
                            Expr::select(
                                Expr::lt(Expr::var("scan_end"), Expr::var("pat_len")),
                                Expr::u32(0),
                                Expr::sub(Expr::var("scan_end"), Expr::var("pat_len")),
                            ),
                        ),
                        append_match_bound_slot(
                            matches,
                            match_count,
                            Expr::var("pattern_id"),
                            Expr::var("match_start"),
                            Expr::var("scan_end"),
                        ),
                    ],
                ),
            ],
        ),
    ];

    Some(Program::wrapped(
        vec![
            BufferDecl::storage(haystack, 0, BufferAccess::ReadOnly, DataType::U32),
            BufferDecl::storage(transitions, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(dfa.state_count.saturating_mul(256)),
            BufferDecl::storage(output_offsets, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(dfa.state_count.saturating_add(1)),
            BufferDecl::storage(output_records, 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(output_records_len),
            BufferDecl::storage(pattern_lengths, 4, BufferAccess::ReadOnly, DataType::U32)
                .with_count(pattern_count),
            BufferDecl::storage(haystack_len, 5, BufferAccess::ReadOnly, DataType::U32)
                .with_count(1),
            BufferDecl::read_write(match_count, 6, DataType::U32).with_count(1),
            BufferDecl::output(matches, 7, DataType::U32).with_count(max_matches.saturating_mul(3)),
        ],
        [128, 1, 1],
        vec![vyre_libs::region::wrap_anonymous(
            "keyhog::matching::classic_ac_bounded_ranges",
            walk_body,
        )],
    ))
}

/// Tracks whether the subgroup-coalesced match-append form
/// (subgroup_ballot + subgroup_shuffle -> `_vyre_match_leader`) is
/// enabled for the AC GPU dispatch Program. Held forced-off because
/// vyre's substrate-neutral pre-emit lowering rejects that form on
/// every backend (CUDA and wgpu both: "_vyre_match_leader referenced
/// before binding", Innovation I.17). This is a named, greppable
/// dead-path marker rather than a silent inline `false`: once the
/// vyre IR gap is closed, flipping this to `true` re-enables the
/// ~32x atomic-contention reduction on the shared match-count buffer
/// across every backend in one place. The interim contention win
/// (per-workgroup local reduction -> one atomic add per group) lives
/// in the kernel builder, not here.
const AC_GPU_SUBGROUP_COALESCE: bool = false;

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
                let use_subgroup_coalesce = AC_GPU_SUBGROUP_COALESCE;
                let program = if use_subgroup_coalesce {
                    vyre_libs::scan::classic_ac::build_ac_bounded_ranges_program_ext(
                        &matcher.dfa,
                        pattern_count,
                        super::rule_pipeline::AC_GPU_MAX_MATCHES_PER_DISPATCH,
                        true,
                    )
                } else {
                    build_ac_bounded_ranges_program_bound_atomic(
                        &matcher.dfa,
                        pattern_count,
                        super::rule_pipeline::AC_GPU_MAX_MATCHES_PER_DISPATCH,
                    )?
                };
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
}
