//! Classic Aho-Corasick scanner with flat `output_links`.
//!
//! Unlike the single-accept DFA in `super::dfa::dfa_compile`, this
//! module precomputes **all** pattern ids that match at each state
//! (including patterns reachable via failure links) into a flat
//! `output_offsets` + `output_records` array.  At scan time the
//! match loop is **O(matches)**, not **O(states × n)**.
//!
//! Build-time complexity is still dominated by the dense transition
//! table (O(states × alphabet)), but the per-state pattern list is
//! built in one BFS pass using dynamic programming on the failure
//! links.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::region::wrap_anonymous;
use crate::scan::builders::{append_match_subgroup, load_packed_byte};
use crate::scan::dfa::{dfa_compile, CompiledDfa};

/// A classic AC automaton with precomputed flat output links.
///
/// Wraps a [`CompiledDfa`] and exposes the Reference oracle scan plus
/// a vyre IR Program for GPU dispatch.
#[derive(Debug, Clone)]
pub struct ClassicAcAutomaton {
    /// Underlying compiled DFA (transitions + flat output links).
    pub dfa: CompiledDfa,
}

/// Build a [`ClassicAcAutomaton`] from a list of byte patterns.
///
/// # Panics
///
/// Panics with an actionable message on DFA budget exhaustion.
/// Use `super::dfa::dfa_compile_with_budget` for structured
/// error handling.
#[must_use]
pub fn classic_ac_compile(patterns: &[&[u8]]) -> ClassicAcAutomaton {
    let dfa = dfa_compile(patterns);
    ClassicAcAutomaton { dfa }
}

/// Reference oracle: walk the DFA byte-by-byte and emit **every**
/// pattern id that matches at each offset.
///
/// Returns a vector of `(pattern_id, end_offset)` pairs.  `end_offset`
/// is the byte position (0-based, inclusive) where the match ends.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn classic_ac_scan(ac: &ClassicAcAutomaton, haystack: &[u8]) -> Vec<(u32, u32)> {
    let dfa = &ac.dfa;
    let mut state = 0u32;
    let mut out = Vec::new();
    for (pos, &b) in haystack.iter().enumerate() {
        state = dfa.transitions[(state as usize) * 256 + (b as usize)];
        let begin = dfa.output_offsets[state as usize] as usize;
        let end = dfa.output_offsets[state as usize + 1] as usize;
        for &pattern_id in &dfa.output_records[begin..end] {
            out.push((pattern_id, pos as u32));
        }
    }
    out
}

/// Reference oracle that returns a per-position **count** of matches.
///
/// `counts[i]` = number of patterns that match ending at byte `i`.
/// This is the oracle shape used by the companion GPU emit when the
/// caller only needs cardinality, not the individual pattern ids.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn classic_ac_scan_counts(ac: &ClassicAcAutomaton, haystack: &[u8]) -> Vec<u32> {
    let dfa = &ac.dfa;
    let mut state = 0u32;
    let mut out = Vec::with_capacity(haystack.len());
    for &b in haystack {
        state = dfa.transitions[(state as usize) * 256 + (b as usize)];
        let begin = dfa.output_offsets[state as usize] as usize;
        let end = dfa.output_offsets[state as usize + 1] as usize;
        out.push((end - begin) as u32);
    }
    out
}

/// Build a vyre `Program` that scans `haystack` and appends every
/// matching pattern id to `matches` via an atomic slot counter.
///
/// Buffers (bindings 0..5):
///
/// | binding | name | access | count |
/// |---|---|---|---|
/// | 0 | `haystack` | ReadOnly | `haystack_len` |
/// | 1 | `transitions` | ReadOnly | `state_count * 256` |
/// | 2 | `output_offsets` | ReadOnly | `state_count + 1` |
/// | 3 | `output_records` | ReadOnly | `output_records_len` |
/// | 4 | `match_count` | ReadWrite | 1 (atomic) |
/// | 5 | `matches` | ReadWrite | `max_matches` |
///
/// Each invocation `i` replays the DFA from state 0 through
/// `haystack[0..=i]`, then atomically claims slots in `matches` and
/// writes every pattern id for the final state.
///
/// The serial replay is still O(n²) total work  -  the fix here is
/// the **match-emission loop**, which is O(matches) thanks to the
/// flat `output_links`.
#[must_use]
pub fn classic_ac_program(
    haystack: &str,
    transitions: &str,
    output_offsets: &str,
    output_records: &str,
    match_count: &str,
    matches: &str,
    haystack_len: u32,
    state_count: u32,
    output_records_len: u32,
    max_matches: u32,
) -> Program {
    let i = Expr::var("i");

    // body executed per invocation i:
    //   walk DFA from 0 through haystack[0..=i]
    //   for each pattern in output_links[state]:
    //       slot = atomic_add(match_count, 0, 1)
    //       if slot < max_matches:
    //           matches[slot] = pattern_id
    let walk_body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::buf_len(haystack)),
            vec![
                // Walk the automaton from state 0 through haystack[0..=i].
                Node::let_bind("state", Expr::u32(0)),
                Node::loop_for(
                    "step",
                    Expr::u32(0),
                    Expr::add(Expr::var("i"), Expr::u32(1)),
                    vec![Node::assign(
                        "state",
                        Expr::load(
                            transitions,
                            Expr::add(
                                Expr::mul(Expr::var("state"), Expr::u32(256)),
                                Expr::load(haystack, Expr::var("step")),
                            ),
                        ),
                    )],
                ),
                // Emit every pattern in the flat output_links[state].
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
                            "slot",
                            Expr::atomic_add(match_count, Expr::u32(0), Expr::u32(1)),
                        ),
                        Node::if_then(
                            Expr::lt(Expr::var("slot"), Expr::u32(max_matches)),
                            vec![Node::Store {
                                buffer: matches.into(),
                                index: Expr::var("slot"),
                                value: Expr::var("pattern_id"),
                            }],
                        ),
                    ],
                ),
            ],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(haystack, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(haystack_len),
            BufferDecl::storage(transitions, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(state_count.saturating_mul(256)),
            BufferDecl::storage(output_offsets, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(state_count.saturating_add(1)),
            BufferDecl::storage(output_records, 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(output_records_len),
            BufferDecl::storage(match_count, 4, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
            BufferDecl::storage(matches, 5, BufferAccess::ReadWrite, DataType::U32)
                .with_count(max_matches),
        ],
        [64, 1, 1],
        vec![wrap_anonymous("vyre-libs::matching::classic_ac", walk_body)],
    )
}

/// Build a Program that scans `haystack` for any AC match and emits
/// `(pattern_id, start, end)` triples through the canonical
/// [`append_match`] hit buffer. Pairs with
/// [`pack_haystack_u32`](crate::scan::dispatch_io::pack_haystack_u32):
/// each invocation `i` corresponds to byte position `i` of the
/// **unpacked** haystack, but loads from the packed u32 buffer via
/// [`load_packed_byte`].
///
/// Buffer layout (bindings 0..7):
///
/// | binding | name | access | element shape |
/// |---|---|---|---|
/// | 0 | `haystack`        | ReadOnly  | packed u32, 4 bytes / word |
/// | 1 | `transitions`     | ReadOnly  | `state_count * 256` u32    |
/// | 2 | `output_offsets`  | ReadOnly  | `state_count + 1` u32      |
/// | 3 | `output_records`  | ReadOnly  | `output_records_len` u32   |
/// | 4 | `pattern_lengths` | ReadOnly  | `pattern_count` u32        |
/// | 5 | `haystack_len`    | ReadOnly  | 1 u32 (byte length)        |
/// | 6 | `match_count`     | ReadWrite | 1 u32 (atomic)             |
/// | 7 | `matches`         | Output    | `max_matches * 3` u32      |
///
/// Each invocation `i` replays the suffix window
/// `haystack[max(0, i+1-max_pattern_len)..=i]` from state 0, then
/// emits every `(pid, start, end)` triple that accepts at `i`. The
/// scan window cap is the only difference from the unbounded walk:
/// `max_pattern_len` must be greater than or equal to the longest
/// entry in `pattern_lengths`, or matches longer than the window are
/// invisible because the walk never sees their first byte.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn classic_ac_bounded_ranges_program(
    haystack: &str,
    transitions: &str,
    output_offsets: &str,
    output_records: &str,
    pattern_lengths: &str,
    haystack_len: &str,
    match_count: &str,
    matches: &str,
    state_count: u32,
    output_records_len: u32,
    pattern_count: u32,
    max_matches: u32,
    max_pattern_len: u32,
) -> Program {
    classic_ac_bounded_ranges_program_ext(
        haystack,
        transitions,
        output_offsets,
        output_records,
        pattern_lengths,
        haystack_len,
        match_count,
        matches,
        state_count,
        output_records_len,
        pattern_count,
        max_matches,
        max_pattern_len,
        true,
    )
}

/// Variant of [`classic_ac_bounded_ranges_program`] with explicit
/// control over the match-append strategy.
///
/// Set `use_subgroup_coalesce = true` for `append_match_subgroup`
/// (Innovation I.17, one atomic per subgroup leader, the default).
/// Set `false` for the simpler `append_match` (one atomic per lane
/// per hit). Use the `false` variant on backends whose IR lowering
/// can't yet emit `subgroup_ballot`/`subgroup_shuffle`  -  currently
/// `vyre-driver-cuda` rejects the subgroup form during canonical
/// pre-emit lowering ("variable `_vyre_match_leader` is referenced
/// before binding"), so callers that route through CUDA must opt
/// out until that path lands.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn classic_ac_bounded_ranges_program_ext(
    haystack: &str,
    transitions: &str,
    output_offsets: &str,
    output_records: &str,
    pattern_lengths: &str,
    haystack_len: &str,
    match_count: &str,
    matches: &str,
    state_count: u32,
    output_records_len: u32,
    pattern_count: u32,
    max_matches: u32,
    max_pattern_len: u32,
    use_subgroup_coalesce: bool,
) -> Program {
    let max_pattern_len = max_pattern_len.max(1);
    let i = Expr::var("i");
    let end = Expr::add(i.clone(), Expr::u32(1));
    let scan_start = Expr::select(
        Expr::lt(i.clone(), Expr::u32(max_pattern_len - 1)),
        Expr::u32(0),
        Expr::sub(end.clone(), Expr::u32(max_pattern_len)),
    );

    let (load_step_byte, step_byte) = load_packed_byte(haystack, Expr::var("step"));

    let walk_body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::load(haystack_len, Expr::u32(0))),
            vec![
                Node::let_bind("state", Expr::u32(0)),
                Node::let_bind("scan_start", scan_start),
                Node::let_bind("scan_end", end.clone()),
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
                Node::loop_for("out_idx", Expr::var("out_begin"), Expr::var("out_end"), {
                    let mut body = vec![
                        Node::let_bind(
                            "pattern_id",
                            Expr::load(output_records, Expr::var("out_idx")),
                        ),
                        Node::let_bind(
                            "pat_len",
                            Expr::load(pattern_lengths, Expr::var("pattern_id")),
                        ),
                        // start = (i + 1) - pat_len, saturating at 0.
                        Node::let_bind(
                            "match_start",
                            Expr::select(
                                Expr::lt(Expr::var("scan_end"), Expr::var("pat_len")),
                                Expr::u32(0),
                                Expr::sub(Expr::var("scan_end"), Expr::var("pat_len")),
                            ),
                        ),
                    ];
                    if use_subgroup_coalesce {
                        // Subgroup-coalesced match append (Innovation I.17):
                        // ONE atomic_add per subgroup leader instead of
                        // `subgroup_size` separate atomics. Wgpu emits this
                        // natively; CUDA cannot lower it yet (see the
                        // `use_subgroup_coalesce` rationale on
                        // `classic_ac_bounded_ranges_program_ext`).
                        body.extend(append_match_subgroup(
                            matches,
                            match_count,
                            Expr::var("pattern_id"),
                            Expr::var("match_start"),
                            Expr::var("scan_end"),
                            Expr::bool(true),
                        ));
                    } else {
                        // Plain global-atomic append for backends without
                        // subgroup-op emit (currently CUDA). One atomic_add
                        // per lane per hit; slower on hit-dense workloads
                        // but compatible.
                        body.push(crate::scan::builders::append_match(
                            matches,
                            match_count,
                            Expr::var("pattern_id"),
                            Expr::var("match_start"),
                            Expr::var("scan_end"),
                        ));
                    }
                    body
                }),
            ],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(haystack, 0, BufferAccess::ReadOnly, DataType::U32),
            BufferDecl::storage(transitions, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(state_count.saturating_mul(256)),
            BufferDecl::storage(output_offsets, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(state_count.saturating_add(1)),
            BufferDecl::storage(output_records, 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(output_records_len),
            BufferDecl::storage(pattern_lengths, 4, BufferAccess::ReadOnly, DataType::U32)
                .with_count(pattern_count),
            BufferDecl::storage(haystack_len, 5, BufferAccess::ReadOnly, DataType::U32)
                .with_count(1),
            BufferDecl::read_write(match_count, 6, DataType::U32).with_count(1),
            BufferDecl::output(matches, 7, DataType::U32).with_count(max_matches.saturating_mul(3)),
        ],
        // Workgroup size 128 (4 NVIDIA warps). At wg128 with the
        // OLD `append_match` (one global atomic per lane per hit) we
        // measured -85% throughput + 1-of-15 finding loss on the 64
        // MiB bench (2026-05-19) due to global-atomic serialization
        // on `match_count`. Now using `append_match_subgroup`
        // (Innovation I.17): one atomic_add per subgroup leader,
        // 32× contention drop on a 32-lane NVIDIA warp  -  so wg128 is
        // safe (4 atomics per workgroup instead of 128).
        [128, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::matching::classic_ac_bounded_ranges",
            walk_body,
        )],
    )
}

/// Build the dispatch Program for a bounded-ranges AC scan over an
/// already-compiled DFA. Pairs with
/// [`classic_ac_bounded_ranges_program`]: identical buffer layout
/// and emit format, but the caller doesn't have to thread through
/// the eight derived count fields every time.
#[must_use]
pub fn build_ac_bounded_ranges_program(
    dfa: &CompiledDfa,
    pattern_count: u32,
    max_matches: u32,
) -> Program {
    build_ac_bounded_ranges_program_ext(dfa, pattern_count, max_matches, true)
}

/// Variant of [`build_ac_bounded_ranges_program`] that exposes the
/// `use_subgroup_coalesce` selector. Pass `false` when the program
/// is going to be dispatched on a backend that cannot lower
/// `subgroup_ballot` + `subgroup_shuffle` yet (currently
/// `vyre-driver-cuda`).
#[must_use]
pub fn build_ac_bounded_ranges_program_ext(
    dfa: &CompiledDfa,
    pattern_count: u32,
    max_matches: u32,
    use_subgroup_coalesce: bool,
) -> Program {
    match try_build_ac_bounded_ranges_program_ext(
        dfa,
        pattern_count,
        max_matches,
        use_subgroup_coalesce,
    ) {
        Ok(program) => program,
        Err(error) => {
            eprintln!("vyre-libs AC bounded-ranges program build failed: {error}");
            empty_ac_bounded_ranges_program(max_matches, use_subgroup_coalesce)
        }
    }
}

/// Fallible variant of [`build_ac_bounded_ranges_program`].
///
/// # Errors
///
/// Returns an actionable error when DFA metadata cannot fit the GPU program's
/// u32 buffer-count ABI.

pub fn try_build_ac_bounded_ranges_program(
    dfa: &CompiledDfa,
    pattern_count: u32,
    max_matches: u32,
) -> Result<Program, String> {
    try_build_ac_bounded_ranges_program_ext(dfa, pattern_count, max_matches, true)
}

/// Fallible variant of [`build_ac_bounded_ranges_program_ext`].
///
/// # Errors
///
/// Returns an actionable error when DFA metadata cannot fit the GPU program's
/// u32 buffer-count ABI.
pub fn try_build_ac_bounded_ranges_program_ext(
    dfa: &CompiledDfa,
    pattern_count: u32,
    max_matches: u32,
    use_subgroup_coalesce: bool,
) -> Result<Program, String> {
    let output_records_len = u32::try_from(dfa.output_records.len()).map_err(|source| {
        format!(
            "AC bounded-ranges DFA output record count {} exceeds u32 GPU buffer metadata: {source}. Fix: shard the pattern set or lower the DFA budget before dispatch.",
            dfa.output_records.len()
        )
    })?;
    Ok(classic_ac_bounded_ranges_program_ext(
        "haystack",
        "transitions",
        "output_offsets",
        "output_records",
        "pattern_lengths",
        "haystack_len",
        "match_count",
        "matches",
        dfa.state_count,
        output_records_len,
        pattern_count,
        max_matches,
        dfa.max_pattern_len,
        use_subgroup_coalesce,
    ))
}

fn empty_ac_bounded_ranges_program(max_matches: u32, use_subgroup_coalesce: bool) -> Program {
    classic_ac_bounded_ranges_program_ext(
        "haystack",
        "transitions",
        "output_offsets",
        "output_records",
        "pattern_lengths",
        "haystack_len",
        "match_count",
        "matches",
        1,
        0,
        0,
        max_matches,
        0,
        use_subgroup_coalesce,
    )
}

/// CPU reference for [`classic_ac_bounded_ranges_program`]. Returns
/// `(pattern_id, start, end)` triples reconstructed from
/// `output_records` plus the pattern length table.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn classic_ac_bounded_ranges_scan(
    ac: &ClassicAcAutomaton,
    pattern_lengths: &[u32],
    haystack: &[u8],
) -> Vec<(u32, u32, u32)> {
    let dfa = &ac.dfa;
    let mut state = 0u32;
    let mut out = Vec::new();
    for (pos, &b) in haystack.iter().enumerate() {
        state = dfa.transitions[(state as usize) * 256 + (b as usize)];
        let begin = dfa.output_offsets[state as usize] as usize;
        let end_off = dfa.output_offsets[state as usize + 1] as usize;
        for &pid in &dfa.output_records[begin..end_off] {
            let pat_len = pattern_lengths.get(pid as usize).copied().unwrap_or(0);
            let end_pos = (pos as u32).saturating_add(1);
            let start = end_pos.saturating_sub(pat_len);
            out.push((pid, start, end_pos));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::byte_pack::bytes_to_u32 as decode_u32_words;

    #[test]
    fn single_pattern_matches() {
        let ac = classic_ac_compile(&[b"abc"]);
        let matches = classic_ac_scan(&ac, b"xxabcxx");
        assert_eq!(matches, vec![(0, 4)]);
    }

    #[test]
    fn overlapping_patterns_report_all() {
        // Patterns "he", "she", "his", "hers" on "ushers".
        let ac = classic_ac_compile(&[b"he", b"she", b"his", b"hers"]);
        let matches = classic_ac_scan(&ac, b"ushers");
        // "she" ends at position 3, "he" ends at position 3,
        // "hers" ends at position 5.
        assert!(matches.contains(&(1, 3)), "must match she");
        assert!(matches.contains(&(0, 3)), "must match he");
        assert!(matches.contains(&(3, 5)), "must match hers");
    }

    #[test]
    fn nested_suffix_patterns_all_reported() {
        // a, aa, aaa, aaaa on "aaaa".
        let ac = classic_ac_compile(&[b"a", b"aa", b"aaa", b"aaaa"]);
        let matches = classic_ac_scan(&ac, b"aaaa");
        // Position 0: "a" (1 char)
        // Position 1: "a", "aa"
        // Position 2: "a", "aa", "aaa"
        // Position 3: "a", "aa", "aaa", "aaaa"
        let expected = vec![
            (0, 0),
            (0, 1),
            (1, 1),
            (0, 2),
            (1, 2),
            (2, 2),
            (0, 3),
            (1, 3),
            (2, 3),
            (3, 3),
        ];
        assert_eq!(matches, expected);
    }

    #[test]
    fn adversarial_failure_chain_is_linear_in_matches() {
        // Patterns a, aa, aaa, ... up to length 128.
        // This creates a long failure-link chain.
        let patterns: Vec<Vec<u8>> = (1..=128).map(|i| vec![b'a'; i]).collect();
        let pattern_refs: Vec<&[u8]> = patterns.iter().map(|p| p.as_slice()).collect();
        let ac = classic_ac_compile(&pattern_refs);
        let haystack = vec![b'a'; 128];
        let matches = classic_ac_scan(&ac, &haystack);

        // At position i (0-based) there are i+1 matches.
        // Total matches = 128 * 129 / 2 = 8256.
        assert_eq!(matches.len(), 8256);

        // Verify the last position has all 128 patterns.
        let last_pos_matches: Vec<u32> = matches
            .iter()
            .filter(|&&(_, pos)| pos == 127)
            .map(|&(pid, _)| pid)
            .collect();
        assert_eq!(last_pos_matches.len(), 128);
        for (expected_pid, &actual_pid) in last_pos_matches.iter().enumerate() {
            assert_eq!(actual_pid, expected_pid as u32);
        }
    }

    #[test]
    fn empty_haystack_yields_no_matches() {
        let ac = classic_ac_compile(&[b"abc"]);
        assert!(classic_ac_scan(&ac, b"").is_empty());
    }

    #[test]
    fn empty_pattern_list_yields_no_matches() {
        let ac = classic_ac_compile(&[]);
        assert!(classic_ac_scan(&ac, b"anything").is_empty());
    }

    #[test]
    fn gpu_emit_matches_cpu_reference() {
        let patterns: [&[u8]; 4] = [b"he", b"she", b"his", b"hers"];
        let ac = classic_ac_compile(&patterns);
        let haystack = b"ushers";
        let cpu = classic_ac_scan(&ac, haystack);

        // Build the vyre IR program.
        let program = classic_ac_program(
            "haystack",
            "transitions",
            "output_offsets",
            "output_records",
            "match_count",
            "matches",
            haystack.len() as u32,
            ac.dfa.state_count,
            ac.dfa.output_records.len() as u32,
            1024,
        );

        let inputs = vec![
            vyre_reference::value::Value::from(crate::test_support::byte_pack::u32_bytes(
                &haystack.iter().map(|&b| u32::from(b)).collect::<Vec<_>>(),
            )),
            vyre_reference::value::Value::from(crate::test_support::byte_pack::u32_bytes(
                &ac.dfa.transitions,
            )),
            vyre_reference::value::Value::from(crate::test_support::byte_pack::u32_bytes(
                &ac.dfa.output_offsets,
            )),
            vyre_reference::value::Value::from(crate::test_support::byte_pack::u32_bytes(
                &ac.dfa.output_records,
            )),
            vyre_reference::value::Value::from(crate::test_support::byte_pack::u32_bytes(&[0u32])),
            vyre_reference::value::Value::from(vec![0u8; 1024 * 4]),
        ];

        let outputs = vyre_reference::reference_eval(&program, &inputs).expect(
            "Fix: classic_ac_program must execute; restore this invariant before continuing.",
        );

        let match_count = decode_u32_words(&outputs[0].to_bytes())[0];
        let gpu_matches_raw = decode_u32_words(&outputs[1].to_bytes());
        let gpu_matches: Vec<u32> = gpu_matches_raw[..match_count as usize].to_vec();

        // CPU gives (pattern_id, end_pos); GPU gives just pattern_id
        // because each invocation writes its own patterns.  The order
        // is nondeterministic (atomic scheduling), so sort both.
        let mut cpu_ids: Vec<u32> = cpu.iter().map(|&(pid, _)| pid).collect();
        cpu_ids.sort_unstable();

        let mut gpu_ids = gpu_matches;
        gpu_ids.sort_unstable();

        assert_eq!(
            cpu_ids, gpu_ids,
            "GPU emit must agree with Reference oracle on pattern ids"
        );
    }

    #[test]
    fn gpu_emit_does_not_overflow_when_max_matches_is_small() {
        let ac = classic_ac_compile(&[b"a", b"aa", b"aaa"]);
        let haystack = b"aaa";
        let program = classic_ac_program(
            "haystack",
            "transitions",
            "output_offsets",
            "output_records",
            "match_count",
            "matches",
            haystack.len() as u32,
            ac.dfa.state_count,
            ac.dfa.output_records.len() as u32,
            2, // only allow 2 stored matches
        );

        let inputs = vec![
            vyre_reference::value::Value::from(crate::test_support::byte_pack::u32_bytes(
                &haystack.iter().map(|&b| u32::from(b)).collect::<Vec<_>>(),
            )),
            vyre_reference::value::Value::from(crate::test_support::byte_pack::u32_bytes(
                &ac.dfa.transitions,
            )),
            vyre_reference::value::Value::from(crate::test_support::byte_pack::u32_bytes(
                &ac.dfa.output_offsets,
            )),
            vyre_reference::value::Value::from(crate::test_support::byte_pack::u32_bytes(
                &ac.dfa.output_records,
            )),
            vyre_reference::value::Value::from(crate::test_support::byte_pack::u32_bytes(&[0u32])),
            vyre_reference::value::Value::from(vec![0u8; 2 * 4]),
        ];

        let outputs = vyre_reference::reference_eval(&program, &inputs).expect(
            "Fix: classic_ac_program must execute; restore this invariant before continuing.",
        );

        let match_count = decode_u32_words(&outputs[0].to_bytes())[0];
        // Total matches = 1 + 2 + 3 = 6, but only 2 slots.
        assert_eq!(match_count, 6, "match_count must reflect total discoveries");
        let stored = decode_u32_words(&outputs[1].to_bytes());
        assert_eq!(stored.len(), 2, "only 2 slots allocated");
    }

    #[test]
    fn bounded_ranges_builder_exposes_checked_metadata_variant() {
        let production = include_str!("classic_ac.rs")
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .expect("Fix: classic AC production section should precede tests");

        assert!(
            production.contains("try_build_ac_bounded_ranges_program_ext"),
            "Fix: AC bounded-ranges builder must expose a fallible metadata sizing path."
        );
        assert!(
            !production.contains("dfa.output_records.len() as u32"),
            "Fix: AC bounded-ranges builder must not narrow output record counts with unchecked casts."
        );
        assert!(
            production.contains("u32::try_from(dfa.output_records.len())"),
            "Fix: AC bounded-ranges output record count must use checked conversion."
        );
        assert!(
            !production.contains(".expect(") && !production.contains(".unwrap("),
            "Fix: AC bounded-ranges production builder must not panic."
        );
    }
}

