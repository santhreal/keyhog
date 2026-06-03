use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::region::wrap_anonymous;
use crate::scan::builders::{append_match, append_match_subgroup, load_packed_byte};
use crate::scan::dfa::CompiledDfa;

#[cfg(any(test, feature = "cpu-parity"))]
use super::ClassicAcAutomaton;

#[path = "bounded_ranges/prefilter.rs"]
mod prefilter;

pub use prefilter::{
    build_ac_bounded_ranges_prefilter_program, build_ac_bounded_ranges_prefilter_program_ext,
    build_ac_bounded_ranges_suffix3_prefilter_program,
    build_ac_bounded_ranges_suffix3_prefilter_program_ext,
    classic_ac_bounded_ranges_prefilter_program, classic_ac_bounded_ranges_prefilter_program_ext,
    classic_ac_bounded_ranges_suffix3_prefilter_program,
    classic_ac_bounded_ranges_suffix3_prefilter_program_ext,
    try_build_ac_bounded_ranges_prefilter_program,
    try_build_ac_bounded_ranges_prefilter_program_ext,
    try_build_ac_bounded_ranges_suffix3_prefilter_program,
    try_build_ac_bounded_ranges_suffix3_prefilter_program_ext,
};

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
/// can't emit `subgroup_ballot`/`subgroup_shuffle`.
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
    let walk_body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::load(haystack_len, Expr::u32(0))),
            bounded_ranges_scan_nodes(
                haystack,
                transitions,
                output_offsets,
                output_records,
                pattern_lengths,
                match_count,
                matches,
                max_pattern_len,
                use_subgroup_coalesce,
            ),
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
        [128, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::matching::classic_ac_bounded_ranges",
            walk_body,
        )],
    )
}

#[allow(clippy::too_many_arguments)]
fn bounded_ranges_scan_nodes(
    haystack: &str,
    transitions: &str,
    output_offsets: &str,
    output_records: &str,
    pattern_lengths: &str,
    match_count: &str,
    matches: &str,
    max_pattern_len: u32,
    use_subgroup_coalesce: bool,
) -> Vec<Node> {
    let max_pattern_len = max_pattern_len.max(1);
    let i = Expr::var("i");
    let end = Expr::add(i.clone(), Expr::u32(1));
    let scan_start = Expr::select(
        Expr::lt(i.clone(), Expr::u32(max_pattern_len - 1)),
        Expr::u32(0),
        Expr::sub(end.clone(), Expr::u32(max_pattern_len)),
    );
    let (load_step_byte, step_byte) = load_packed_byte(haystack, Expr::var("step"));

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
                body.extend(append_match_subgroup(
                    matches,
                    match_count,
                    Expr::var("pattern_id"),
                    Expr::var("match_start"),
                    Expr::var("scan_end"),
                    Expr::bool(true),
                ));
            } else {
                body.push(append_match(
                    matches,
                    match_count,
                    Expr::var("pattern_id"),
                    Expr::var("match_start"),
                    Expr::var("scan_end"),
                ));
            }
            body
        }),
    ]
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
