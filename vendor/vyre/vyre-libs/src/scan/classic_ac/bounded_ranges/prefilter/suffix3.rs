use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::region::wrap_anonymous;
use crate::scan::builders::load_packed_byte_expr;
use crate::scan::dfa::CompiledDfa;

use super::super::super::count_program::{
    suffix3_bloom_bit_index_expr, CLASSIC_AC_SUFFIX2_MASK_WORDS, CLASSIC_AC_SUFFIX3_BLOOM_WORDS,
};
use super::super::bounded_ranges_scan_nodes;

/// Build a bounded-window AC ranges program with byte, suffix2, and suffix3
/// candidate filters before match-emitting replay.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn classic_ac_bounded_ranges_suffix3_prefilter_program(
    haystack: &str,
    transitions: &str,
    output_offsets: &str,
    output_records: &str,
    pattern_lengths: &str,
    haystack_len: &str,
    match_count: &str,
    candidate_end_mask: &str,
    candidate_suffix2_mask: &str,
    candidate_suffix3_bloom: &str,
    matches: &str,
    state_count: u32,
    output_records_len: u32,
    pattern_count: u32,
    max_matches: u32,
    max_pattern_len: u32,
) -> Program {
    classic_ac_bounded_ranges_suffix3_prefilter_program_ext(
        haystack,
        transitions,
        output_offsets,
        output_records,
        pattern_lengths,
        haystack_len,
        match_count,
        candidate_end_mask,
        candidate_suffix2_mask,
        candidate_suffix3_bloom,
        matches,
        state_count,
        output_records_len,
        pattern_count,
        max_matches,
        max_pattern_len,
        true,
    )
}

/// Variant of [`classic_ac_bounded_ranges_suffix3_prefilter_program`] with
/// explicit control over subgroup match-append coalescing.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn classic_ac_bounded_ranges_suffix3_prefilter_program_ext(
    haystack: &str,
    transitions: &str,
    output_offsets: &str,
    output_records: &str,
    pattern_lengths: &str,
    haystack_len: &str,
    match_count: &str,
    candidate_end_mask: &str,
    candidate_suffix2_mask: &str,
    candidate_suffix3_bloom: &str,
    matches: &str,
    state_count: u32,
    output_records_len: u32,
    pattern_count: u32,
    max_matches: u32,
    max_pattern_len: u32,
    use_subgroup_coalesce: bool,
) -> Program {
    let i = Expr::var("i");
    let candidate_byte = load_packed_byte_expr(haystack, i.clone());
    let previous_byte =
        load_packed_byte_expr(haystack, Expr::saturating_sub(i.clone(), Expr::u32(1)));
    let previous2_byte =
        load_packed_byte_expr(haystack, Expr::saturating_sub(i.clone(), Expr::u32(2)));
    let suffix2_index = Expr::bitor(
        Expr::shl(Expr::var("previous_byte"), Expr::u32(8)),
        Expr::var("candidate_byte"),
    );
    let suffix3_index = Expr::bitor(
        Expr::bitor(
            Expr::shl(Expr::var("previous2_byte"), Expr::u32(16)),
            Expr::shl(Expr::var("previous_byte"), Expr::u32(8)),
        ),
        Expr::var("candidate_byte"),
    );
    let suffix3_bit_index = suffix3_bloom_bit_index_expr(Expr::var("suffix3_index"));
    let scan_nodes = bounded_ranges_scan_nodes(
        haystack,
        transitions,
        output_offsets,
        output_records,
        pattern_lengths,
        match_count,
        matches,
        max_pattern_len,
        use_subgroup_coalesce,
    );

    let body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::load(haystack_len, Expr::u32(0))),
            vec![
                Node::let_bind("candidate_byte", candidate_byte),
                Node::let_bind(
                    "candidate_word",
                    Expr::load(
                        candidate_end_mask,
                        Expr::shr(Expr::var("candidate_byte"), Expr::u32(5)),
                    ),
                ),
                Node::let_bind(
                    "candidate_bit",
                    Expr::shl(
                        Expr::u32(1),
                        Expr::bitand(Expr::var("candidate_byte"), Expr::u32(31)),
                    ),
                ),
                Node::if_then(
                    Expr::ne(
                        Expr::bitand(Expr::var("candidate_word"), Expr::var("candidate_bit")),
                        Expr::u32(0),
                    ),
                    vec![Node::if_then_else(
                        Expr::eq(i.clone(), Expr::u32(0)),
                        scan_nodes.clone(),
                        vec![
                            Node::let_bind("previous_byte", previous_byte),
                            Node::let_bind("suffix2_index", suffix2_index),
                            Node::let_bind(
                                "suffix2_word",
                                Expr::load(
                                    candidate_suffix2_mask,
                                    Expr::shr(Expr::var("suffix2_index"), Expr::u32(5)),
                                ),
                            ),
                            Node::let_bind(
                                "suffix2_bit",
                                Expr::shl(
                                    Expr::u32(1),
                                    Expr::bitand(Expr::var("suffix2_index"), Expr::u32(31)),
                                ),
                            ),
                            Node::if_then(
                                Expr::ne(
                                    Expr::bitand(
                                        Expr::var("suffix2_word"),
                                        Expr::var("suffix2_bit"),
                                    ),
                                    Expr::u32(0),
                                ),
                                vec![Node::if_then_else(
                                    Expr::eq(i.clone(), Expr::u32(1)),
                                    scan_nodes.clone(),
                                    vec![
                                        Node::let_bind("previous2_byte", previous2_byte),
                                        Node::let_bind("suffix3_index", suffix3_index),
                                        Node::let_bind("suffix3_bit_index", suffix3_bit_index),
                                        Node::let_bind(
                                            "suffix3_word",
                                            Expr::load(
                                                candidate_suffix3_bloom,
                                                Expr::shr(
                                                    Expr::var("suffix3_bit_index"),
                                                    Expr::u32(5),
                                                ),
                                            ),
                                        ),
                                        Node::let_bind(
                                            "suffix3_bit",
                                            Expr::shl(
                                                Expr::u32(1),
                                                Expr::bitand(
                                                    Expr::var("suffix3_bit_index"),
                                                    Expr::u32(31),
                                                ),
                                            ),
                                        ),
                                        Node::if_then(
                                            Expr::ne(
                                                Expr::bitand(
                                                    Expr::var("suffix3_word"),
                                                    Expr::var("suffix3_bit"),
                                                ),
                                                Expr::u32(0),
                                            ),
                                            scan_nodes,
                                        ),
                                    ],
                                )],
                            ),
                        ],
                    )],
                ),
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
            BufferDecl::storage(candidate_end_mask, 7, BufferAccess::ReadOnly, DataType::U32)
                .with_count(8),
            BufferDecl::storage(
                candidate_suffix2_mask,
                8,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(CLASSIC_AC_SUFFIX2_MASK_WORDS as u32),
            BufferDecl::storage(
                candidate_suffix3_bloom,
                9,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(CLASSIC_AC_SUFFIX3_BLOOM_WORDS as u32),
            BufferDecl::output(matches, 10, DataType::U32)
                .with_count(max_matches.saturating_mul(3)),
        ],
        [128, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::matching::classic_ac_bounded_ranges_suffix3_prefilter",
            body,
        )],
    )
}

/// Build the suffix-prefiltered bounded-ranges AC scan for a compiled DFA.
#[must_use]
pub fn build_ac_bounded_ranges_suffix3_prefilter_program(
    dfa: &CompiledDfa,
    pattern_count: u32,
    max_matches: u32,
) -> Program {
    build_ac_bounded_ranges_suffix3_prefilter_program_ext(dfa, pattern_count, max_matches, true)
}

/// Variant of [`build_ac_bounded_ranges_suffix3_prefilter_program`] that
/// exposes the match-append coalescing selector.
#[must_use]
pub fn build_ac_bounded_ranges_suffix3_prefilter_program_ext(
    dfa: &CompiledDfa,
    pattern_count: u32,
    max_matches: u32,
    use_subgroup_coalesce: bool,
) -> Program {
    match try_build_ac_bounded_ranges_suffix3_prefilter_program_ext(
        dfa,
        pattern_count,
        max_matches,
        use_subgroup_coalesce,
    ) {
        Ok(program) => program,
        Err(error) => {
            eprintln!(
                "vyre-libs AC bounded-ranges suffix3 prefilter program build failed: {error}"
            );
            empty_ac_bounded_ranges_suffix3_prefilter_program(max_matches, use_subgroup_coalesce)
        }
    }
}

/// Fallible variant of [`build_ac_bounded_ranges_suffix3_prefilter_program`].
///
/// # Errors
///
/// Returns an actionable error when DFA metadata cannot fit the GPU program's
/// u32 buffer-count ABI.
pub fn try_build_ac_bounded_ranges_suffix3_prefilter_program(
    dfa: &CompiledDfa,
    pattern_count: u32,
    max_matches: u32,
) -> Result<Program, String> {
    try_build_ac_bounded_ranges_suffix3_prefilter_program_ext(dfa, pattern_count, max_matches, true)
}

/// Fallible variant of [`build_ac_bounded_ranges_suffix3_prefilter_program_ext`].
///
/// # Errors
///
/// Returns an actionable error when DFA metadata cannot fit the GPU program's
/// u32 buffer-count ABI.
pub fn try_build_ac_bounded_ranges_suffix3_prefilter_program_ext(
    dfa: &CompiledDfa,
    pattern_count: u32,
    max_matches: u32,
    use_subgroup_coalesce: bool,
) -> Result<Program, String> {
    let output_records_len = u32::try_from(dfa.output_records.len()).map_err(|source| {
        format!(
            "AC bounded-ranges suffix3 prefilter DFA output record count {} exceeds u32 GPU buffer metadata: {source}. Fix: shard the pattern set or lower the DFA budget before dispatch.",
            dfa.output_records.len()
        )
    })?;
    Ok(classic_ac_bounded_ranges_suffix3_prefilter_program_ext(
        "haystack",
        "transitions",
        "output_offsets",
        "output_records",
        "pattern_lengths",
        "haystack_len",
        "match_count",
        "candidate_end_mask",
        "candidate_suffix2_mask",
        "candidate_suffix3_bloom",
        "matches",
        dfa.state_count,
        output_records_len,
        pattern_count,
        max_matches,
        dfa.max_pattern_len,
        use_subgroup_coalesce,
    ))
}

fn empty_ac_bounded_ranges_suffix3_prefilter_program(
    max_matches: u32,
    use_subgroup_coalesce: bool,
) -> Program {
    classic_ac_bounded_ranges_suffix3_prefilter_program_ext(
        "haystack",
        "transitions",
        "output_offsets",
        "output_records",
        "pattern_lengths",
        "haystack_len",
        "match_count",
        "candidate_end_mask",
        "candidate_suffix2_mask",
        "candidate_suffix3_bloom",
        "matches",
        1,
        0,
        0,
        max_matches,
        0,
        use_subgroup_coalesce,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::classic_ac::{
        classic_ac_bounded_ranges_scan, classic_ac_candidate_end_byte_mask_words,
        classic_ac_candidate_suffix2_mask_words, classic_ac_candidate_suffix3_bloom_words,
        classic_ac_compile,
    };
    use crate::scan::{pack_haystack_u32, pack_u32_slice};

    fn decode_u32(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect()
    }

    fn pattern_lengths(patterns: &[&[u8]]) -> Vec<u32> {
        patterns
            .iter()
            .map(|pattern| pattern.len() as u32)
            .collect()
    }

    fn decode_match_triples(outputs: &[vyre_reference::value::Value]) -> Vec<(u32, u32, u32)> {
        let count = decode_u32(&outputs[0].to_bytes())[0] as usize;
        let words = decode_u32(&outputs[1].to_bytes());
        words[..count.saturating_mul(3)]
            .chunks_exact(3)
            .map(|chunk| (chunk[0], chunk[1], chunk[2]))
            .collect()
    }

    #[test]
    fn bounded_ranges_suffix3_prefilter_reference_eval_matches_cpu_oracle() {
        let patterns: [&[u8]; 6] = [b"a", b"bc", b"ab", b"abcd", b"BEGIN", b"token"];
        let haystack = b"zabcd a bc BEGIN token abcdbc";
        let ac = classic_ac_compile(&patterns);
        let lengths = pattern_lengths(&patterns);
        let mut expected = classic_ac_bounded_ranges_scan(&ac, &lengths, haystack);
        expected.sort_unstable();
        let program = build_ac_bounded_ranges_suffix3_prefilter_program_ext(
            &ac.dfa,
            patterns.len() as u32,
            128,
            false,
        );
        let inputs = vec![
            vyre_reference::value::Value::from(pack_haystack_u32(haystack)),
            vyre_reference::value::Value::from(pack_u32_slice(&ac.dfa.transitions)),
            vyre_reference::value::Value::from(pack_u32_slice(&ac.dfa.output_offsets)),
            vyre_reference::value::Value::from(pack_u32_slice(&ac.dfa.output_records)),
            vyre_reference::value::Value::from(pack_u32_slice(&lengths)),
            vyre_reference::value::Value::from(pack_u32_slice(&[haystack.len() as u32])),
            vyre_reference::value::Value::from(pack_u32_slice(&[0])),
            vyre_reference::value::Value::from(pack_u32_slice(
                &classic_ac_candidate_end_byte_mask_words(&ac.dfa),
            )),
            vyre_reference::value::Value::from(pack_u32_slice(
                &classic_ac_candidate_suffix2_mask_words(&ac.dfa),
            )),
            vyre_reference::value::Value::from(pack_u32_slice(
                &classic_ac_candidate_suffix3_bloom_words(&patterns),
            )),
        ];
        let outputs = vyre_reference::reference_eval(&program, &inputs).expect(
            "Fix: suffix3 prefiltered AC bounded-ranges program should evaluate in reference backend.",
        );
        let mut actual = decode_match_triples(&outputs);
        actual.sort_unstable();

        assert_eq!(actual, expected);
    }

    #[test]
    fn bounded_ranges_suffix3_prefilter_program_has_compact_stable_shape() {
        let ac = classic_ac_compile(&[b"Authorization: Bearer ", b"token", b"tok"]);
        let program =
            build_ac_bounded_ranges_suffix3_prefilter_program_ext(&ac.dfa, 3, 1024, false);

        assert_eq!(program.workgroup_size(), [128, 1, 1]);
        assert_eq!(program.buffers().len(), 11);
        assert_eq!(program.buffers()[6].name(), "match_count");
        assert_eq!(program.buffers()[6].count, 1);
        assert_eq!(program.buffers()[7].name(), "candidate_end_mask");
        assert_eq!(program.buffers()[7].count, 8);
        assert_eq!(program.buffers()[8].name(), "candidate_suffix2_mask");
        assert_eq!(
            program.buffers()[8].count,
            CLASSIC_AC_SUFFIX2_MASK_WORDS as u32
        );
        assert_eq!(program.buffers()[9].name(), "candidate_suffix3_bloom");
        assert_eq!(
            program.buffers()[9].count,
            CLASSIC_AC_SUFFIX3_BLOOM_WORDS as u32
        );
        assert_eq!(program.buffers()[10].name(), "matches");
        assert_eq!(program.buffers()[10].count, 1024 * 3);
    }
}
