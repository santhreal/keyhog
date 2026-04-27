//! `vyre-libs::parsing::bracket_match` — Tier 3 wrapper over the
//! Tier 2.5 [`vyre_primitives::matching::bracket_match::bracket_match`] primitive.
//!
//! Migrated per `docs/primitives-tier.md` Step 2 +
//! `docs/lego-block-rule.md`. The op id stays
//! `vyre-libs::parsing::bracket_match` so existing consumers don't
//! break; the IR-builder + CPU reference all live in
//! `vyre-primitives-matching`. Future parser dialects (`parse-c`,
//! `parse-rust`, `parse-go`, `parse-python` for f-strings) consume
//! the exact same scanner.

pub use vyre_primitives::matching::bracket_match::{
    bracket_match, cpu_ref, pack_u32, CLOSE_BRACE, MATCH_NONE, OPEN_BRACE, OP_ID, OTHER,
};

const CORE_DELIMITER_GENERATOR: &str = "vyre-libs::parsing::core_delimiter_match";

fn fixture_inputs() -> Vec<Vec<Vec<u8>>> {
    vec![vec![
        pack_u32(&[OPEN_BRACE, OPEN_BRACE, CLOSE_BRACE, CLOSE_BRACE]),
        vec![0u8; 4 * 4],
        pack_u32(&[MATCH_NONE; 4]),
    ]]
}

fn fixture_outputs() -> Vec<Vec<Vec<u8>>> {
    // The universal harness expects one readback per RW / output
    // buffer. bracket_match declares two RW buffers in order: `stack`
    // (scratch depth stack) and `match_pairs` (result). For the
    // fixture input [OPEN, OPEN, CLOSE, CLOSE] with max_depth=4,
    // tracing the serial walk leaves stack = [0, 1, 0, 0] (slots
    // 2..3 never written) and match_pairs = [3, 2, 1, 0].
    vec![vec![
        pack_u32(&[0, 1, 0, 0]),
        pack_u32(&cpu_ref(
            &[OPEN_BRACE, OPEN_BRACE, CLOSE_BRACE, CLOSE_BRACE],
            4,
        )),
    ]]
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || bracket_match("kinds", "stack", "match_pairs", 4, 4),
        test_inputs: Some(fixture_inputs),
        expected_output: Some(fixture_outputs),
    }
}

use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre_foundation::composition::mark_self_exclusive_region;

/// Generic delimiter matching logic for arbitrary token streams.
///
/// Implements a subgroup parallel scan algorithm to trace depth
/// transitions natively without warp divergence. Valid token depths
/// are recorded alongside each symbol for the AST constructor boundary map.
#[must_use]
pub fn core_delimiter_match(
    tok_types: &str,
    tok_depths: &str,
    tok_count: u32,
    open_tok_id: u32,
    close_tok_id: u32,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };

    // Each lane computes its own inclusive prefix sum over `tok_types[0..=t]`
    // by walking the prefix serially. Correct on every backend; a real
    // parallel subgroup scan lands as a follow-up once the Tier-2.5
    // `prefix_scan_u32` primitive ships (currently there's only one Tier-3
    // caller — not enough for promotion per the LEGO rule). Underflow on
    // close > open in the prefix wraps via two's complement, matching the
    // documented behaviour of the previous subgroup_inclusive_add path.
    let transform_logic = vec![
        Node::let_bind("running_depth", Expr::u32(0)),
        Node::loop_for(
            "k",
            Expr::u32(0),
            Expr::add(t.clone(), Expr::u32(1)),
            vec![
                Node::let_bind("kth_tok", Expr::load(tok_types, Expr::var("k"))),
                Node::if_then(
                    Expr::eq(Expr::var("kth_tok"), Expr::u32(open_tok_id)),
                    vec![Node::assign(
                        "running_depth",
                        Expr::add(Expr::var("running_depth"), Expr::u32(1)),
                    )],
                ),
                Node::if_then(
                    Expr::eq(Expr::var("kth_tok"), Expr::u32(close_tok_id)),
                    vec![Node::assign(
                        "running_depth",
                        Expr::sub(Expr::var("running_depth"), Expr::u32(1)),
                    )],
                ),
            ],
        ),
        Node::store(tok_depths, t.clone(), Expr::var("running_depth")),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(tok_types, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_count),
            BufferDecl::storage(tok_depths, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(tok_count),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            &mark_self_exclusive_region(CORE_DELIMITER_GENERATOR),
            vec![Node::if_then(
                Expr::lt(t.clone(), Expr::u32(tok_count)),
                transform_logic,
            )],
        )],
    )
    .with_entry_op_id(CORE_DELIMITER_GENERATOR)
    .with_non_composable_with_self(true)
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::parsing::core_delimiter_match",
        build: || {
            core_delimiter_match("tok_types", "tok_depths", 8, 12, 13)
        },
        // 8-token input with LBRACE(12) / RBRACE(13) pairs at
        // indices {0,1,5,6}. Expected inclusive-prefix depth at each
        // position: 1, 2, 2, 2, 2, 1, 0, 0.
        test_inputs: Some(|| {
            let tokens: [u32; 8] = [12, 12, 0, 0, 0, 13, 13, 0];
            let bytes = tokens
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<u8>>();
            vec![vec![bytes, vec![0u8; 4 * 8]]]
        }),
        expected_output: Some(|| {
            let depths: [u32; 8] = [1, 2, 2, 2, 2, 1, 0, 0];
            let bytes = depths
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<u8>>();
            vec![vec![bytes]]
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_reference::value::Value;

    fn run(kinds: &[u32], max_depth: u32) -> Vec<u32> {
        let n = kinds.len().max(1) as u32;
        let program = bracket_match("kinds", "stack", "match_pairs", n, max_depth);
        let inputs = vec![
            Value::Bytes(pack_u32(kinds).into()),
            Value::Bytes(vec![0u8; (max_depth as usize) * 4].into()),
            Value::Bytes(pack_u32(&vec![MATCH_NONE; n as usize]).into()),
        ];
        let outputs =
            vyre_reference::reference_eval(&program, &inputs).expect("bracket_match must run");
        outputs[1]
            .to_bytes()
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect()
    }

    #[test]
    fn balanced_single_pair() {
        assert_eq!(
            run(&[OPEN_BRACE, OTHER, CLOSE_BRACE], 3),
            vec![2, MATCH_NONE, 0]
        );
    }

    #[test]
    fn nested_pairs() {
        assert_eq!(
            run(&[OPEN_BRACE, OPEN_BRACE, CLOSE_BRACE, CLOSE_BRACE], 4),
            vec![3, 2, 1, 0]
        );
    }

    #[test]
    fn unbalanced_extra_open() {
        assert_eq!(
            run(&[OPEN_BRACE, OPEN_BRACE, CLOSE_BRACE], 3),
            vec![MATCH_NONE, 2, 1]
        );
    }

    #[test]
    fn unbalanced_extra_close() {
        assert_eq!(
            run(&[CLOSE_BRACE, OPEN_BRACE, CLOSE_BRACE], 3),
            vec![MATCH_NONE, 2, 1]
        );
    }

    #[test]
    fn depth_cap_truncates_extra_opens() {
        assert_eq!(
            run(
                &[
                    OPEN_BRACE,
                    OPEN_BRACE,
                    OPEN_BRACE,
                    CLOSE_BRACE,
                    CLOSE_BRACE,
                    CLOSE_BRACE
                ],
                2,
            ),
            vec![4, 3, MATCH_NONE, 1, 0, MATCH_NONE],
        );
    }
}
