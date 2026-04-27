//! Aho-Corasick multi-pattern scanner (companion to [`dfa_compile`]).
//!
//! Consumes a transition table built by [`super::dfa_compile`] and
//! scans `haystack` for any of the compiled patterns. Emits `1` at
//! `matches[i]` whenever the automaton accepts at position `i`.
//!
//! Layout assumptions (see `dfa_compile::CompiledDfa`):
//!
//! ```text
//! transitions[state * 256 + byte] = next_state
//! accept[state]                    = 0 unless state accepts
//! ```
//!
//! One invocation per haystack byte; each invocation walks the
//! automaton from state 0 up to position `i` so scans can execute in
//! parallel without ordering constraints. That is O(n²) in serial
//! work but O(n/lanes) wall time — the classic trade-off Cat-A
//! doesn't fuse until `region_inline` + loop-hoist passes see the
//! structure.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::region::wrap_anonymous;

/// Build a Program that scans `haystack` (u32 per byte) for any
/// accepting state of a pre-built DFA. Buffers:
///
/// - `haystack`: ReadOnly, `u32` per byte.
/// - `transitions`: ReadOnly, `u32` — `state * 256 + byte → next`.
/// - `accept`: ReadOnly, `u32` — accept table indexed by state.
/// - `matches`: ReadWrite, `u32` — one slot per haystack byte, set
///   to `accept[state]` (pattern_id + 1) when the automaton accepts
///   at that offset.
#[must_use]
pub fn aho_corasick(
    haystack: &str,
    transitions: &str,
    accept: &str,
    matches: &str,
    haystack_len: u32,
    state_count: u32,
) -> Program {
    let i = Expr::var("i");
    let body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::buf_len(haystack)),
            vec![
                // Walk the automaton from state 0 through haystack[0..=i].
                Node::let_bind("state", Expr::u32(0)),
                Node::loop_for(
                    "step",
                    Expr::u32(0),
                    Expr::add(i.clone(), Expr::u32(1)),
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
                // matches[i] = accept[state]; non-zero = (pattern_id + 1).
                Node::Store {
                    buffer: matches.into(),
                    index: i,
                    value: Expr::load(accept, Expr::var("state")),
                },
            ],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(haystack, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(haystack_len),
            BufferDecl::storage(transitions, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(state_count.saturating_mul(256)),
            BufferDecl::storage(accept, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(state_count),
            BufferDecl::output(matches, 3, DataType::U32).with_count(haystack_len),
        ],
        [64, 1, 1],
        vec![wrap_anonymous("vyre-libs::matching::aho_corasick", body)],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::matching::aho_corasick",
        build: || {
            let patterns: [&[u8]; 1] = [b"abra"];
            let compiled = crate::matching::dfa::dfa_compile(&patterns);
            aho_corasick("haystack", "transitions", "accept", "matches", 11, compiled.accept.len() as u32)
        },
        test_inputs: Some(|| {
            let patterns: [&[u8]; 1] = [b"abra"];
            let compiled = crate::matching::dfa::dfa_compile(&patterns);
            let haystack = b"abracadabra";
            let u32_bytes = |words: &[u32]| words.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                u32_bytes(&haystack.iter().map(|&b| u32::from(b)).collect::<Vec<_>>()),
                u32_bytes(&compiled.transitions),
                u32_bytes(&compiled.accept),
                vec![0u8; haystack.len() * 4],
            ]]
        }),
        expected_output: Some(|| vec![
            vec![
                vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, ],
            ],
        ]),
    }
}
