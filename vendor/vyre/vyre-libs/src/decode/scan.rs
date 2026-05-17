//! Shared decode-to-DFA scan bodies.

use vyre::ir::{Expr, Node};

const ALPHABET_SIZE: u32 = 256;

fn transition_expr(transitions: &str, state: Expr, byte: Expr) -> Expr {
    Expr::load(
        transitions,
        Expr::add(Expr::mul(state, Expr::u32(ALPHABET_SIZE)), byte),
    )
}

/// Build a bounded Aho-Corasick scan body for fused decoders.
///
/// The scanner walks the decoded stream once and writes every accepting state
/// in order. This preserves the existing Aho-Corasick output contract without
/// replaying the prefix independently for every output position.
#[must_use]
pub(crate) fn linear_aho_scan_body(
    input: &str,
    transitions: &str,
    accept: &str,
    matches: &str,
    valid_len: Expr,
) -> Vec<Node> {
    vec![Node::if_then(
        Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
        vec![
            Node::let_bind("state", Expr::u32(0)),
            Node::loop_for(
                "decode_scan_step",
                Expr::u32(0),
                valid_len,
                vec![
                    Node::let_bind("byte", Expr::load(input, Expr::var("decode_scan_step"))),
                    Node::assign(
                        "state",
                        transition_expr(transitions, Expr::var("state"), Expr::var("byte")),
                    ),
                    Node::store(
                        matches,
                        Expr::var("decode_scan_step"),
                        Expr::load(accept, Expr::var("state")),
                    ),
                ],
            ),
        ],
    )]
}

/// Build a single-invocation tiled Aho-Corasick body over a caller-supplied
/// byte expression.
///
/// The body keeps DFA state in registers and advances over bounded tiles,
/// alternating the decoded byte through two scalar slots. For decoders that can
/// expose `byte_at(index)` cheaply, this avoids the old decode-buffer readback
/// pass: decode for the next slot and scan for the current slot are fused in one
/// loop nest. The optional `store_decoded` hook preserves the public decoded
/// buffer contract for existing builders.
#[must_use]
pub(crate) fn tiled_decode_aho_scan_body<ByteAt, StoreDecoded>(
    transitions: &str,
    accept: &str,
    matches: &str,
    valid_len: Expr,
    tile_width: u32,
    mut byte_at: ByteAt,
    mut store_decoded: StoreDecoded,
) -> Vec<Node>
where
    ByteAt: FnMut(Expr) -> Expr,
    StoreDecoded: FnMut(Expr, Expr) -> Option<Node>,
{
    let tile_width = tile_width.max(1).next_power_of_two();
    vec![Node::if_then(
        Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
        vec![
            Node::let_bind("state", Expr::u32(0)),
            Node::let_bind("decode_scan_ping", Expr::u32(0)),
            Node::let_bind("decode_scan_pong", Expr::u32(0)),
            Node::loop_for(
                "decode_scan_tile_base",
                Expr::u32(0),
                valid_len.clone(),
                vec![Node::if_then(
                    Expr::eq(
                        Expr::bitand(
                            Expr::sub(Expr::var("decode_scan_tile_base"), Expr::u32(0)),
                            Expr::u32(tile_width - 1),
                        ),
                        Expr::u32(0),
                    ),
                    vec![Node::loop_for(
                        "decode_scan_tile_lane",
                        Expr::u32(0),
                        Expr::u32(tile_width),
                        tiled_lane_body(
                            transitions,
                            accept,
                            matches,
                            valid_len.clone(),
                            &mut byte_at,
                            &mut store_decoded,
                        ),
                    )],
                )],
            ),
        ],
    )]
}

fn tiled_lane_body<ByteAt, StoreDecoded>(
    transitions: &str,
    accept: &str,
    matches: &str,
    valid_len: Expr,
    byte_at: &mut ByteAt,
    store_decoded: &mut StoreDecoded,
) -> Vec<Node>
where
    ByteAt: FnMut(Expr) -> Expr,
    StoreDecoded: FnMut(Expr, Expr) -> Option<Node>,
{
    let index = Expr::add(
        Expr::var("decode_scan_tile_base"),
        Expr::var("decode_scan_tile_lane"),
    );
    let slot_is_ping = Expr::eq(
        Expr::bitand(Expr::var("decode_scan_tile_lane"), Expr::u32(1)),
        Expr::u32(0),
    );
    let decoded = byte_at(index.clone());
    let mut body = vec![Node::let_bind("decode_scan_byte", decoded)];
    if let Some(store) = store_decoded(index.clone(), Expr::var("decode_scan_byte")) {
        body.push(store);
    }
    body.extend([
        Node::if_then_else(
            slot_is_ping,
            vec![Node::assign(
                "decode_scan_ping",
                Expr::var("decode_scan_byte"),
            )],
            vec![Node::assign(
                "decode_scan_pong",
                Expr::var("decode_scan_byte"),
            )],
        ),
        Node::assign(
            "state",
            transition_expr(
                transitions,
                Expr::var("state"),
                Expr::var("decode_scan_byte"),
            ),
        ),
        Node::store(
            matches,
            index.clone(),
            Expr::load(accept, Expr::var("state")),
        ),
    ]);
    vec![Node::if_then(Expr::lt(index, valid_len), body)]
}
