//! `resolve_family` — `node_tags[v] & family_mask != 0` → NodeSet bit v.
//!
//! One invocation per node. Reads the per-node tag bitmap, ANDs it
//! against the compile-time family mask, atomically-ORs the result
//! bit into `nodeset_out[v / 32]`.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::label::resolve_family";

/// Build a Program: for each node `v`, if
/// `node_tags[v] & family_mask != 0`, set bit `v` in `nodeset_out`.
#[must_use]
pub fn resolve_family(
    node_tags: &str,
    nodeset_out: &str,
    node_count: u32,
    family_mask: u32,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let words = node_count.div_ceil(32);
    let body = vec![
        Node::let_bind("tag", Expr::load(node_tags, t.clone())),
        Node::if_then(
            Expr::ne(
                Expr::bitand(Expr::var("tag"), Expr::u32(family_mask)),
                Expr::u32(0),
            ),
            vec![
                Node::let_bind("word_idx", Expr::shr(t.clone(), Expr::u32(5))),
                Node::let_bind(
                    "bit",
                    Expr::shl(Expr::u32(1), Expr::bitand(t.clone(), Expr::u32(31))),
                ),
                Node::let_bind(
                    "_",
                    Expr::atomic_or(nodeset_out, Expr::var("word_idx"), Expr::var("bit")),
                ),
            ],
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage(node_tags, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(node_count),
            BufferDecl::storage(nodeset_out, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(words),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::lt(t.clone(), Expr::u32(node_count)),
                body,
            )]),
        }],
    )
}

/// CPU reference.
///
/// # Panics
///
/// Panics if `node_tags.len() > u32::MAX`. AUDIT_2026-04-24 F-RF-02:
/// prior `as u32` truncation silently dropped every node whose index
/// was above the u32 range, producing a shorter bitset than the GPU
/// path with no diagnostic. The contract is a u32 node-id space, so
/// any slice above it is a producer bug that now fails loudly.
#[must_use]
pub fn cpu_ref(node_tags: &[u32], family_mask: u32) -> Vec<u32> {
    let n = u32::try_from(node_tags.len()).expect(
        "resolve_family cpu_ref: node_tags.len() exceeds u32::MAX — node-id space is u32 by \
         contract; split the graph or redesign the caller",
    );
    let words = n.div_ceil(32) as usize;
    let mut out = vec![0u32; words];
    for (v, tag) in node_tags.iter().enumerate() {
        if (tag & family_mask) != 0 {
            let word = v / 32;
            let bit = 1u32 << (v % 32);
            out[word] |= bit;
        }
    }
    out
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || resolve_family("tags", "nodeset", 4, 0b0010),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // node_tags: 0x01, 0x02, 0x06, 0x04 — family mask 0x02
            // hits nodes 1 and 2 (0x02 and 0x06 both have bit 1).
            vec![vec![to_bytes(&[0x01, 0x02, 0x06, 0x04]), to_bytes(&[0])]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0b0110])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_family_bit() {
        assert_eq!(cpu_ref(&[0x01, 0x02, 0x06, 0x04], 0x02), vec![0b0110]);
    }

    #[test]
    fn empty_family_yields_empty_nodeset() {
        assert_eq!(cpu_ref(&[0x01, 0x02], 0x00), vec![0]);
    }
}
