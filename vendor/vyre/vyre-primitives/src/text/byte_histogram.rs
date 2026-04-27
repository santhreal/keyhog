//! Byte histogram primitive over `u32`-packed bytes.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::{GeneratorRef, Ident};
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id for the 256-bin byte histogram primitive.
pub const BYTE_HISTOGRAM_256_OP_ID: &str = "vyre-primitives::text::byte_histogram_256";

/// Build the reusable histogram body.
#[must_use]
pub fn byte_histogram_256_body(input: &str, histogram: &str, count: u32) -> Vec<Node> {
    let rounds = Expr::div(Expr::add(Expr::u32(count), Expr::u32(255)), Expr::u32(256));
    vec![
        Node::let_bind("lane", Expr::InvocationId { axis: 0 }),
        Node::store(histogram, Expr::var("lane"), Expr::u32(0)),
        Node::Barrier,
        Node::loop_for(
            "round",
            Expr::u32(0),
            rounds,
            vec![
                Node::let_bind(
                    "idx",
                    Expr::add(
                        Expr::mul(Expr::var("round"), Expr::u32(256)),
                        Expr::var("lane"),
                    ),
                ),
                Node::if_then(
                    Expr::lt(Expr::var("idx"), Expr::u32(count)),
                    vec![
                        Node::let_bind("word", Expr::load(input, Expr::var("idx"))),
                        Node::let_bind("byte", Expr::bitand(Expr::var("word"), Expr::u32(0xFF))),
                        Node::let_bind(
                            "_prev_hist",
                            Expr::atomic_add(histogram, Expr::var("byte"), Expr::u32(1)),
                        ),
                    ],
                ),
            ],
        ),
        Node::Barrier,
    ]
}

/// Wrap the histogram body as a child of `parent_op_id`.
#[must_use]
pub fn byte_histogram_256_child(
    parent_op_id: &str,
    input: &str,
    histogram: &str,
    count: u32,
) -> Node {
    Node::Region {
        generator: Ident::from(BYTE_HISTOGRAM_256_OP_ID),
        source_region: Some(GeneratorRef {
            name: parent_op_id.to_string(),
        }),
        body: Arc::new(byte_histogram_256_body(input, histogram, count)),
    }
}

/// Standalone histogram program for primitive-level conformance.
#[must_use]
pub fn byte_histogram_256(input: &str, histogram: &str, count: u32) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(count.max(1)),
            BufferDecl::output(histogram, 1, DataType::U32)
                .with_count(256)
                .with_output_byte_range(0..256 * 4),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(BYTE_HISTOGRAM_256_OP_ID),
            source_region: None,
            body: Arc::new(byte_histogram_256_body(input, histogram, count)),
        }],
    )
}

/// CPU reference for [`byte_histogram_256`].
#[must_use]
pub fn cpu_ref(bytes: &[u8]) -> [u32; 256] {
    let mut histogram = [0u32; 256];
    for &byte in bytes {
        histogram[usize::from(byte)] += 1;
    }
    histogram
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        BYTE_HISTOGRAM_256_OP_ID,
        || byte_histogram_256("bytes", "histogram", 5),
        Some(|| {
            vec![vec![
                [b'a', b'b', b'a', 0xC3, 0xA9]
                    .into_iter()
                    .flat_map(|byte| u32::from(byte).to_le_bytes())
                    .collect(),
                vec![0; 256 * 4],
            ]]
        }),
        Some(|| {
            let histogram = cpu_ref(&[b'a', b'b', b'a', 0xC3, 0xA9]);
            vec![vec![histogram.iter().flat_map(|value| value.to_le_bytes()).collect()]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_ref_counts_each_byte() {
        let histogram = cpu_ref(&[b'a', b'b', b'a', 0xC3, 0xA9]);
        assert_eq!(histogram[usize::from(b'a')], 2);
        assert_eq!(histogram[usize::from(b'b')], 1);
        assert_eq!(histogram[0xC3], 1);
        assert_eq!(histogram[0xA9], 1);
    }
}
