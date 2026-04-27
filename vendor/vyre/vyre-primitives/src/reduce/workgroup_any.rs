//! Workgroup-local OR reduction over a u32 scratch buffer.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::{GeneratorRef, Ident};
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id for workgroup-local u32 any reduction.
pub const WORKGROUP_ANY_U32_OP_ID: &str = "vyre-primitives::reduce::workgroup_any_u32";

/// Build a body that assigns `out_var = bit_or(values[0..count])`.
#[must_use]
pub fn workgroup_any_u32_body(values: &str, out_var: &str, count: u32) -> Vec<Node> {
    vec![
        Node::assign(out_var, Expr::u32(0)),
        Node::loop_for(
            "i",
            Expr::u32(0),
            Expr::u32(count),
            vec![Node::assign(
                out_var,
                Expr::bitor(Expr::var(out_var), Expr::load(values, Expr::var("i"))),
            )],
        ),
    ]
}

/// Wrap the workgroup any body as a child of `parent_op_id`.
#[must_use]
pub fn workgroup_any_u32_child(
    parent_op_id: &str,
    values: &str,
    out_var: &str,
    count: u32,
) -> Node {
    Node::Region {
        generator: Ident::from(WORKGROUP_ANY_U32_OP_ID),
        source_region: Some(GeneratorRef {
            name: parent_op_id.to_string(),
        }),
        body: Arc::new(workgroup_any_u32_body(values, out_var, count)),
    }
}

/// Standalone workgroup-any program for primitive-level conformance.
#[must_use]
pub fn workgroup_any_u32(values: &str, out: &str, count: u32) -> Program {
    let mut body = vec![Node::let_bind("any_changed", Expr::u32(0))];
    body.extend(workgroup_any_u32_body(values, "any_changed", count));
    body.push(Node::store(out, Expr::u32(0), Expr::var("any_changed")));
    Program::wrapped(
        vec![
            BufferDecl::storage(values, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(count.max(1)),
            BufferDecl::output(out, 1, DataType::U32)
                .with_count(1)
                .with_output_byte_range(0..4),
        ],
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(WORKGROUP_ANY_U32_OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference for [`workgroup_any_u32`].
#[must_use]
pub fn cpu_ref(values: &[u32]) -> u32 {
    values.iter().fold(0u32, |acc, value| acc | value)
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        WORKGROUP_ANY_U32_OP_ID,
        || workgroup_any_u32("values", "out", 4),
        Some(|| vec![vec![
            [0u32, 0, 7, 0].into_iter().flat_map(|value| value.to_le_bytes()).collect(),
            vec![0; 4],
        ]]),
        Some(|| vec![vec![7u32.to_le_bytes().to_vec()]]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_ref_ors_values() {
        assert_eq!(cpu_ref(&[0, 2, 4, 0]), 6);
    }
}
