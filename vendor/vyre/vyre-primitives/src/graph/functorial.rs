//! Functorial data migration primitive (#52).
//!
//! Categorical data migration (Spivak 2012, Patterson 2022 Catlab.jl):
//! treat schema migrations between databases as functors `F: C → D`.
//! Each instance migration is a graph rewrite.
//!
//! This file ships the **per-cell functor application** primitive —
//! given a source-instance row, a functor encoded as a column-mapping
//! lookup table, emit the target-instance row. Composes with
//! `level_wave_program` for whole-schema migration.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Op id.
pub const OP_ID: &str = "vyre-primitives::graph::functor_apply";

/// Apply column-mapping functor to a source-instance row.
/// `source_row[i]` becomes `target_row[mapping[i]]` for `i ∈ 0..n_cols`.
#[must_use]
pub fn functor_apply(source_row: &str, mapping: &str, target_row: &str, n_cols: u32) -> Program {
    if n_cols == 0 {
        return crate::invalid_output_program(
            OP_ID,
            target_row,
            DataType::U32,
            "Fix: functor_apply requires n_cols > 0, got 0.".to_string(),
        );
    }

    let t = Expr::InvocationId { axis: 0 };
    let target_idx = Expr::load(mapping, t.clone());
    let value = Expr::load(source_row, t.clone());

    let body = vec![Node::if_then(
        Expr::lt(t.clone(), Expr::u32(n_cols)),
        vec![Node::store(target_row, target_idx, value)],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(source_row, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n_cols),
            BufferDecl::storage(mapping, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n_cols),
            BufferDecl::storage(target_row, 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(n_cols),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference.
#[must_use]
pub fn functor_apply_cpu(source_row: &[u32], mapping: &[u32], target_size: u32) -> Vec<u32> {
    let mut out = vec![0u32; target_size as usize];
    for (&src, &dst) in source_row.iter().zip(mapping.iter()) {
        if let Some(slot) = out.get_mut(dst as usize) {
            *slot = src;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_identity_mapping() {
        let src = vec![10u32, 20, 30];
        let map = vec![0u32, 1, 2];
        let out = functor_apply_cpu(&src, &map, 3);
        assert_eq!(out, src);
    }

    #[test]
    fn cpu_permutation_mapping() {
        let src = vec![10u32, 20, 30];
        let map = vec![2u32, 0, 1];
        let out = functor_apply_cpu(&src, &map, 3);
        assert_eq!(out, vec![20, 30, 10]);
    }

    #[test]
    fn cpu_target_larger_than_source_zero_padded() {
        let src = vec![10u32, 20];
        let map = vec![0u32, 2];
        let out = functor_apply_cpu(&src, &map, 4);
        assert_eq!(out, vec![10, 0, 20, 0]);
    }

    #[test]
    fn cpu_mismatched_or_out_of_range_mapping_is_ignored() {
        let out = functor_apply_cpu(&[7, 8], &[3], 2);
        assert_eq!(out, vec![0, 0]);
    }

    #[test]
    fn ir_program_buffer_layout() {
        let p = functor_apply("s", "m", "t", 8);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        for buf in p.buffers.iter() {
            assert_eq!(buf.count(), 8);
        }
    }

    #[test]
    fn zero_n_cols_traps() {
        let p = functor_apply("s", "m", "t", 0);
        assert!(p.stats().trap());
    }
}
