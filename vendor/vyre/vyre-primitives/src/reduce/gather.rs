//! `reduce_gather` — parallel gather over a u32 ValueSet.
//!
//! Each global invocation loads one index and, if in-range, copies
//! `src[index]` into `dst[global_id]`.  Used by graph operations for
//! indirect access patterns (e.g. pulling node properties via edge
//! indices).
//!
//! # Algorithm
//!
//! Work-group size `[256, 1, 1]`.  Caller dispatches
//! `(count + 255) / 256` work-groups.  Each active lane:
//!
//! ```text
//! if global_id < count:
//!     idx = indices[global_id]
//!     if idx < count:
//!         dst[global_id] = src[idx]
//! ```
//!
//! Out-of-range indices are silently dropped — at internet scale an
//! unguarded load would read past the end of the source buffer.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::reduce::gather";

/// Build a Program: `dst[i] = src[indices[i]]` for every `i < count`
/// where `indices[i] < count`.
///
/// # Panics
///
/// Panics if `count == 0` — a zero-element gather has no valid output
/// buffer and would make every dispatch a no-op.
#[must_use]
pub fn gather(src: &str, indices: &str, dst: &str, count: u32) -> Program {
    assert!(count > 0, "Fix: gather requires count > 0, got {count}.");

    let t = Expr::InvocationId { axis: 0 };

    let body = vec![
        Node::let_bind("idx", Expr::load(indices, t.clone())),
        Node::if_then(
            Expr::lt(Expr::var("idx"), Expr::u32(count)),
            vec![Node::store(
                dst,
                t.clone(),
                Expr::load(src, Expr::var("idx")),
            )],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(src, 0, BufferAccess::ReadOnly, DataType::U32).with_count(count),
            BufferDecl::storage(indices, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(count),
            BufferDecl::storage(dst, 2, BufferAccess::ReadWrite, DataType::U32).with_count(count),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::lt(t.clone(), Expr::u32(count)),
                body,
            )]),
        }],
    )
}

/// CPU reference.
///
/// Returns a `Vec<u32>` of length `indices.len()`.  Out-of-range
/// indices **panic** so that conformance tests with invalid data fail
/// loudly rather than silently producing wrong results.
#[must_use]
pub fn cpu_ref(src: &[u32], indices: &[u32]) -> Vec<u32> {
    indices
        .iter()
        .map(|&idx| {
            let i = idx as usize;
            assert!(
                i < src.len(),
                "Fix: gather index {idx} out of bounds for src length {}.",
                src.len()
            );
            src[i]
        })
        .collect()
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || gather("src", "indices", "dst", 4),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[10, 20, 30, 40]),
                to_bytes(&[3, 0, 2, 1]),
                to_bytes(&[0, 0, 0, 0]),
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[40, 10, 30, 20])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_gather() {
        let src = &[10u32, 20, 30, 40];
        let indices = &[3u32, 0, 2, 1];
        assert_eq!(cpu_ref(src, indices), vec![40, 10, 30, 20]);
    }

    #[test]
    fn identity_gather() {
        let src = &[1u32, 2, 3, 4, 5];
        let indices = &[0u32, 1, 2, 3, 4];
        assert_eq!(cpu_ref(src, indices), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn empty_indices() {
        let src = &[1u32, 2, 3];
        let indices: &[u32] = &[];
        assert_eq!(cpu_ref(src, indices), Vec::<u32>::new());
    }

    #[test]
    fn single_element() {
        let src = &[42u32];
        let indices = &[0u32];
        assert_eq!(cpu_ref(src, indices), vec![42]);
    }

    #[test]
    fn repeated_index() {
        let src = &[7u32, 8, 9];
        let indices = &[0u32, 0, 0, 2, 2];
        assert_eq!(cpu_ref(src, indices), vec![7, 7, 7, 9, 9]);
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn cpu_ref_panics_on_out_of_bounds() {
        let src = &[1u32, 2, 3];
        let indices = &[0u32, 5]; // 5 is out of bounds
        let _ = cpu_ref(src, indices);
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn cpu_ref_panics_on_max_u32_index() {
        let src = &[1u32, 2, 3];
        let indices = &[u32::MAX];
        let _ = cpu_ref(src, indices);
    }

    #[test]
    fn program_has_expected_buffers() {
        let p = gather("src", "indices", "dst", 1024);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["src", "indices", "dst"]);
    }

    #[test]
    fn program_buffer_counts() {
        let p = gather("src", "indices", "dst", 1024);
        assert_eq!(p.buffers[0].count(), 1024);
        assert_eq!(p.buffers[1].count(), 1024);
        assert_eq!(p.buffers[2].count(), 1024);
    }

    #[test]
    #[should_panic(expected = "count > 0")]
    fn zero_count_panics() {
        let _ = gather("src", "indices", "dst", 0);
    }

    #[test]
    fn adversarial_all_out_of_bounds_program() {
        // The program itself must compile and have the right shape even
        // when the indices it will process are all out-of-bounds.
        let p = gather("src", "indices", "dst", 4);
        assert_eq!(p.buffers[1].count(), 4);
    }

    #[test]
    fn concurrent_access_cpu_simulation() {
        // Simulate what 256 parallel threads would do: many threads read
        // from the same source slot.  The result must be deterministic.
        let src = &[100u32; 1];
        let indices = vec![0u32; 10_000];
        let out = cpu_ref(src, &indices);
        assert_eq!(out.len(), 10_000);
        assert!(out.iter().all(|&v| v == 100));
    }
}
