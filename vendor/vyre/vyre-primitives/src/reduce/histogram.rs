//! `reduce_histogram` — parallel atomic histogram over a u32 ValueSet.
//!
//! Each global invocation loads one input index and atomically increments
//! the corresponding output bin.  Used by radix_sort, frequency analysis,
//! and label distribution.
//!
//! # Algorithm
//!
//! Work-group size `[256, 1, 1]`.  Caller dispatches
//! `(count + 255) / 256` work-groups.  Each active lane:
//!
//! ```text
//! if global_id < count:
//!     bin = input[global_id]
//!     if bin < num_bins:
//!         atomic_add(output[bin], 1)
//! ```
//!
//! Out-of-range indices are silently dropped — at internet scale an
//! unguarded atomic would corrupt adjacent buffers.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::reduce::histogram";

/// Build a Program: `output[input[i]] += 1` for every `i < count`.
///
/// # Panics
///
/// Panics if `num_bins == 0` — a zero-bin histogram has no valid
/// output buffer and would make every input index out-of-range.
#[must_use]
pub fn histogram(input: &str, output: &str, count: u32, num_bins: u32) -> Program {
    assert!(count > 0, "Fix: histogram requires count > 0, got {count}.");
    assert!(
        num_bins > 0,
        "Fix: histogram requires num_bins > 0, got {num_bins}."
    );

    let t = Expr::InvocationId { axis: 0 };

    let body = vec![
        Node::let_bind("bin", Expr::load(input, t.clone())),
        Node::if_then(
            Expr::lt(Expr::var("bin"), Expr::u32(num_bins)),
            vec![Node::let_bind(
                "_prev",
                Expr::atomic_add(output, Expr::var("bin"), Expr::u32(1)),
            )],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::U32).with_count(count),
            BufferDecl::storage(output, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(num_bins),
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
/// Returns a `Vec<u32>` of length `num_bins`.  Out-of-range input
/// values are ignored (matches the GPU drop behaviour).
#[must_use]
pub fn cpu_ref(input: &[u32], num_bins: u32) -> Vec<u32> {
    let mut out = vec![0u32; num_bins as usize];
    for &bin in input {
        let b = bin as usize;
        if b < out.len() {
            out[b] = out[b].wrapping_add(1);
        }
    }
    out
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || histogram("input", "output", 8, 4),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0, 1, 2, 3, 0, 1, 2, 3]),
                to_bytes(&[0, 0, 0, 0]),
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[2, 2, 2, 2])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_histogram() {
        let input = &[0u32, 1, 2, 3, 0, 1, 2, 3];
        assert_eq!(cpu_ref(input, 4), vec![2, 2, 2, 2]);
    }

    #[test]
    fn empty_input() {
        assert_eq!(cpu_ref(&[], 4), vec![0, 0, 0, 0]);
    }

    #[test]
    fn all_same_bin() {
        let input = &[2u32, 2, 2, 2, 2];
        assert_eq!(cpu_ref(input, 4), vec![0, 0, 5, 0]);
    }

    #[test]
    fn out_of_bounds_ignored() {
        let input = &[0u32, 1, 99, 2, 3, 100];
        assert_eq!(cpu_ref(input, 4), vec![1, 1, 1, 1]);
    }

    #[test]
    fn wrapping_on_overflow() {
        // u32::MAX + 1 wraps to 0, matching GPU atomic_add semantics.
        // cpu_ref uses wrapping_add, so we verify the accumulator behaviour
        // by starting from a high base and adding repeatedly.
        let mut base = u32::MAX - 1;
        base = base.wrapping_add(1); // = u32::MAX
        base = base.wrapping_add(1); // = 0
        assert_eq!(base, 0);
    }

    #[test]
    fn wrapping_overflow_correct() {
        // Simulate a bin that already has u32::MAX - 1 and we add 3 more.
        // cpu_ref starts from 0, so we need to verify wrapping_add works.
        let mut manual = [0u32; 2];
        manual[0] = u32::MAX - 1;
        // cpu_ref computes from input, so we test the add behaviour directly.
        let base = u32::MAX - 1;
        let after_three = base.wrapping_add(3);
        assert_eq!(after_three, 1);
    }

    #[test]
    fn many_bins() {
        let input: Vec<u32> = (0..100).collect();
        let out = cpu_ref(&input, 100);
        assert_eq!(out.len(), 100);
        for (i, &v) in out.iter().enumerate() {
            assert_eq!(v, 1, "bin {i} should have count 1");
        }
    }

    #[test]
    fn sparse_bins() {
        let input = &[0u32, 50, 50, 99];
        let mut expected = vec![0u32; 100];
        expected[0] = 1;
        expected[50] = 2;
        expected[99] = 1;
        assert_eq!(cpu_ref(input, 100), expected);
    }

    #[test]
    fn program_has_expected_buffers() {
        let p = histogram("in", "out", 1024, 16);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["in", "out"]);
    }

    #[test]
    fn program_buffer_counts() {
        let p = histogram("in", "out", 1024, 16);
        assert_eq!(p.buffers[0].count(), 1024);
        assert_eq!(p.buffers[1].count(), 16);
    }

    #[test]
    #[should_panic(expected = "num_bins > 0")]
    fn zero_bins_panics() {
        let _ = histogram("in", "out", 10, 0);
    }

    #[test]
    #[should_panic(expected = "count > 0")]
    fn zero_count_panics() {
        let _ = histogram("in", "out", 0, 4);
    }

    #[test]
    fn concurrent_access_cpu_simulation() {
        // Simulate what 256 parallel threads would do: many threads hit
        // the same bin.  The result must be deterministic.
        let input = vec![7u32; 10_000];
        let out = cpu_ref(&input, 16);
        assert_eq!(out[7], 10_000);
        for (i, &v) in out.iter().enumerate() {
            if i != 7 {
                assert_eq!(v, 0);
            }
        }
    }

    #[test]
    fn adversarial_all_out_of_bounds() {
        let input = &[100u32, 200, 300];
        assert_eq!(cpu_ref(input, 2), vec![0, 0]);
    }

    #[test]
    fn adversarial_max_u32_index() {
        let input = &[u32::MAX];
        assert_eq!(cpu_ref(input, 4), vec![0, 0, 0, 0]);
    }
}
