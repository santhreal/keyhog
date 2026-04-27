//! `range_check` — interval-VSA bound check. Composes the per-node
//! interval table with a comparison against a known bound.
//!
//! Per node `n`, write 1 to `out[n]` iff `interval(n).hi < bound[n]`.
//! Surgec rules use this for CWE-787 / CWE-190 to assert "size is
//! bounded by destination buffer length."

use std::sync::Arc;
use vyre::ir::Program;
use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node};
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "vyre-libs::dataflow::range_check";

/// Build a range-check Program. Inputs:
/// - `interval_hi`: per-node u32 buffer of interval upper bounds.
/// - `bound`:       per-node u32 buffer of allowed maxima.
/// - `out`:         per-node bitset; bit `n` set iff `interval_hi[n] < bound[n]`.
#[must_use]
pub fn range_check(node_count: u32, interval_hi: &str, bound: &str, out: &str) -> Program {
    let _words = bitset_words(node_count);
    let t = Expr::InvocationId { axis: 0 };
    let body = vec![Node::store(
        out,
        t.clone(),
        Expr::lt(
            Expr::load(interval_hi, t.clone()),
            Expr::load(bound, t.clone()),
        ),
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(interval_hi, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(node_count),
            BufferDecl::storage(bound, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(node_count),
            BufferDecl::storage(out, 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(node_count),
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

/// CPU oracle.
#[must_use]
pub fn cpu_ref(interval_hi: &[u32], bound: &[u32]) -> Vec<u32> {
    let n = interval_hi.len().min(bound.len());
    (0..n)
        .map(|i| u32::from(interval_hi[i] < bound[i]))
        .collect()
}

/// Soundness marker for [`range_check`].
pub struct RangeCheck;
impl super::soundness::SoundnessTagged for RangeCheck {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::Exact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_bound_returns_one() {
        assert_eq!(cpu_ref(&[5, 10, 15], &[10, 20, 30]), vec![1, 1, 1]);
    }

    #[test]
    fn at_bound_returns_zero() {
        assert_eq!(cpu_ref(&[10, 20], &[10, 20]), vec![0, 0]);
    }

    #[test]
    fn over_bound_returns_zero() {
        assert_eq!(cpu_ref(&[100], &[10]), vec![0]);
    }

    #[test]
    fn mixed_bounds() {
        assert_eq!(cpu_ref(&[1, 100, 5], &[10, 10, 100]), vec![1, 0, 1]);
    }
}
