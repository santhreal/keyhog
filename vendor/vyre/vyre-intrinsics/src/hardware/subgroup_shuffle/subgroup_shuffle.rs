//! Cat-C `subgroup_shuffle` — per-lane permutation via source-lane indices.
//! Maps to hardware `subgroupShuffle()`. Serial CPU reference
//! (SUBGROUP_WIDTH=1): `lane == 0 ? value : 0`. Feature-gated behind
//! `subgroup-ops`.

use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

#[cfg(any(test, feature = "subgroup-ops"))]
use crate::hardware::pack_u32;
use crate::hardware::MAP_WORKGROUP;

/// Build a Program that maps `out[i] = values[lanes[i]]` across the subgroup.
/// Serial CPU reference (SUBGROUP_WIDTH=1): `out[i] = lanes[i] == 0 ? values[i] : 0`.
#[must_use]
pub fn subgroup_shuffle(values: &str, lanes: &str, out: &str, n: u32) -> Program {
    let body = vec![crate::region::wrap_anonymous(
        "vyre-intrinsics::hardware::subgroup_shuffle",
        vec![
            Node::let_bind("idx", Expr::InvocationId { axis: 0 }),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::buf_len(out)),
                vec![Node::store(
                    out,
                    Expr::var("idx"),
                    Expr::SubgroupShuffle {
                        value: Box::new(Expr::load(values, Expr::var("idx"))),
                        lane: Box::new(Expr::load(lanes, Expr::var("idx"))),
                    },
                )],
            ),
        ],
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(values, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::storage(lanes, 1, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::output(out, 2, DataType::U32).with_count(n),
        ],
        MAP_WORKGROUP,
        body,
    )
}

#[cfg(any(test, feature = "subgroup-ops"))]
fn cpu_ref(values: &[u32], lanes: &[u32]) -> Vec<u8> {
    // With `subgroup-ops` enabled the reference interpreter
    // permutes inside a 32-wide subgroup: each lane i returns
    // values[subgroup_start + lanes[i]] where subgroup_start is
    // (i / 32) * 32. Without the feature, SubgroupShuffle stays
    // single-lane: `lanes[i] == 0 ? values[i] : 0`.
    #[cfg(feature = "subgroup-ops")]
    {
        const SUBGROUP_WIDTH: usize = 32;
        let n = values.len().min(lanes.len());
        let mut out = Vec::with_capacity(n);
        for (i, lane) in lanes.iter().take(n).enumerate() {
            let subgroup_start = (i / SUBGROUP_WIDTH) * SUBGROUP_WIDTH;
            let src = subgroup_start + (*lane as usize);
            out.push(values.get(src).copied().unwrap_or(0));
        }
        return pack_u32(&out);
    }
    #[allow(unreachable_code)]
    pack_u32(
        &values
            .iter()
            .zip(lanes.iter())
            .map(|(&v, &l)| if l == 0 { v } else { 0 })
            .collect::<Vec<_>>(),
    )
}

#[cfg(feature = "subgroup-ops")]
fn test_inputs() -> Vec<Vec<Vec<u8>>> {
    let values = vec![10u32, 20, 30, 40];
    let lanes = vec![0u32, 1, 0, 2];
    let len = values.len() * 4;
    vec![vec![pack_u32(&values), pack_u32(&lanes), vec![0u8; len]]]
}

#[cfg(feature = "subgroup-ops")]
fn expected_output() -> Vec<Vec<Vec<u8>>> {
    let values = vec![10u32, 20, 30, 40];
    let lanes = vec![0u32, 1, 0, 2];
    vec![vec![cpu_ref(&values, &lanes)]]
}

#[cfg(feature = "subgroup-ops")]
inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-intrinsics::hardware::subgroup_shuffle",
        build: || subgroup_shuffle("values", "lanes", "out", 4),
        test_inputs: Some(test_inputs),
        expected_output: Some(expected_output),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::run_program;

    fn assert_case(values: &[u32], lanes: &[u32]) {
        let n = values.len() as u32;
        let program = subgroup_shuffle("values", "lanes", "out", n.max(1));
        let outputs = run_program(
            &program,
            vec![
                pack_u32(values),
                pack_u32(lanes),
                vec![0u8; (n.max(1) * 4) as usize],
            ],
        );
        assert_eq!(outputs, vec![cpu_ref(values, lanes)]);
    }

    #[test]
    fn lane_zero_passes_through() {
        assert_case(&[7, 9, 11], &[0, 0, 0]);
    }
    #[test]
    fn nonzero_lane_zeros() {
        assert_case(&[7, 9, 11], &[1, 2, 3]);
    }
    #[test]
    fn mixed() {
        assert_case(&[1, 2, 3, 4, 5, 6, 7, 8], &[0, 1, 0, 2, 0, 0, 3, 4]);
    }
}
