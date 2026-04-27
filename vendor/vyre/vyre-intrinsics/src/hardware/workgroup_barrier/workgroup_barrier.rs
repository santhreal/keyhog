//! Cat-C `workgroup_barrier` — per-lane identity store followed by a
//! workgroup-scope barrier. CPU reference is a no-op on the serial
//! interpreter (barrier semantics are a concurrency fence, invisible
//! sequentially). Backends lower the barrier to `workgroupBarrier`
//! (WGSL) / `OpControlBarrier Workgroup` (SPIR-V).

use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::hardware::{pack_u32, MAP_WORKGROUP};

/// Build a Program that emits a workgroup-scope memory barrier after an
/// identity store over `n` u32 lanes.
#[must_use]
pub fn workgroup_barrier(input: &str, out: &str, n: u32) -> Program {
    let body = vec![crate::region::wrap_anonymous(
        "vyre-intrinsics::hardware::workgroup_barrier",
        vec![
            Node::let_bind("idx", Expr::InvocationId { axis: 0 }),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::buf_len(out)),
                vec![Node::store(
                    out,
                    Expr::var("idx"),
                    Expr::load(input, Expr::var("idx")),
                )],
            ),
            Node::barrier(),
        ],
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::output(out, 1, DataType::U32).with_count(n),
        ],
        MAP_WORKGROUP,
        body,
    )
}

fn cpu_ref(input: &[u32]) -> Vec<u8> {
    pack_u32(input)
}

fn test_inputs() -> Vec<Vec<Vec<u8>>> {
    let input = vec![1u32, 2, 3, 4];
    let len = input.len() * 4;
    vec![vec![pack_u32(&input), vec![0u8; len]]]
}

fn expected_output() -> Vec<Vec<Vec<u8>>> {
    let input = vec![1u32, 2, 3, 4];
    vec![vec![cpu_ref(&input)]]
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-intrinsics::hardware::workgroup_barrier",
        build: || workgroup_barrier("input", "out", 4),
        test_inputs: Some(test_inputs),
        expected_output: Some(expected_output),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::{lcg_u32, run_program};

    fn assert_case(input: &[u32]) {
        let n = input.len() as u32;
        let program = workgroup_barrier("input", "out", n.max(1));
        let outputs = run_program(
            &program,
            vec![pack_u32(input), vec![0u8; (n.max(1) * 4) as usize]],
        );
        assert_eq!(outputs, vec![cpu_ref(input)]);
    }

    #[test]
    fn one_element() {
        assert_case(&[42]);
    }

    #[test]
    fn random_sixty_four() {
        let input = lcg_u32(0xB100_0011, 64);
        assert_case(&input);
    }
}
