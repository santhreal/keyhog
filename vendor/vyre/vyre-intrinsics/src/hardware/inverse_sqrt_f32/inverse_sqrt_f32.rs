//! Cat-C `inverse_sqrt_f32` — `1 / sqrt(x)` per f32 lane.
//! CPU reference: `1.0 / f32::sqrt(x)` bit-exact (that exact expression).

use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::hardware::{pack_f32, MAP_WORKGROUP};

/// Build a Program that computes `out[i] = 1.0 / sqrt(input[i])` over `n` f32 lanes.
#[must_use]
pub fn inverse_sqrt_f32(input: &str, out: &str, n: u32) -> Program {
    let body = vec![crate::region::wrap_anonymous(
        "vyre-intrinsics::hardware::inverse_sqrt_f32",
        vec![
            Node::let_bind("idx", Expr::InvocationId { axis: 0 }),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::buf_len(out)),
                vec![Node::store(
                    out,
                    Expr::var("idx"),
                    Expr::inverse_sqrt(Expr::load(input, Expr::var("idx"))),
                )],
            ),
        ],
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::output(out, 1, DataType::F32).with_count(n),
        ],
        MAP_WORKGROUP,
        body,
    )
}

fn cpu_ref(input: &[f32]) -> Vec<u8> {
    pack_f32(&input.iter().map(|&x| 1.0 / x.sqrt()).collect::<Vec<_>>())
}

fn test_inputs() -> Vec<Vec<Vec<u8>>> {
    let input = vec![1.0f32, 4.0, 9.0, 16.0];
    let len = input.len() * 4;
    vec![vec![pack_f32(&input), vec![0u8; len]]]
}

fn expected_output() -> Vec<Vec<Vec<u8>>> {
    let input = vec![1.0f32, 4.0, 9.0, 16.0];
    vec![vec![cpu_ref(&input)]]
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-intrinsics::hardware::inverse_sqrt_f32",
        build: || inverse_sqrt_f32("input", "out", 4),
        test_inputs: Some(test_inputs),
        expected_output: Some(expected_output),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::{lcg_f32, run_program};

    fn assert_case(input: &[f32]) {
        let n = input.len() as u32;
        let program = inverse_sqrt_f32("input", "out", n.max(1));
        let outputs = run_program(
            &program,
            vec![pack_f32(input), vec![0u8; (n.max(1) * 4) as usize]],
        );
        assert_eq!(outputs, vec![cpu_ref(input)]);
    }

    #[test]
    fn one_element() {
        assert_case(&[4.0]);
    }

    #[test]
    fn known_values() {
        assert_case(&[1.0, 4.0, 9.0, 16.0, 25.0, 100.0]);
    }

    #[test]
    fn random_sixty_four() {
        // Positive values only — `1/sqrt(negative)` is NaN.
        let input: Vec<f32> = lcg_f32(0x0F1A_A005, 64)
            .into_iter()
            .map(|v| v.abs() + 0.01)
            .collect();
        assert_case(&input);
    }
}
