//! GELU (Gaussian Error Linear Unit): `y = 0.5 * x * (1 + tanh(sqrt(2/π) * (x + 0.044715 * x^3)))`.
//!
//! Category A composition.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp};

use crate::region::wrap_anonymous;

const GELU_SQRT_2_OVER_PI: f32 = 0.797_884_6;
const GELU_COEF: f32 = 0.044715;

/// Build a Program that applies GELU element-wise from `input` into
/// `output`. `n` is the element count of both buffers.
#[must_use]
pub fn gelu(input: &str, output: &str, n: u32) -> Program {
    let i = Expr::var("i");
    let x = Expr::load(input, i.clone());

    // tanh approximation: 0.5 * x * (1 + tanh(sqrt(2/pi) * (x + 0.044715 * x^3)))
    let x3 = Expr::mul(Expr::mul(x.clone(), x.clone()), x.clone());
    let inner = Expr::mul(
        Expr::f32(GELU_SQRT_2_OVER_PI),
        Expr::add(x.clone(), Expr::mul(Expr::f32(GELU_COEF), x3)),
    );
    let tanh_inner = Expr::UnOp {
        op: UnOp::Tanh,
        operand: Box::new(inner),
    };
    let gelu_val = Expr::mul(
        Expr::f32(0.5),
        Expr::mul(x.clone(), Expr::add(Expr::f32(1.0), tanh_inner)),
    );

    let body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::buf_len(input)),
            vec![Node::Store {
                buffer: output.into(),
                index: i,
                value: gelu_val,
            }],
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::output(output, 1, DataType::F32).with_count(n),
        ],
        [64, 1, 1],
        vec![wrap_anonymous("vyre-libs::nn::gelu", body)],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::nn::gelu",
        build: || gelu("input", "output", 4),
        test_inputs: Some(|| {
            let to_bytes = |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0.0_f32, 1.0, -1.0, 2.0]), // input
            ]]
        }),
        expected_output: Some(|| {
            let input = [0.0_f32, 1.0, -1.0, 2.0];
            let out: Vec<f32> = input
                .iter()
                .map(|&x| {
                    let x3 = x * x * x;
                    let inner = GELU_SQRT_2_OVER_PI * (x + GELU_COEF * x3);
                    0.5 * x * (1.0 + inner.tanh())
                })
                .collect();
            let bytes = out
                .iter()
                .flat_map(|v| v.to_bits().to_le_bytes())
                .collect::<Vec<u8>>();
            vec![vec![bytes]]
        }),
        category: Some("nn"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_reference::value::Value;

    fn f32_bytes(values: &[f32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    fn decode_f32(bytes: &[u8]) -> Vec<f32> {
        bytes
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes(c.try_into().unwrap()))
            .collect()
    }

    fn gelu_ref(x: f32) -> f32 {
        let x3 = x * x * x;
        let inner = GELU_SQRT_2_OVER_PI * (x + GELU_COEF * x3);
        0.5 * x * (1.0 + inner.tanh())
    }

    #[test]
    fn gelu_all_zeros() {
        let input = [0.0f32; 4];
        let program = gelu("input", "output", 4);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[Value::from(f32_bytes(&input)), Value::from(vec![0u8; 16])],
        )
        .expect("Fix: gelu all-zeros must execute");
        let out = decode_f32(&outputs[0].to_bytes());
        assert_eq!(out, vec![0.0; 4]);
    }

    #[test]
    fn gelu_positive_values() {
        let input = [1.0f32, 2.0, 3.0, 4.0];
        let program = gelu("input", "output", 4);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[Value::from(f32_bytes(&input)), Value::from(vec![0u8; 16])],
        )
        .expect("Fix: gelu positive values must execute");
        let out = decode_f32(&outputs[0].to_bytes());
        for (i, (&v, expected)) in out
            .iter()
            .zip(input.iter().copied().map(gelu_ref))
            .enumerate()
        {
            assert!(
                (v - expected).abs() <= 1.0e-5,
                "gelu mismatch at {i}: {v} != {expected}"
            );
        }
    }

    #[test]
    fn gelu_negative_values() {
        let input = [-1.0f32, -2.0, -0.5, -3.0];
        let program = gelu("input", "output", 4);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[Value::from(f32_bytes(&input)), Value::from(vec![0u8; 16])],
        )
        .expect("Fix: gelu negative values must execute");
        let out = decode_f32(&outputs[0].to_bytes());
        for (i, (&v, expected)) in out
            .iter()
            .zip(input.iter().copied().map(gelu_ref))
            .enumerate()
        {
            assert!(
                (v - expected).abs() <= 1.0e-5,
                "gelu mismatch at {i}: {v} != {expected}"
            );
        }
    }

    #[test]
    fn gelu_empty_tensor() {
        let program = gelu("input", "output", 0);
        let outputs =
            vyre_reference::reference_eval(&program, &[Value::from(vec![]), Value::from(vec![])])
                .expect("Fix: gelu n=0 must not panic");
        assert!(outputs[0].to_bytes().is_empty());
    }

    #[test]
    fn gelu_nan_input_propagates_nan() {
        let input = [f32::NAN];
        let program = gelu("input", "output", 1);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[Value::from(f32_bytes(&input)), Value::from(vec![0u8; 4])],
        )
        .expect("Fix: gelu must not panic on NaN input");
        let out = decode_f32(&outputs[0].to_bytes());
        assert!(out[0].is_nan(), "gelu(NaN) must be NaN");
    }
}
