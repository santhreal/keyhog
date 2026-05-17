//! Logit softcap: `y = tanh(x / cap) * cap`.
//!
//! Category A composition — element-wise. Used in the Parameter Golf
//! recipe to bound logits before cross-entropy loss (default cap=30.0).

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp};

use crate::region::wrap_anonymous;

const OP_ID: &str = "vyre-libs::nn::logit_softcap";

fn flush_tiny(value: Expr) -> Expr {
    Expr::select(
        Expr::le(Expr::abs(value.clone()), Expr::f32(f32::MIN_POSITIVE)),
        Expr::f32(0.0),
        value,
    )
}

/// Build a Program that applies `tanh(x / cap) * cap` element-wise.
#[must_use]
pub fn logit_softcap(input: &str, output: &str, n: u32, cap: f32) -> Program {
    let i = Expr::var("i");
    let x = Expr::load(input, i.clone());

    // tanh(x / cap) * cap
    let scaled = Expr::div(x, Expr::f32(cap));
    let tanh_val = Expr::UnOp {
        op: UnOp::Tanh,
        operand: Box::new(scaled),
    };
    let result = Expr::mul(tanh_val, Expr::f32(cap));

    let body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::buf_len(input)),
            vec![Node::Store {
                buffer: output.into(),
                index: i,
                value: flush_tiny(result),
            }],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::output(output, 1, DataType::F32).with_count(n),
        ],
        [64, 1, 1],
        vec![wrap_anonymous(OP_ID, body)],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || logit_softcap("input", "output", 4, 30.0),
        test_inputs: Some(|| {
            let to_bytes = |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0.0_f32, 15.0, -60.0, 100.0]),
                vec![0u8; 4 * 4],
            ]]
        }),
        expected_output: Some(|| {
            let out = [
                f32::from_bits(0x0000_0000),
                f32::from_bits(0x415d_d0f4),
                f32::from_bits(0xc1e7_5ddb),
                f32::from_bits(0x41ef_63d2),
            ];
            let bytes = out.iter().flat_map(|v| v.to_bits().to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![bytes]]
        }),
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

    fn softcap_ref(x: f32, cap: f32) -> f32 {
        (x / cap).tanh() * cap
    }

    #[test]
    fn logit_softcap_nan_input_propagates_nan() {
        let input = [f32::NAN];
        let program = logit_softcap("input", "output", 1, 30.0);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[Value::from(f32_bytes(&input)), Value::from(vec![0u8; 4])],
        )
        .expect("Fix: logit_softcap must not panic on NaN input");
        let out = decode_f32(&outputs[0].to_bytes());
        assert!(out[0].is_nan(), "logit_softcap(NaN) must be NaN");
    }

    #[test]
    fn logit_softcap_inf_inputs() {
        let program = logit_softcap("input", "output", 2, 30.0);
        // +Inf → tanh(+Inf) * cap = 1.0 * cap = cap
        let outputs = vyre_reference::reference_eval(
            &program,
            &[Value::from(f32_bytes(&[f32::INFINITY, 0.0])), Value::from(vec![0u8; 8])],
        )
        .expect("Fix: logit_softcap must not panic on +Inf input");
        let out = decode_f32(&outputs[0].to_bytes());
        assert_eq!(out[0], 30.0, "logit_softcap(+Inf) must clamp to cap");

        // -Inf → tanh(-Inf) * cap = -1.0 * cap = -cap
        let outputs = vyre_reference::reference_eval(
            &program,
            &[Value::from(f32_bytes(&[f32::NEG_INFINITY, 0.0])), Value::from(vec![0u8; 8])],
        )
        .expect("Fix: logit_softcap must not panic on -Inf input");
        let out = decode_f32(&outputs[0].to_bytes());
        assert_eq!(out[0], -30.0, "logit_softcap(-Inf) must clamp to -cap");
    }

    #[test]
    fn logit_softcap_negative_zero_vs_positive_zero() {
        let program = logit_softcap("input", "output", 2, 30.0);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[Value::from(f32_bytes(&[0.0f32, -0.0f32])), Value::from(vec![0u8; 8])],
        )
        .expect("Fix: logit_softcap must handle -0.0");
        let out = decode_f32(&outputs[0].to_bytes());
        assert_eq!(out[0].to_bits(), 0.0f32.to_bits());
        // tanh(-0.0/cap) = -0.0, -0.0 * cap = -0.0, but flush_tiny may flush
        assert_eq!(out[1].to_bits(), 0.0f32.to_bits(), "logit_softcap(-0.0) must be +0.0 after flush_tiny");
    }

    #[test]
    fn logit_softcap_subnormal_input_is_flushed_to_zero() {
        let sub = f32::from_bits(1);
        let program = logit_softcap("input", "output", 1, 30.0);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[Value::from(f32_bytes(&[sub])), Value::from(vec![0u8; 4])],
        )
        .expect("Fix: logit_softcap must not panic on subnormal input");
        let out = decode_f32(&outputs[0].to_bytes());
        assert_eq!(out[0].to_bits(), 0.0f32.to_bits(), "logit_softcap must flush tiny subnormal to +0.0");
    }

    #[test]
    fn logit_softcap_all_zeros() {
        let input = [0.0f32; 4];
        let program = logit_softcap("input", "output", 4, 30.0);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[Value::from(f32_bytes(&input)), Value::from(vec![0u8; 16])],
        )
        .expect("Fix: logit_softcap all-zeros must execute");
        let out = decode_f32(&outputs[0].to_bytes());
        assert_eq!(out, vec![0.0; 4]);
    }

    #[test]
    fn logit_softcap_all_ones() {
        let input = [1.0f32; 4];
        let program = logit_softcap("input", "output", 4, 30.0);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[Value::from(f32_bytes(&input)), Value::from(vec![0u8; 16])],
        )
        .expect("Fix: logit_softcap all-ones must execute");
        let out = decode_f32(&outputs[0].to_bytes());
        let expected = softcap_ref(1.0, 30.0);
        for (i, &v) in out.iter().enumerate() {
            assert!((v - expected).abs() <= 1.0e-5, "logit_softcap all-ones mismatch at {i}: {v}");
        }
    }

    #[test]
    fn logit_softcap_all_max_f32() {
        let input = [f32::MAX; 4];
        let program = logit_softcap("input", "output", 4, 30.0);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[Value::from(f32_bytes(&input)), Value::from(vec![0u8; 16])],
        )
        .expect("Fix: logit_softcap all-max-f32 must not panic");
        let out = decode_f32(&outputs[0].to_bytes());
        for (i, &v) in out.iter().enumerate() {
            assert_eq!(v, 30.0, "logit_softcap(f32::MAX) must clamp to cap at {i}: got {v}");
        }
    }

    #[test]
    fn logit_softcap_single_element() {
        let input = [15.0f32];
        let program = logit_softcap("input", "output", 1, 30.0);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[Value::from(f32_bytes(&input)), Value::from(vec![0u8; 4])],
        )
        .expect("Fix: logit_softcap single element must execute");
        let out = decode_f32(&outputs[0].to_bytes());
        let expected = softcap_ref(15.0, 30.0);
        assert!((out[0] - expected).abs() <= 1.0e-5, "logit_softcap single element mismatch");
    }

    #[test]
    fn logit_softcap_empty_tensor() {
        let program = logit_softcap("input", "output", 0, 30.0);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[Value::from(vec![]), Value::from(vec![])],
        )
        .expect("Fix: logit_softcap n=0 must not panic");
        assert!(outputs[0].to_bytes().is_empty());
    }
}
