//! Fused `linear_4bit` constructor — unpack-on-demand 4-bit quantized linear.
//!
//! Instead of materializing an unpacked f32 weight buffer, this kernel loads
//! the packed u32 weight, extracts the correct nibble inside the inner `k`
//! loop, and accumulates directly. This eliminates the 8× memory expansion
//! of a separate unpack dispatch.

use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Build a Program that computes `out[i] = sum_k x[k] * unpack(w_packed[k,i]) + b[i]`
/// where `w_packed` stores 8 4-bit weights per u32.
///
/// `in_dim` must be divisible by 8 (each output column consumes `in_dim/8` u32s).
///
/// # Errors
/// Returns `Err` when `in_dim == 0` or `in_dim % 8 != 0`.
pub fn linear_4bit(
    x: &str,
    w_packed: &str,
    b: &str,
    out: &str,
    in_dim: u32,
    out_dim: u32,
) -> Result<Program, String> {
    if in_dim == 0 {
        return Err("Fix: linear_4bit in_dim=0 is invalid: empty reduction".to_string());
    }
    if out_dim == 0 {
        return Err("Fix: linear_4bit out_dim=0 is invalid: empty output".to_string());
    }
    if in_dim % 8 != 0 {
        return Err(format!(
            "Fix: linear_4bit in_dim={in_dim} is not divisible by 8; pad weights to a multiple of 8."
        ));
    }
    let u32s_per_col = in_dim / 8;
    let total_u32s = u32s_per_col.checked_mul(out_dim).ok_or_else(|| {
        "Fix: linear_4bit in_dim/8 * out_dim overflows u32; reduce dimensions.".to_string()
    })?;

    let i = Expr::var("i");
    let k = Expr::var("k");

    // packed_index = k / 8 * out_dim + i
    let packed_idx = Expr::add(
        Expr::mul(Expr::div(k.clone(), Expr::u32(8)), Expr::u32(out_dim)),
        i.clone(),
    );
    // nibble_shift = (k % 8) * 4
    let shift = Expr::mul(Expr::rem(k.clone(), Expr::u32(8)), Expr::u32(4));
    // unpacked_nibble = (w_packed[packed_idx] >> shift) & 0xF
    let nibble = Expr::bitand(
        Expr::shr(Expr::load(w_packed, packed_idx), shift),
        Expr::u32(0xF),
    );
    // cast to f32 for accumulation
    let weight_f32 = Expr::cast(DataType::F32, nibble);

    let body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::u32(out_dim)),
            vec![
                Node::let_bind("acc", Expr::load(b, i.clone())),
                Node::loop_for(
                    "k",
                    Expr::u32(0),
                    Expr::u32(in_dim),
                    vec![Node::assign(
                        "acc",
                        Expr::add(
                            Expr::var("acc"),
                            Expr::mul(Expr::load(x, k.clone()), weight_f32.clone()),
                        ),
                    )],
                ),
                Node::Store {
                    buffer: out.into(),
                    index: i,
                    value: Expr::var("acc"),
                },
            ],
        ),
    ];

    Ok(Program::wrapped(
        vec![
            BufferDecl::storage(x, 0, BufferAccess::ReadOnly, DataType::F32).with_count(in_dim),
            BufferDecl::storage(w_packed, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(total_u32s),
            BufferDecl::storage(b, 2, BufferAccess::ReadOnly, DataType::F32).with_count(out_dim),
            BufferDecl::output(out, 3, DataType::F32).with_count(out_dim),
        ],
        [64, 1, 1],
        vec![wrap_anonymous("vyre-libs::nn::linear_4bit", body)],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_reference::value::Value;

    fn f32_bytes(words: &[f32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    fn u32_bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    #[test]
    fn linear_4bit_matches_unpack_then_linear() {
        // in_dim = 8, out_dim = 2
        // x = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
        let x = f32_bytes(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]);
        // Weights: 2 output columns, each with 8 nibbles (2 u32s)
        // Column 0 nibbles: [1, 2, 3, 4, 5, 6, 7, 8] → packed as:
        //   u32[0] = 0x_8_7_6_5_4_3_2_1 (little-endian byte order, but nibble order within u32)
        //   Actually in our unpack: nibble for k=0 is bits[3:0], k=1 is bits[7:4], etc.
        //   So u32[0] = (8<<28)|(7<<24)|(6<<20)|(5<<16)|(4<<12)|(3<<8)|(2<<4)|1
        let col0 = 0x8765_4321u32;
        // Column 1 nibbles: [0, 0, 0, 0, 0, 0, 0, 0]
        let col1 = 0x0000_0000u32;
        let w = u32_bytes(&[col0, col1]);
        // bias = [0.0, 0.0]
        let b = f32_bytes(&[0.0, 0.0]);
        let out_size = 2usize * 4;

        let program = linear_4bit("x", "w", "b", "out", 8, 2).unwrap();
        let outputs = vyre_reference::reference_eval(
            &program,
            &[
                Value::from(x),
                Value::from(w),
                Value::from(b),
                Value::from(vec![0u8; out_size]),
            ],
        )
        .expect("reference eval must succeed");

        let out_bytes = outputs[0].to_bytes();
        let out_vals: Vec<f32> = out_bytes
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();

        // Column 0: sum_k x[k] * nibble[k] = 1*1 + 2*2 + 3*3 + 4*4 + 5*5 + 6*6 + 7*7 + 8*8 = 204
        assert!(
            (out_vals[0] - 204.0).abs() < 1e-4,
            "expected 204.0, got {}",
            out_vals[0]
        );
        // Column 1: all zero nibbles → 0
        assert!(
            (out_vals[1] - 0.0).abs() < 1e-4,
            "expected 0.0, got {}",
            out_vals[1]
        );
    }

    #[test]
    fn linear_4bit_rejects_indivisible_in_dim() {
        let err = linear_4bit("x", "w", "b", "out", 7, 4).unwrap_err();
        assert!(
            err.contains("divisible by 8"),
            "error must mention divisibility: {err}"
        );
    }
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::nn::linear_4bit",
        build: || {
            linear_4bit("x", "w", "b", "out", 8, 4).unwrap_or_else(|error| {
                crate::builder::invalid_output_program(
                    "vyre-libs::nn::linear_4bit",
                    "out",
                    DataType::F32,
                    error,
                )
            })
        },
        test_inputs: Some(|| {
            let x: Vec<f32> = (0..8).map(|i| i as f32).collect();
            let w: Vec<u32> = vec![0x7654_3210, 0xFEDC_BA98, 0x1111_1111, 0x0000_0000];
            let b: Vec<f32> = vec![0.0; 4];
            vec![vec![
                x.iter().flat_map(|v| v.to_le_bytes()).collect(),
                w.iter().flat_map(|v| v.to_le_bytes()).collect(),
                b.iter().flat_map(|v| v.to_le_bytes()).collect(),
            ]]
        }),
        expected_output: Some(|| {
            let out = [140.0f32, 364.0, 28.0, 0.0];
            vec![vec![out.iter().flat_map(|v| v.to_le_bytes()).collect()]]
        }),
        category: Some("nn"),
    }
}
