//! Embedding lookup: `y[s, d] = embed_table[token[s], d]`.
//!
//! Category A composition — gather from weight buffer by token index.
//! Tokens are U32, embedding table is F32.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Program};

use crate::builder::build_indexed_map;

const OP_ID: &str = "vyre-libs::nn::embedding";

/// Build a Program that looks up F32 embeddings for `n` U32 token IDs.
///
/// `embed_table[vocab_size * embed_dim]` (F32), `tokens[n]` (U32),
/// `output[n * embed_dim]` (F32).
#[must_use]
pub fn embedding(embed_table: &str, tokens: &str, output: &str, n: u32, embed_dim: u32) -> Program {
    let total_out = n * embed_dim;

    build_indexed_map(
        OP_ID,
        vec![
            BufferDecl::storage(embed_table, 0, BufferAccess::ReadOnly, DataType::F32),
            BufferDecl::storage(tokens, 1, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::output(output, 2, DataType::F32).with_count(total_out),
        ],
        output,
        total_out,
        [64, 1, 1],
        |i| {
            let seq_idx = Expr::div(i.clone(), Expr::u32(embed_dim));
            let dim_idx = Expr::sub(i.clone(), Expr::mul(seq_idx.clone(), Expr::u32(embed_dim)));
            let token_id = Expr::load(tokens, seq_idx);
            let table_offset = Expr::add(Expr::mul(token_id, Expr::u32(embed_dim)), dim_idx);
            (i, Expr::load(embed_table, table_offset))
        },
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || embedding("table", "tokens", "output", 2, 3),
        test_inputs: Some(|| {
            let to_f32 = |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            let to_u32 = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_f32(&[1.0, 2.0, 3.0,  4.0, 5.0, 6.0]), // table: 2 vocab × 3 dim
                to_u32(&[1, 0]),                             // tokens
                vec![0u8; 4 * 6],                            // output
            ]]
        }),
        expected_output: Some(|| {
            let to_f32 = |w: &[f32]| w.iter().flat_map(|v| v.to_bits().to_le_bytes()).collect::<Vec<u8>>();
            // token 1 → [4,5,6], token 0 → [1,2,3]
            vec![vec![to_f32(&[4.0, 5.0, 6.0, 1.0, 2.0, 3.0])]]
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

    fn u32_bytes(values: &[u32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    fn decode_f32(bytes: &[u8]) -> Vec<f32> {
        bytes
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes(c.try_into().unwrap()))
            .collect()
    }

    #[test]
    fn embedding_empty_tensor() {
        let program = embedding("table", "tokens", "output", 0, 3);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[
                Value::from(f32_bytes(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0])),
                Value::from(vec![]),
                Value::from(vec![]),
            ],
        )
        .expect("Fix: embedding n=0 must not panic");
        assert!(outputs[0].to_bytes().is_empty());
    }

    #[test]
    fn embedding_single_element() {
        let program = embedding("table", "tokens", "output", 1, 2);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[
                Value::from(f32_bytes(&[10.0, 20.0, 30.0, 40.0])),
                Value::from(u32_bytes(&[1])),
                Value::from(vec![0u8; 8]),
            ],
        )
        .expect("Fix: embedding single element must execute");
        let out = decode_f32(&outputs[0].to_bytes());
        assert_eq!(out, vec![30.0, 40.0]);
    }

    #[test]
    fn embedding_zero_token_index() {
        let program = embedding("table", "tokens", "output", 2, 2);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[
                Value::from(f32_bytes(&[1.0, 2.0, 3.0, 4.0])),
                Value::from(u32_bytes(&[0, 0])),
                Value::from(vec![0u8; 8]),
            ],
        )
        .expect("Fix: embedding zero token must execute");
        let out = decode_f32(&outputs[0].to_bytes());
        assert_eq!(out, vec![1.0, 2.0, 1.0, 2.0]);
    }

    #[test]
    fn embedding_nan_in_table_propagates_to_output() {
        let program = embedding("table", "tokens", "output", 1, 2);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[
                Value::from(f32_bytes(&[f32::NAN, 2.0])),
                Value::from(u32_bytes(&[0])),
                Value::from(vec![0u8; 8]),
            ],
        )
        .expect("Fix: embedding NaN table must not panic");
        let out = decode_f32(&outputs[0].to_bytes());
        assert!(out[0].is_nan(), "embedding must propagate NaN from table to output");
        assert_eq!(out[1], 2.0);
    }

    #[test]
    fn embedding_out_of_bounds_token_may_trap_or_return_zero() {
        // Adversarial: token index >= vocab_size. The IR does an
        // unguarded load at table_offset = token_id * embed_dim + dim_idx.
        // The reference interpreter may trap or return 0 for OOB.
        // We assert that it does not silently produce a finite non-zero value.
        let program = embedding("table", "tokens", "output", 1, 2);
        let result = vyre_reference::reference_eval(
            &program,
            &[
                Value::from(f32_bytes(&[1.0, 2.0])),
                Value::from(u32_bytes(&[9999])),
                Value::from(vec![0u8; 8]),
            ],
        );
        match result {
            Ok(outputs) => {
                let out = decode_f32(&outputs[0].to_bytes());
                // If the interpreter does not trap, it should at least not
                // silently claim the lookup is valid (0 is acceptable for OOB).
                assert!(
                    out.iter().all(|&v| v == 0.0 || v.is_nan()),
                    "OOB embedding lookup must trap or return 0/NaN, got {:?}",
                    out
                );
            }
            Err(_) => {
                // Trapping is acceptable behavior for OOB.
            }
        }
    }
}
