//! Top-K selection: indices of the K largest elements.
//!
//! Category-A composition. Sequential implementation for the reference
//! oracle; parallel bitonic top-k lands in Tier 2.

use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Build a Program that finds the indices of the `k` largest elements in `input`.
/// `input`: `n`, `output_indices`: `k`.
///
/// Uses a sequential insertion-sort-into-slots algorithm: maintains `k` best
/// (value, index) pairs in descending order, updating on every new element.
#[must_use]
pub fn top_k(input: &str, output_indices: &str, n: u32, k: u32) -> Program {
    // Body maintains two arrays of size k: best_vals and best_idxs.
    // Both are initialized to sentinel values.
    // For each input element, we scan the k slots and insert if larger.
    let mut body = vec![];

    // Initialize best_vals to -inf and best_idxs to 0
    for slot in 0..k {
        body.push(Node::Store {
            buffer: "best_vals".into(),
            index: Expr::u32(slot),
            value: Expr::f32(f32::NEG_INFINITY),
        });
        body.push(Node::Store {
            buffer: "best_idxs".into(),
            index: Expr::u32(slot),
            value: Expr::u32(0),
        });
    }

    // For each input element i:
    //   val = input[i]
    //   Scan j=0..k: if val > best_vals[j], shift j..k-1 down and insert at j
    body.push(Node::loop_for(
        "i",
        Expr::u32(0),
        Expr::u32(n),
        vec![
            Node::let_bind("val", Expr::load(input, Expr::var("i"))),
            Node::let_bind("idx", Expr::var("i")),
            // Find insertion point
            Node::let_bind("insert_pos", Expr::u32(k)), // default = no insert
            Node::loop_for(
                "j",
                Expr::u32(0),
                Expr::u32(k),
                vec![Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("insert_pos"), Expr::u32(k)),
                        Expr::gt(Expr::var("val"), Expr::load("best_vals", Expr::var("j"))),
                    ),
                    vec![Node::assign("insert_pos", Expr::var("j"))],
                )],
            ),
            // If insert_pos < k, shift down and insert
            Node::if_then(
                Expr::lt(Expr::var("insert_pos"), Expr::u32(k)),
                vec![
                    // Shift j from k-1 down to insert_pos+1
                    Node::loop_for(
                        "shift_j",
                        Expr::u32(0),
                        Expr::u32(k),
                        vec![
                            // We need to shift in reverse order. Since we can't easily
                            // do reverse loops with loop_for (which only increments),
                            // we compute the reverse index: rev = k - 1 - shift_j
                            Node::let_bind(
                                "rev",
                                Expr::sub(Expr::u32(k - 1), Expr::var("shift_j")),
                            ),
                            Node::if_then(
                                Expr::and(
                                    Expr::ge(Expr::var("rev"), Expr::var("insert_pos")),
                                    Expr::lt(Expr::var("rev"), Expr::u32(k - 1)),
                                ),
                                vec![
                                    Node::Store {
                                        buffer: "best_vals".into(),
                                        index: Expr::add(Expr::var("rev"), Expr::u32(1)),
                                        value: Expr::load("best_vals", Expr::var("rev")),
                                    },
                                    Node::Store {
                                        buffer: "best_idxs".into(),
                                        index: Expr::add(Expr::var("rev"), Expr::u32(1)),
                                        value: Expr::load("best_idxs", Expr::var("rev")),
                                    },
                                ],
                            ),
                        ],
                    ),
                    Node::Store {
                        buffer: "best_vals".into(),
                        index: Expr::var("insert_pos"),
                        value: Expr::var("val"),
                    },
                    Node::Store {
                        buffer: "best_idxs".into(),
                        index: Expr::var("insert_pos"),
                        value: Expr::var("idx"),
                    },
                ],
            ),
        ],
    ));

    // Copy best_idxs to output
    for slot in 0..k {
        body.push(Node::Store {
            buffer: output_indices.into(),
            index: Expr::u32(slot),
            value: Expr::load("best_idxs", Expr::u32(slot)),
        });
    }

    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::output(output_indices, 1, DataType::U32).with_count(k),
            // Internal scratch buffers
            BufferDecl::read_write("best_vals", 2, DataType::F32).with_count(k),
            BufferDecl::read_write("best_idxs", 3, DataType::U32).with_count(k),
        ],
        [1, 1, 1],
        vec![wrap_anonymous("vyre-libs::nn::top_k", body)],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_reference::value::Value;

    fn f32_bytes(words: &[f32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    fn u32_from_bytes(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    }

    #[test]
    fn top_k_descending_input() {
        let scores: Vec<f32> = (1..=8).map(|i| i as f32).collect();
        let program = top_k("input", "output", 8, 2);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[
                Value::from(f32_bytes(&scores)),
                Value::from(vec![0u8; 2 * 4]),
                Value::from(vec![0u8; 2 * 4]),
                Value::from(vec![0u8; 2 * 4]),
            ],
        )
        .unwrap();
        let indices = u32_from_bytes(&outputs[0].to_bytes());
        assert_eq!(indices[0], 7); // max = 8.0 at index 7
        assert_eq!(indices[1], 6); // second = 7.0 at index 6
    }

    #[test]
    fn top_k_ascending_input() {
        let scores: Vec<f32> = (1..=8).rev().map(|i| i as f32).collect();
        let program = top_k("input", "output", 8, 2);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[
                Value::from(f32_bytes(&scores)),
                Value::from(vec![0u8; 2 * 4]),
                Value::from(vec![0u8; 2 * 4]),
                Value::from(vec![0u8; 2 * 4]),
            ],
        )
        .unwrap();
        let indices = u32_from_bytes(&outputs[0].to_bytes());
        assert_eq!(indices[0], 0); // max = 8.0 at index 0
        assert_eq!(indices[1], 1); // second = 7.0 at index 1
    }

    #[test]
    fn top_k_with_duplicates() {
        let scores = vec![3.0, 1.0, 4.0, 1.0, 5.0, 9.0, 2.0, 6.0];
        let program = top_k("input", "output", 8, 3);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[
                Value::from(f32_bytes(&scores)),
                Value::from(vec![0u8; 3 * 4]),
                Value::from(vec![0u8; 3 * 4]),
                Value::from(vec![0u8; 3 * 4]),
            ],
        )
        .unwrap();
        let indices = u32_from_bytes(&outputs[0].to_bytes());
        // 9.0(5), 6.0(7), 5.0(4), 4.0(2), 3.0(0), 2.0(6), 1.0(1), 1.0(3)
        assert_eq!(indices[0], 5);
        assert_eq!(indices[1], 7);
        assert_eq!(indices[2], 4);
    }
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::nn::top_k",
        build: || top_k("input", "output", 8, 2),
        test_inputs: Some(|| {
            let scores: [f32; 8] = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
            let input_bytes = scores
                .iter()
                .flat_map(|v| v.to_bits().to_le_bytes())
                .collect::<Vec<u8>>();
            vec![vec![
                input_bytes,
                vec![0u8; 4 * 2],
                vec![0u8; 4 * 2],
                vec![0u8; 4 * 2],
            ]]
        }),
        expected_output: Some(|| {
            // Top-2 of ascending [1..8] are indices 7 and 6
            let best_vals = [8.0f32, 7.0f32]
                .iter()
                .flat_map(|v| v.to_bits().to_le_bytes())
                .collect::<Vec<u8>>();
            let best_idxs = [7u32, 6u32]
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<u8>>();
            vec![vec![
                best_idxs.clone(),
                best_vals,
                best_idxs,
            ]]
        }),
        category: Some("nn"),
    }
}
