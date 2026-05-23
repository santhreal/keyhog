//! GPU DEFLATE stored-block decode composition.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

#[cfg(test)]
use crate::buffer_names::fixed_name;
use crate::buffer_names::scoped_generic_name;
use crate::decode::scan::{linear_aho_scan_body, tiled_decode_aho_scan_body};
use crate::region::wrap_anonymous;
use vyre_primitives::decode::inflate::inflate_stored_child;

const OP_ID: &str = "vyre-libs::decode::inflate_stored_block";
const FUSED_SCAN_OP_ID: &str = "vyre-libs::decode::inflate_stored_block_then_aho_corasick";
const TILED_FUSED_SCAN_OP_ID: &str =
    "vyre-libs::decode::inflate_stored_block_tiled_then_aho_corasick";
const FAMILY_PREFIX: &str = "decode_inflate";
const INFLATED_LEN_BUFFER: &str = "__vyre_decode_inflate_inflated_len";
const DEFAULT_DECODE_SCAN_TILE: u32 = 64;
const FIXED_HUFFMAN_REJECT: &str = "Fix: vyre-libs::decode::inflate_stored_block accepts raw DEFLATE stored blocks only; route BTYPE=1 input to a compressed-block decoder.";
const DYNAMIC_HUFFMAN_REJECT: &str = "Fix: vyre-libs::decode::inflate_stored_block accepts raw DEFLATE stored blocks only; route BTYPE=2 input to a dynamic-Huffman decoder.";
const RESERVED_BTYPE_FIX: &str =
    "Fix: reject reserved DEFLATE BTYPE=3 inputs before dispatching vyre-libs::decode::inflate_stored_block.";
const STORED_HEADER_FIX: &str =
    "Fix: validate LEN/NLEN before copying a stored DEFLATE block in vyre-libs::decode::inflate_stored_block.";

fn pack_words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn scoped_input_buffer(name: &str) -> String {
    scoped_generic_name(FAMILY_PREFIX, "input", name, &["input"])
}

fn scoped_output_buffer(name: &str) -> String {
    scoped_generic_name(FAMILY_PREFIX, "decoded", name, &["decoded", "output"])
}

/// Build a Program that inflates a single DEFLATE stored block from `input`
/// into `output`.
///
/// This builder is named for the BTYPE=0 contract. Compressed
/// DEFLATE blocks are rejected with an actionable diagnostic before bytes are
/// copied into the output buffer.
///
/// ```ignore
/// use vyre_libs::decode::inflate_stored_block;
///
/// let program = inflate_stored_block("input", "output", 10);
/// assert_eq!(program.buffers().len(), 3);
/// ```
#[must_use]
pub fn inflate_stored_block(input: &str, output: &str, input_len: u32) -> Program {
    let input = scoped_input_buffer(input);
    let output = scoped_output_buffer(output);
    let body = vec![inflate_stored_child(
        OP_ID,
        &input,
        &output,
        INFLATED_LEN_BUFFER,
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(&input, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(input_len),
            BufferDecl::output(&output, 1, DataType::U32).with_count(input_len),
            // Sidecar: actual inflated byte count (V022: at most one `::output`).
            BufferDecl::read_write(INFLATED_LEN_BUFFER, 2, DataType::U32).with_count(1),
        ],
        [64, 1, 1],
        vec![wrap_anonymous(OP_ID, body)],
    )
}

/// Compatibility alias for the stored-block-only DEFLATE builder.
#[must_use]
pub fn inflate(input: &str, output: &str, input_len: u32) -> Program {
    inflate_stored_block(input, output, input_len)
}

/// Build one GPU program that inflates a stored DEFLATE block and then scans
/// the inflated bytes with the Aho-Corasick transition table, without a host
/// readback between stages.
///
/// Only BTYPE=0 (stored) blocks are accepted by this builder.
///
/// ```ignore
/// use vyre_libs::decode::inflate::inflate_stored_block_then_aho_corasick;
///
/// let program = inflate_stored_block_then_aho_corasick(
///     "input",
///     "decoded",
///     "transitions",
///     "accept",
///     "matches",
///     10,
///     4,
/// );
/// assert_eq!(program.output_buffer_indices().len(), 1);
/// ```
#[must_use]
pub fn inflate_stored_block_then_aho_corasick(
    input: &str,
    decoded: &str,
    transitions: &str,
    accept: &str,
    matches: &str,
    input_len: u32,
    state_count: u32,
) -> Program {
    inflate_stored_block_tiled_then_aho_corasick(
        input,
        decoded,
        transitions,
        accept,
        matches,
        input_len,
        state_count,
        DEFAULT_DECODE_SCAN_TILE,
    )
}

/// Build a stored-block inflate→scan program that scans bytes as they are
/// copied from the stored block payload.
///
/// Stored DEFLATE blocks have no entropy decode dependency, so the fused path
/// can keep DFA state in registers and avoid a second pass over the decoded
/// global buffer. The decoded buffer remains populated to preserve the existing
/// output contract.
#[must_use]
pub fn inflate_stored_block_tiled_then_aho_corasick(
    input: &str,
    decoded: &str,
    transitions: &str,
    accept: &str,
    matches: &str,
    input_len: u32,
    state_count: u32,
    tile_width: u32,
) -> Program {
    let input = scoped_input_buffer(input);
    let decoded = scoped_output_buffer(decoded);
    let len_expr = Expr::bitor(
        Expr::load(&input, Expr::u32(1)),
        Expr::shl(Expr::load(&input, Expr::u32(2)), Expr::u32(8)),
    );
    let nlen_expr = Expr::bitor(
        Expr::load(&input, Expr::u32(3)),
        Expr::shl(Expr::load(&input, Expr::u32(4)), Expr::u32(8)),
    );
    let scan = tiled_decode_aho_scan_body(
        transitions,
        accept,
        matches,
        Expr::var("len"),
        tile_width,
        |index| Expr::load(&input, Expr::add(Expr::u32(5), index)),
        |index, value| Some(Node::store(&decoded, index, value)),
    );
    let entry = vec![
        Node::if_then(
            Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
            vec![Node::store(INFLATED_LEN_BUFFER, Expr::u32(0), Expr::u32(0))],
        ),
        Node::let_bind("header", Expr::load(&input, Expr::u32(0))),
        Node::let_bind(
            "btype",
            Expr::bitand(Expr::shr(Expr::var("header"), Expr::u32(1)), Expr::u32(0x3)),
        ),
        Node::if_then(
            Expr::eq(Expr::var("btype"), Expr::u32(0)),
            vec![
                Node::let_bind("len", len_expr),
                Node::let_bind("nlen", nlen_expr),
                Node::if_then(
                    Expr::eq(
                        Expr::var("nlen"),
                        Expr::bitxor(Expr::var("len"), Expr::u32(0xFFFF)),
                    ),
                    {
                        let mut body = vec![Node::if_then(
                            Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
                            vec![Node::store(
                                INFLATED_LEN_BUFFER,
                                Expr::u32(0),
                                Expr::var("len"),
                            )],
                        )];
                        body.extend(scan);
                        body
                    },
                ),
                Node::if_then(
                    Expr::ne(
                        Expr::var("nlen"),
                        Expr::bitxor(Expr::var("len"), Expr::u32(0xFFFF)),
                    ),
                    vec![Node::trap(Expr::u32(0), STORED_HEADER_FIX)],
                ),
            ],
        ),
        Node::if_then(
            Expr::eq(Expr::var("btype"), Expr::u32(1)),
            vec![Node::trap(Expr::u32(1), FIXED_HUFFMAN_REJECT)],
        ),
        Node::if_then(
            Expr::eq(Expr::var("btype"), Expr::u32(2)),
            vec![Node::trap(Expr::u32(2), DYNAMIC_HUFFMAN_REJECT)],
        ),
        Node::if_then(
            Expr::eq(Expr::var("btype"), Expr::u32(3)),
            vec![Node::trap(Expr::u32(3), RESERVED_BTYPE_FIX)],
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage(&input, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(input_len),
            BufferDecl::read_write(&decoded, 1, DataType::U32).with_count(input_len),
            BufferDecl::storage(transitions, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(state_count.saturating_mul(256)),
            BufferDecl::storage(accept, 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(state_count),
            BufferDecl::output(matches, 4, DataType::U32).with_count(input_len),
            BufferDecl::read_write(INFLATED_LEN_BUFFER, 5, DataType::U32).with_count(1),
        ],
        [64, 1, 1],
        vec![wrap_anonymous(TILED_FUSED_SCAN_OP_ID, entry)],
    )
}

/// Compatibility builder for the legacy decode-buffer scan shape.
#[must_use]
pub fn inflate_stored_block_buffered_then_aho_corasick(
    input: &str,
    decoded: &str,
    transitions: &str,
    accept: &str,
    matches: &str,
    input_len: u32,
    state_count: u32,
) -> Program {
    let input = scoped_input_buffer(input);
    let decoded = scoped_output_buffer(decoded);
    let mut entry = vec![inflate_stored_child(
        FUSED_SCAN_OP_ID,
        &input,
        &decoded,
        INFLATED_LEN_BUFFER,
    )];
    entry.extend(linear_aho_scan_body(
        &decoded,
        transitions,
        accept,
        matches,
        Expr::load(INFLATED_LEN_BUFFER, Expr::u32(0)),
    ));
    Program::wrapped(
        vec![
            BufferDecl::storage(&input, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(input_len),
            BufferDecl::read_write(&decoded, 1, DataType::U32).with_count(input_len),
            BufferDecl::storage(transitions, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(state_count.saturating_mul(256)),
            BufferDecl::storage(accept, 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(state_count),
            BufferDecl::output(matches, 4, DataType::U32).with_count(input_len),
            BufferDecl::read_write(INFLATED_LEN_BUFFER, 5, DataType::U32).with_count(1),
        ],
        [64, 1, 1],
        vec![wrap_anonymous(FUSED_SCAN_OP_ID, entry)],
    )
}

/// Compatibility alias for the stored-block-only fused decode→scan builder.
#[must_use]
pub fn inflate_then_aho_corasick(
    input: &str,
    decoded: &str,
    transitions: &str,
    accept: &str,
    matches: &str,
    input_len: u32,
    state_count: u32,
) -> Program {
    inflate_stored_block_then_aho_corasick(
        input,
        decoded,
        transitions,
        accept,
        matches,
        input_len,
        state_count,
    )
}

#[cfg(test)]
fn cpu_ref(input: &[u8]) -> Result<(Vec<u32>, u32), String> {
    if input.len() < 5 {
        return Err(STORED_HEADER_FIX.to_string());
    }
    let btype = (input[0] >> 1) & 0x3;
    match btype {
        0 => {
            let len = u16::from_le_bytes([input[1], input[2]]);
            let nlen = u16::from_le_bytes([input[3], input[4]]);
            if nlen != !len {
                return Err(STORED_HEADER_FIX.to_string());
            }
            let len_usize = usize::from(len);
            if input.len() < 5 + len_usize {
                return Err(STORED_HEADER_FIX.to_string());
            }
            Ok((
                input[5..5 + len_usize]
                    .iter()
                    .map(|&byte| u32::from(byte))
                    .collect(),
                u32::from(len),
            ))
        }
        1 => Err(FIXED_HUFFMAN_REJECT.to_string()),
        2 => Err(DYNAMIC_HUFFMAN_REJECT.to_string()),
        _ => Err(RESERVED_BTYPE_FIX.to_string()),
    }
}

fn fixture_inputs() -> Vec<Vec<Vec<u8>>> {
    vec![vec![
        pack_words(&[
            0x01,
            0x05,
            0x00,
            0xFA,
            0xFF,
            u32::from(b'h'),
            u32::from(b'e'),
            u32::from(b'l'),
            u32::from(b'l'),
            u32::from(b'o'),
        ]),
        vec![0u8; 4],
    ]]
}

fn fixture_outputs() -> Vec<Vec<Vec<u8>>> {
    vec![vec![
        pack_words(&[
            u32::from(b'h'),
            u32::from(b'e'),
            u32::from(b'l'),
            u32::from(b'l'),
            u32::from(b'o'),
            0,
            0,
            0,
            0,
            0,
        ]),
        pack_words(&[5]),
    ]]
}

inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || inflate_stored_block("input", "output", 10),
        Some(fixture_inputs),
        Some(fixture_outputs),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_primitives::matching::{dfa_compile, CompiledDfa};
    use vyre_reference::value::Value;

    fn run(input: &[u8]) -> (Vec<u32>, u32) {
        let program = inflate_stored_block("input", "output", input.len() as u32);
        let inputs = vec![
            Value::from(pack_words(
                &input
                    .iter()
                    .map(|&byte| u32::from(byte))
                    .collect::<Vec<_>>(),
            )),
            Value::from(vec![0u8; input.len() * 4]),
            Value::from(vec![0u8; 4]),
        ];
        let outputs = vyre_reference::reference_eval(&program, &inputs)
            .expect("Fix: inflate must run; restore this invariant before continuing.");
        let decoded = outputs[0]
            .to_bytes()
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect::<Vec<_>>();
        let len_bytes = outputs[1].to_bytes();
        let decoded_len =
            u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);
        (decoded, decoded_len)
    }

    #[test]
    fn stored_block_decodes_without_host_roundtrip() {
        let (decoded, decoded_len) =
            run(&[0x01, 0x05, 0x00, 0xFA, 0xFF, b'h', b'e', b'l', b'l', b'o']);
        assert_eq!(&decoded[..5], &[104, 101, 108, 108, 111]);
        assert_eq!(decoded_len, 5);
    }

    #[test]
    fn cpu_reference_names_fixed_huffman_gap() {
        let err = cpu_ref(&[0x03, 0, 0, 0, 0]).expect_err("BTYPE=1 must reject");
        assert_eq!(err, FIXED_HUFFMAN_REJECT);
    }

    #[test]
    fn cpu_reference_names_dynamic_huffman_gap() {
        let err = cpu_ref(&[0x05, 0, 0, 0, 0]).expect_err("BTYPE=2 must reject");
        assert_eq!(err, DYNAMIC_HUFFMAN_REJECT);
    }

    #[test]
    #[cfg(feature = "matching-dfa")]
    fn fused_stored_block_matches_parity_with_separate_inflate_then_aho() {
        let patterns: [&[u8]; 1] = [b"ell"];
        let compiled = dfa_compile(&patterns);
        let input_len = 10u32;

        let stored_block = {
            let payload = b"hello";
            let len = payload.len() as u16;
            let nlen = !len;
            [
                &[0x01u8][..],
                &len.to_le_bytes(),
                &nlen.to_le_bytes(),
                payload.as_slice(),
            ]
            .concat()
        };

        // --- Fused run ---
        let fused_program = inflate_stored_block_then_aho_corasick(
            "input",
            "decoded",
            "transitions",
            "accept",
            "matches",
            input_len,
            compiled.state_count,
        );
        let fused_inputs = vec![
            Value::from(pack_words(
                &stored_block
                    .iter()
                    .map(|&b| u32::from(b))
                    .collect::<Vec<_>>(),
            )),
            Value::from(vec![0u8; input_len as usize * 4]),
            Value::from(pack_words(&compiled.transitions)),
            Value::from(pack_words(&compiled.accept)),
            Value::from(vec![0u8; input_len as usize * 4]),
            Value::from(vec![0u8; 4]),
        ];
        let fused_outputs = vyre_reference::reference_eval(&fused_program, &fused_inputs)
            .expect("Fix: fused must run; restore this invariant before continuing.");
        let fused_matches = fused_outputs[1]
            .to_bytes()
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect::<Vec<_>>();

        // --- Separate inflate ---
        let inflate_program = inflate_stored_block("input", "output", input_len);
        let inflate_inputs = vec![
            Value::from(pack_words(
                &stored_block
                    .iter()
                    .map(|&b| u32::from(b))
                    .collect::<Vec<_>>(),
            )),
            Value::from(vec![0u8; input_len as usize * 4]),
            Value::from(vec![0u8; 4]),
        ];
        let inflate_outputs = vyre_reference::reference_eval(&inflate_program, &inflate_inputs)
            .expect("Fix: inflate must run; restore this invariant before continuing.");
        let decoded_bytes = inflate_outputs[0].to_bytes();
        let len_bytes = inflate_outputs[1].to_bytes();
        let decoded_len =
            u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);

        // --- Separate aho ---
        let aho_program = crate::scan::aho_corasick(
            "haystack",
            "transitions",
            "accept",
            "matches",
            decoded_len,
            compiled.state_count,
        );
        let aho_inputs = vec![
            Value::from(decoded_bytes[..decoded_len as usize * 4].to_vec()),
            Value::from(pack_words(&compiled.transitions)),
            Value::from(pack_words(&compiled.accept)),
            Value::from(vec![0u8; decoded_len as usize * 4]),
        ];
        let aho_outputs = vyre_reference::reference_eval(&aho_program, &aho_inputs)
            .expect("Fix: aho must run; restore this invariant before continuing.");
        let separate_matches = aho_outputs[0]
            .to_bytes()
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect::<Vec<_>>();

        assert_eq!(
            &fused_matches[..decoded_len as usize],
            &separate_matches[..]
        );
        for &m in &fused_matches[decoded_len as usize..] {
            assert_eq!(m, 0);
        }
    }

    #[test]
    fn fused_program_reuses_decoded_buffer_for_scan() {
        let dfa = CompiledDfa {
            transitions: vec![0; 256],
            accept: vec![0],
            state_count: 1,
            max_pattern_len: 0,
            output_offsets: vec![0, 0],
            output_records: vec![],
        };
        let program = inflate_stored_block_then_aho_corasick(
            "input",
            "decoded",
            "transitions",
            "accept",
            "matches",
            10,
            dfa.state_count,
        );
        assert_eq!(
            program.buffers()[1].name(),
            fixed_name(FAMILY_PREFIX, "decoded")
        );
        assert_eq!(program.buffers()[4].name(), "matches");
        assert_eq!(program.buffers()[5].name(), INFLATED_LEN_BUFFER);
    }

    #[test]
    fn generic_default_names_are_family_scoped() {
        let program = inflate_stored_block("input", "decoded", 10);
        assert_eq!(
            program.buffers()[0].name(),
            fixed_name(FAMILY_PREFIX, "input")
        );
        assert_eq!(
            program.buffers()[1].name(),
            fixed_name(FAMILY_PREFIX, "decoded")
        );
        assert_eq!(program.buffers()[2].name(), INFLATED_LEN_BUFFER);
    }
}
