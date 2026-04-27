//! GPU base64 decode compositions.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

#[cfg(test)]
use crate::buffer_names::fixed_name;
use crate::buffer_names::scoped_generic_name;
use crate::region::wrap_anonymous;
use vyre_primitives::decode::base64::base64_decode_child;

const OP_ID: &str = "vyre-libs::decode::base64";
const FUSED_SCAN_OP_ID: &str = "vyre-libs::decode::base64_then_aho_corasick";
const FAMILY_PREFIX: &str = "decode_base64";
const INVALID: u32 = 0xFF;

/// Fixed buffer name carrying the base64 decode lookup table.
///
/// The buffer contains 256 `u32` entries; each entry is the six-bit value for
/// the corresponding ASCII byte, or `0xFF` for invalid input.
///
/// ```ignore
/// use vyre_libs::decode::{base64_decode, BASE64_DECODE_TABLE_BUFFER};
///
/// let program = base64_decode("encoded", "decoded", 8);
/// assert_eq!(program.buffers()[1].name(), BASE64_DECODE_TABLE_BUFFER);
/// ```
pub const BASE64_DECODE_TABLE_BUFFER: &str = "__vyre_decode_base64_table";
const DECODED_LEN_BUFFER: &str = "__vyre_decode_base64_decoded_len";

fn scoped_input_buffer(name: &str) -> String {
    scoped_generic_name(FAMILY_PREFIX, "input", name, &["input"])
}

fn scoped_output_buffer(name: &str) -> String {
    scoped_generic_name(FAMILY_PREFIX, "decoded", name, &["decoded", "output"])
}

fn blocks_for_len(input_len: u32) -> u32 {
    input_len / 4
}

fn decoded_capacity(input_len: u32) -> u32 {
    blocks_for_len(input_len).saturating_mul(3)
}

fn base64_table() -> [u32; 256] {
    let mut table = [INVALID; 256];
    let mut byte = b'A';
    while byte <= b'Z' {
        table[byte as usize] = u32::from(byte - b'A');
        byte += 1;
    }
    byte = b'a';
    while byte <= b'z' {
        table[byte as usize] = u32::from(byte - b'a' + 26);
        byte += 1;
    }
    byte = b'0';
    while byte <= b'9' {
        table[byte as usize] = u32::from(byte - b'0' + 52);
        byte += 1;
    }
    table[b'+' as usize] = 62;
    table[b'/' as usize] = 63;
    table[b'=' as usize] = 0;
    table
}

fn pack_words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn dynamic_aho_scan_body(
    decoded: &str,
    transitions: &str,
    accept: &str,
    matches: &str,
) -> Vec<Node> {
    vec![
        Node::let_bind("scan_i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(
                Expr::var("scan_i"),
                Expr::load(DECODED_LEN_BUFFER, Expr::u32(0)),
            ),
            vec![
                Node::let_bind("state", Expr::u32(0)),
                Node::loop_for(
                    "scan_step",
                    Expr::u32(0),
                    Expr::add(Expr::var("scan_i"), Expr::u32(1)),
                    vec![Node::assign(
                        "state",
                        Expr::load(
                            transitions,
                            Expr::add(
                                Expr::mul(Expr::var("state"), Expr::u32(256)),
                                Expr::load(decoded, Expr::var("scan_step")),
                            ),
                        ),
                    )],
                ),
                Node::store(
                    matches,
                    Expr::var("scan_i"),
                    Expr::load(accept, Expr::var("state")),
                ),
            ],
        ),
    ]
}

/// Build a Program that decodes base64-encoded ASCII bytes from `input` into
/// `output`, storing one decoded byte per `u32` slot.
///
/// The input buffer carries one ASCII byte per `u32` element so the decode
/// output can chain directly into Aho-Corasick transition-table programs.
///
/// ```ignore
/// use vyre_libs::decode::base64::base64_decode;
///
/// let program = base64_decode("encoded", "decoded", 8);
/// assert_eq!(program.workgroup_size(), [64, 1, 1]);
/// ```
///
/// # Panics
///
/// Panics when `input_len` is not a multiple of 4. Base64 encodes
/// 24 input bits as 4 characters; any other length is either a
/// truncated payload or a caller bug (PHASE2_DECODE MEDIUM —
/// previous implementation silently dropped the trailing bytes).
#[must_use]
pub fn base64_decode(input: &str, output: &str, input_len: u32) -> Program {
    assert!(
        input_len % 4 == 0,
        "Fix: base64_decode requires input_len to be a multiple of 4, got {input_len}. \
         Pad the input with '=' or reject the payload upstream."
    );
    let input = scoped_input_buffer(input);
    let output = scoped_output_buffer(output);
    let body = vec![base64_decode_child(
        OP_ID,
        &input,
        BASE64_DECODE_TABLE_BUFFER,
        &output,
        DECODED_LEN_BUFFER,
        input_len,
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(&input, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(input_len),
            BufferDecl::storage(
                BASE64_DECODE_TABLE_BUFFER,
                1,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(256),
            BufferDecl::output(&output, 2, DataType::U32).with_count(decoded_capacity(input_len)),
            // Length is aux state — `read_write` only (V022: at most one `::output`).
            BufferDecl::read_write(DECODED_LEN_BUFFER, 3, DataType::U32).with_count(1),
        ],
        [64, 1, 1],
        vec![wrap_anonymous(OP_ID, body)],
    )
}

/// Build one GPU program that base64-decodes and then scans the decoded bytes
/// with the Aho-Corasick transition table, without a host readback between
/// stages.
///
/// ```ignore
/// use vyre_libs::decode::base64::base64_decode_then_aho_corasick;
///
/// let program = base64_decode_then_aho_corasick(
///     "encoded",
///     "decoded",
///     "transitions",
///     "accept",
///     "matches",
///     8,
///     4,
/// );
/// assert_eq!(program.output_buffer_indices().len(), 2);
/// ```
#[must_use]
pub fn base64_decode_then_aho_corasick(
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
    let decoded_capacity = decoded_capacity(input_len);
    let mut entry = vec![base64_decode_child(
        FUSED_SCAN_OP_ID,
        &input,
        BASE64_DECODE_TABLE_BUFFER,
        &decoded,
        DECODED_LEN_BUFFER,
        input_len,
    )];
    entry.extend(dynamic_aho_scan_body(
        &decoded,
        transitions,
        accept,
        matches,
    ));
    Program::wrapped(
        vec![
            BufferDecl::storage(&input, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(input_len),
            BufferDecl::storage(
                BASE64_DECODE_TABLE_BUFFER,
                1,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(256),
            BufferDecl::read_write(&decoded, 2, DataType::U32).with_count(decoded_capacity),
            BufferDecl::storage(transitions, 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(state_count.saturating_mul(256)),
            BufferDecl::storage(accept, 4, BufferAccess::ReadOnly, DataType::U32)
                .with_count(state_count),
            BufferDecl::output(matches, 5, DataType::U32).with_count(decoded_capacity),
            BufferDecl::read_write(DECODED_LEN_BUFFER, 6, DataType::U32).with_count(1),
        ],
        [64, 1, 1],
        vec![wrap_anonymous(FUSED_SCAN_OP_ID, entry)],
    )
}

fn cpu_ref(input: &[u8]) -> (Vec<u32>, u32) {
    let table = base64_table();
    let blocks = input.len() / 4;
    let mut out = vec![0u32; blocks.saturating_mul(3)];
    for block in 0..blocks {
        let base = block * 4;
        let vals = [
            table[input[base] as usize],
            table[input[base + 1] as usize],
            table[input[base + 2] as usize],
            table[input[base + 3] as usize],
        ]
        .map(|value| if value == INVALID { 0 } else { value });
        let out_base = block * 3;
        out[out_base] = (vals[0] << 2) | (vals[1] >> 4);
        if input[base + 2] != b'=' {
            out[out_base + 1] = ((vals[1] & 0x0F) << 4) | (vals[2] >> 2);
        }
        if input[base + 3] != b'=' {
            out[out_base + 2] = ((vals[2] & 0x03) << 6) | vals[3];
        }
    }
    let mut decoded_len = out.len() as u32;
    if input.len() >= 2 {
        if input[input.len() - 1] == b'=' {
            decoded_len = decoded_len.saturating_sub(1);
        }
        if input[input.len() - 2] == b'=' {
            decoded_len = decoded_len.saturating_sub(1);
        }
    }
    (out, decoded_len)
}

fn fixture_inputs() -> Vec<Vec<Vec<u8>>> {
    vec![
        vec![
            pack_words(&[
                u32::from(b'T'),
                u32::from(b'W'),
                u32::from(b'F'),
                u32::from(b'u'),
                u32::from(b'T'),
                u32::from(b'W'),
                u32::from(b'F'),
                u32::from(b'u'),
            ]),
            pack_words(&base64_table()),
            vec![0u8; 6 * 4],
            vec![0u8; 4],
        ],
        vec![
            pack_words(&[
                u32::from(b'T'),
                u32::from(b'W'),
                u32::from(b'E'),
                u32::from(b'='),
                u32::from(b'T'),
                u32::from(b'W'),
                u32::from(b'E'),
                u32::from(b'='),
            ]),
            pack_words(&base64_table()),
            vec![0u8; 6 * 4],
            vec![0u8; 4],
        ],
        vec![
            pack_words(&[
                u32::from(b'S'),
                u32::from(b'G'),
                u32::from(b'V'),
                u32::from(b's'),
                u32::from(b'b'),
                u32::from(b'G'),
                u32::from(b'8'),
                u32::from(b'*'),
            ]),
            pack_words(&base64_table()),
            vec![0u8; 6 * 4],
            vec![0u8; 4],
        ],
    ]
}

fn fixture_outputs() -> Vec<Vec<Vec<u8>>> {
    [
        b"TWFuTWFu".as_slice(),
        b"TWE=TWE=".as_slice(),
        b"SGVsbG8*".as_slice(),
    ]
    .into_iter()
    .map(|case| {
        let (decoded, decoded_len) = cpu_ref(case);
        vec![pack_words(&decoded), pack_words(&[decoded_len])]
    })
    .collect()
}

inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || base64_decode("input", "output", 8),
        Some(fixture_inputs),
        Some(fixture_outputs),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_primitives::matching::CompiledDfa;
    use vyre_reference::value::Value;

    fn run(input: &[u8]) -> (Vec<u32>, u32) {
        let program = base64_decode("input", "output", input.len() as u32);
        let decoded_capacity = decoded_capacity(input.len() as u32);
        let inputs = vec![
            Value::from(pack_words(
                &input
                    .iter()
                    .map(|&byte| u32::from(byte))
                    .collect::<Vec<_>>(),
            )),
            Value::from(pack_words(base64_table().as_ref())),
            Value::from(vec![0u8; decoded_capacity as usize * 4]),
            Value::from(vec![0u8; 4]),
        ];
        let outputs =
            vyre_reference::reference_eval(&program, &inputs).expect("base64 decode must run");
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
    fn aligned_input_decodes_three_bytes() {
        let (decoded, decoded_len) = run(b"TWFu");
        assert_eq!(&decoded[..3], &[77, 97, 110]);
        assert_eq!(decoded_len, 3);
    }

    #[test]
    fn padded_input_reports_real_length() {
        let (decoded, decoded_len) = run(b"TQ==");
        assert_eq!(decoded[0], 77);
        assert_eq!(decoded_len, 1);
    }

    #[test]
    fn invalid_character_clamps_without_panicking() {
        let (decoded, decoded_len) = run(b"SGVsbG8*");
        assert_eq!(&decoded[..6], &[72, 101, 108, 108, 111, 0]);
        assert_eq!(decoded_len, 6);
    }

    #[test]
    fn fused_program_reuses_decoded_buffer_for_scan() {
        let dfa = CompiledDfa {
            transitions: vec![0; 256],
            accept: vec![0],
            state_count: 1,
            output_offsets: vec![0, 0],
            output_records: vec![],
        };
        let program = base64_decode_then_aho_corasick(
            "input",
            "decoded",
            "transitions",
            "accept",
            "matches",
            8,
            dfa.state_count,
        );
        assert_eq!(
            program.buffers()[2].name(),
            fixed_name(FAMILY_PREFIX, "decoded")
        );
        assert_eq!(program.buffers()[5].name(), "matches");
        assert_eq!(program.buffers()[6].name(), DECODED_LEN_BUFFER);
    }

    #[test]
    fn generic_default_names_are_family_scoped() {
        let program = base64_decode("input", "decoded", 8);
        assert_eq!(
            program.buffers()[0].name(),
            fixed_name(FAMILY_PREFIX, "input")
        );
        assert_eq!(
            program.buffers()[2].name(),
            fixed_name(FAMILY_PREFIX, "decoded")
        );
        assert_eq!(program.buffers()[3].name(), DECODED_LEN_BUFFER);
    }

    #[test]
    fn twelve_byte_input_decodes_nine_bytes_in_linear_time() {
        let (decoded, decoded_len) = run(b"TWFuTWFuTWFu");
        assert_eq!(&decoded[..9], &[77, 97, 110, 77, 97, 110, 77, 97, 110]);
        assert_eq!(decoded_len, 9);
    }
}
