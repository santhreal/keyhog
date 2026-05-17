//! GPU hex decode composition.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

#[cfg(test)]
use crate::buffer_names::fixed_name;
use crate::buffer_names::scoped_generic_name;
use crate::decode::scan::tiled_decode_aho_scan_body;
use crate::region::wrap_anonymous;

const OP_ID: &str = "vyre-libs::decode::hex";
const FUSED_SCAN_OP_ID: &str = "vyre-libs::decode::hex_then_aho_corasick";
const FAMILY_PREFIX: &str = "decode_hex";
/// Fixed buffer name carrying the ASCII hex decode lookup table.
pub const HEX_DECODE_TABLE_BUFFER: &str = "__vyre_decode_hex_table";

fn scoped_input_buffer(name: &str) -> String {
    scoped_generic_name(FAMILY_PREFIX, "input", name, &["input"])
}

fn scoped_output_buffer(name: &str) -> String {
    scoped_generic_name(FAMILY_PREFIX, "decoded", name, &["decoded", "output"])
}

fn pack_words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

/// Return the canonical 256-entry ASCII hex decode table.
#[must_use]
pub fn hex_decode_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut byte = b'0';
    while byte <= b'9' {
        table[byte as usize] = u32::from(byte - b'0');
        byte += 1;
    }
    byte = b'A';
    while byte <= b'F' {
        table[byte as usize] = u32::from(byte - b'A' + 10);
        byte += 1;
    }
    byte = b'a';
    while byte <= b'f' {
        table[byte as usize] = u32::from(byte - b'a' + 10);
        byte += 1;
    }
    table
}

fn nibble_expr(byte: Expr, table: &str) -> Expr {
    Expr::load(table, Expr::bitand(byte, Expr::u32(0xFF)))
}

fn decode_body(input: &str, output: &str, table: &str, input_len: u32) -> Vec<Node> {
    let output_len = input_len / 2;
    vec![
        Node::let_bind("pair", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(Expr::var("pair"), Expr::u32(output_len)),
            vec![
                Node::let_bind("in_base", Expr::mul(Expr::var("pair"), Expr::u32(2))),
                Node::store(
                    output,
                    Expr::var("pair"),
                    decode_pair_expr(input, table, Expr::var("pair")),
                ),
            ],
        ),
    ]
}

fn decode_pair_expr(input: &str, table: &str, pair: Expr) -> Expr {
    let in_base = Expr::mul(pair, Expr::u32(2));
    let hi = nibble_expr(Expr::load(input, in_base.clone()), table);
    let lo = nibble_expr(Expr::load(input, Expr::add(in_base, Expr::u32(1))), table);
    Expr::bitor(Expr::shl(hi, Expr::u32(4)), lo)
}

/// Build a Program that decodes ASCII hex bytes from `input` into `output`,
/// storing one decoded byte per `u32` slot.
///
/// ```ignore
/// use vyre_libs::decode::hex_decode;
///
/// let program = hex_decode("encoded", "decoded", 8);
/// assert_eq!(program.buffers().len(), 2);
/// ```
#[must_use]
pub fn hex_decode(input: &str, output: &str, input_len: u32) -> Program {
    let input = scoped_input_buffer(input);
    let output = scoped_output_buffer(output);
    let body = decode_body(&input, &output, HEX_DECODE_TABLE_BUFFER, input_len);
    Program::wrapped(
        vec![
            BufferDecl::storage(&input, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(input_len),
            BufferDecl::output(&output, 1, DataType::U32).with_count(input_len / 2),
            BufferDecl::storage(
                HEX_DECODE_TABLE_BUFFER,
                2,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(256),
        ],
        [64, 1, 1],
        vec![wrap_anonymous(OP_ID, body)],
    )
}

/// Build one GPU program that hex-decodes and then scans the decoded bytes
/// with the Aho-Corasick transition table, without a host readback between
/// stages.
///
/// ```ignore
/// use vyre_libs::decode::hex::hex_decode_then_aho_corasick;
///
/// let program = hex_decode_then_aho_corasick(
///     "encoded",
///     "decoded",
///     "transitions",
///     "accept",
///     "matches",
///     8,
///     4,
/// );
/// assert_eq!(program.output_buffer_indices().len(), 1);
/// ```
#[must_use]
pub fn hex_decode_then_aho_corasick(
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
    let decoded_len = input_len / 2;
    let body = tiled_decode_aho_scan_body(
        transitions,
        accept,
        matches,
        Expr::u32(decoded_len),
        64,
        |pair| decode_pair_expr(&input, HEX_DECODE_TABLE_BUFFER, pair),
        |pair, byte| Some(Node::store(&decoded, pair, byte)),
    );
    Program::wrapped(
        vec![
            BufferDecl::storage(&input, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(input_len),
            BufferDecl::read_write(&decoded, 1, DataType::U32).with_count(decoded_len),
            BufferDecl::storage(transitions, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(state_count.saturating_mul(256)),
            BufferDecl::storage(accept, 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(state_count),
            BufferDecl::output(matches, 4, DataType::U32).with_count(decoded_len),
            BufferDecl::storage(
                HEX_DECODE_TABLE_BUFFER,
                5,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(256),
        ],
        [64, 1, 1],
        vec![wrap_anonymous(FUSED_SCAN_OP_ID, body)],
    )
}

fn cpu_ref(input: &[u8]) -> Vec<u32> {
    input
        .chunks_exact(2)
        .map(|pair| {
            let hi = match pair[0] {
                b'0'..=b'9' => pair[0] - b'0',
                b'A'..=b'F' => pair[0] - b'A' + 10,
                b'a'..=b'f' => pair[0] - b'a' + 10,
                _ => 0,
            };
            let lo = match pair[1] {
                b'0'..=b'9' => pair[1] - b'0',
                b'A'..=b'F' => pair[1] - b'A' + 10,
                b'a'..=b'f' => pair[1] - b'a' + 10,
                _ => 0,
            };
            u32::from((hi << 4) | lo)
        })
        .collect()
}

fn fixture_inputs() -> Vec<Vec<Vec<u8>>> {
    vec![
        vec![
            pack_words(&[
                u32::from(b'4'),
                u32::from(b'D'),
                u32::from(b'6'),
                u32::from(b'1'),
                u32::from(b'6'),
                u32::from(b'E'),
            ]),
            vec![0u8; 3 * 4],
            pack_words(&hex_decode_table()),
        ],
        vec![
            pack_words(&[
                u32::from(b'6'),
                u32::from(b'8'),
                u32::from(b'4'),
                u32::from(b'9'),
                u32::from(b'4'),
                u32::from(b'A'),
            ]),
            vec![0u8; 3 * 4],
            pack_words(&hex_decode_table()),
        ],
        vec![
            pack_words(&[
                u32::from(b'7'),
                u32::from(b'a'),
                u32::from(b'Z'),
                u32::from(b'1'),
                u32::from(b'0'),
                u32::from(b'0'),
            ]),
            vec![0u8; 3 * 4],
            pack_words(&hex_decode_table()),
        ],
    ]
}

fn fixture_outputs() -> Vec<Vec<Vec<u8>>> {
    [
        b"4D616E".as_slice(),
        b"68494A".as_slice(),
        b"7aZ100".as_slice(),
    ]
    .into_iter()
    .map(|case| vec![pack_words(&cpu_ref(case))])
    .collect()
}

inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || hex_decode("input", "output", 6),
        Some(fixture_inputs),
        Some(fixture_outputs),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_primitives::matching::CompiledDfa;
    use vyre_reference::value::Value;

    fn run(input: &[u8]) -> Vec<u32> {
        let program = hex_decode("input", "output", input.len() as u32);
        let inputs = vec![
            Value::from(pack_words(
                &input
                    .iter()
                    .map(|&byte| u32::from(byte))
                    .collect::<Vec<_>>(),
            )),
            Value::from(vec![0u8; (input.len() / 2) * 4]),
            Value::from(pack_words(&hex_decode_table())),
        ];
        let outputs = vyre_reference::reference_eval(&program, &inputs)
            .expect("Fix: hex decode must run; restore this invariant before continuing.");
        outputs[0]
            .to_bytes()
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect()
    }

    #[test]
    fn decodes_uppercase_hex() {
        assert_eq!(run(b"4D616E"), vec![77, 97, 110]);
    }

    #[test]
    fn decodes_lowercase_hex() {
        assert_eq!(run(b"68494a"), vec![104, 73, 74]);
    }

    #[test]
    fn decodes_sixteen_char_hex() {
        // 16-character input → 8 output bytes. Regression guard against
        // any O(n²) path that re-walks the input per output byte.
        assert_eq!(
            run(b"4D616E6973657321"),
            vec![77, 97, 110, 105, 115, 101, 115, 33]
        );
    }

    #[test]
    fn invalid_nibble_clamps_to_zero() {
        assert_eq!(run(b"7aZ100"), vec![122, 1, 0]);
    }

    #[test]
    fn generic_default_names_are_family_scoped() {
        let program = hex_decode("input", "decoded", 6);
        assert_eq!(
            program.buffers()[0].name(),
            fixed_name(FAMILY_PREFIX, "input")
        );
        assert_eq!(
            program.buffers()[1].name(),
            fixed_name(FAMILY_PREFIX, "decoded")
        );
        assert_eq!(program.buffers()[2].name(), HEX_DECODE_TABLE_BUFFER);
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
        let program = hex_decode_then_aho_corasick(
            "input",
            "decoded",
            "transitions",
            "accept",
            "matches",
            8,
            dfa.state_count,
        );
        assert_eq!(
            program.buffers()[1].name(),
            fixed_name(FAMILY_PREFIX, "decoded")
        );
        assert_eq!(program.buffers()[4].name(), "matches");
        assert_eq!(program.buffers()[5].name(), HEX_DECODE_TABLE_BUFFER);
    }
}
