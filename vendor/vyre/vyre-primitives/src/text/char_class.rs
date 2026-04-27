//! Tier 2.5 byte classifier — the canonical char-class primitive.
//!
//! Each invocation classifies one packed source byte (`source[i]`,
//! low 8 bits) by loading a host-supplied 256-entry lookup table from
//! the `table` buffer. The table stays in data rather than code so
//! alternate classifier sets can be swapped in without rebuilding the
//! crate.
//!
//! First Tier 2.5 migration per `docs/primitives-tier.md` Step 2.
//! Tier 3 dialects (`vyre-libs::text::char_class`, future
//! `vyre-libs-parse-c::lexer`) call this builder + register their
//! own `OpEntry` against it. The function lives here so future
//! parsers reuse the exact same byte-classifier kernel — the LEGO
//! substrate.

use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// `\0`
pub const C_EOF: u32 = 0;
/// Space or tab.
pub const C_WS: u32 = 1;
/// `\n` or `\r`
pub const C_NEWLINE: u32 = 2;
/// `A-Z`, `a-z`, `_`
pub const C_ALPHA: u32 = 3;
/// `0-9`
pub const C_DIGIT: u32 = 4;
/// `(`
pub const C_OPEN_PAREN: u32 = 5;
/// `)`
pub const C_CLOSE_PAREN: u32 = 6;
/// `{`
pub const C_OPEN_BRACE: u32 = 7;
/// `}`
pub const C_CLOSE_BRACE: u32 = 8;
/// `;`
pub const C_SEMICOLON: u32 = 9;
/// `,`
pub const C_COMMA: u32 = 10;
/// `.`
pub const C_DOT: u32 = 11;
/// `*`
pub const C_STAR: u32 = 12;
/// `+`
pub const C_PLUS: u32 = 13;
/// `-`
pub const C_MINUS: u32 = 14;
/// `/`
pub const C_SLASH: u32 = 15;
/// `#`
pub const C_HASH: u32 = 16;
/// `'`
pub const C_QUOTE: u32 = 17;
/// `"`
pub const C_DQUOTE: u32 = 18;
/// `=`
pub const C_EQUALS: u32 = 19;
/// `<`
pub const C_LT: u32 = 20;
/// `>`
pub const C_GT: u32 = 21;
/// `!`
pub const C_BANG: u32 = 22;
/// `&`
pub const C_AMP: u32 = 23;
/// `|`
pub const C_PIPE: u32 = 24;
/// `^`
pub const C_CARET: u32 = 25;
/// `~`
pub const C_TILDE: u32 = 26;
/// `%`
pub const C_PERCENT: u32 = 27;
/// `\`
pub const C_BACKSLASH: u32 = 28;
/// `[`
pub const C_OPEN_BRACKET: u32 = 29;
/// `]`
pub const C_CLOSE_BRACKET: u32 = 30;
/// Anything else.
pub const C_OTHER: u32 = 31;

/// Stable op id for the registered Tier 3 wrapper. Kept in this
/// crate so callers (and the harness) can reference the canonical
/// id without duplicating the string literal.
pub const OP_ID: &str = "vyre-libs::text::char_class";

/// Build the default ASCII byte-classification table.
#[must_use]
pub fn build_char_class_table() -> [u32; 256] {
    let mut table = [C_OTHER; 256];

    table[0] = C_EOF;
    table[b' ' as usize] = C_WS;
    table[b'\t' as usize] = C_WS;
    table[b'\n' as usize] = C_NEWLINE;
    table[b'\r' as usize] = C_NEWLINE;
    table[b'(' as usize] = C_OPEN_PAREN;
    table[b')' as usize] = C_CLOSE_PAREN;
    table[b'{' as usize] = C_OPEN_BRACE;
    table[b'}' as usize] = C_CLOSE_BRACE;
    table[b';' as usize] = C_SEMICOLON;
    table[b',' as usize] = C_COMMA;
    table[b'.' as usize] = C_DOT;
    table[b'*' as usize] = C_STAR;
    table[b'+' as usize] = C_PLUS;
    table[b'-' as usize] = C_MINUS;
    table[b'/' as usize] = C_SLASH;
    table[b'#' as usize] = C_HASH;
    table[b'\'' as usize] = C_QUOTE;
    table[b'"' as usize] = C_DQUOTE;
    table[b'=' as usize] = C_EQUALS;
    table[b'<' as usize] = C_LT;
    table[b'>' as usize] = C_GT;
    table[b'!' as usize] = C_BANG;
    table[b'&' as usize] = C_AMP;
    table[b'|' as usize] = C_PIPE;
    table[b'^' as usize] = C_CARET;
    table[b'~' as usize] = C_TILDE;
    table[b'%' as usize] = C_PERCENT;
    table[b'\\' as usize] = C_BACKSLASH;
    table[b'[' as usize] = C_OPEN_BRACKET;
    table[b']' as usize] = C_CLOSE_BRACKET;
    table[b'_' as usize] = C_ALPHA;

    for byte in b'0'..=b'9' {
        table[byte as usize] = C_DIGIT;
    }
    for byte in b'A'..=b'Z' {
        table[byte as usize] = C_ALPHA;
    }
    for byte in b'a'..=b'z' {
        table[byte as usize] = C_ALPHA;
    }

    table
}

/// Build a Program that writes one character-class code per source byte.
///
/// `source[i]` is expected to carry the byte in its low 8 bits.
/// `table` is loaded from a host-provided buffer named `"table"`.
#[must_use]
pub fn char_class(source: &str, classified: &str, n: u32) -> Program {
    let body = vec![Node::Region {
        generator: vyre_foundation::ir::model::expr::Ident::from(OP_ID),
        source_region: None,
        body: std::sync::Arc::new(vec![
            Node::let_bind("idx", Expr::InvocationId { axis: 0 }),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::u32(n)),
                vec![Node::store(
                    classified,
                    Expr::var("idx"),
                    Expr::load(
                        "table",
                        Expr::bitand(Expr::load(source, Expr::var("idx")), Expr::u32(0xFF)),
                    ),
                )],
            ),
        ]),
    }];

    Program::wrapped(
        vec![
            BufferDecl::storage(source, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::storage("table", 1, BufferAccess::ReadOnly, DataType::U32).with_count(256),
            BufferDecl::output(classified, 2, DataType::U32).with_count(n),
        ],
        [64, 1, 1],
        body,
    )
}

/// CPU reference: classify each source byte through the lookup table.
///
/// Pure function, exposed for fixture generation + harness oracles.
#[must_use]
pub fn cpu_ref(source: &[u8], table: &[u32; 256]) -> Vec<u32> {
    source
        .iter()
        .map(|byte| table[usize::from(*byte)])
        .collect()
}

/// Pack a `[u32]` slice into the LE-byte layout the harness uses.
#[must_use]
pub fn pack_u32(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

/// Pack a `[u8]` source slice into the per-element u32 layout the GPU
/// kernel expects (each byte in the low 8 bits of a u32 lane).
#[must_use]
pub fn pack_bytes_as_u32(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .flat_map(|byte| u32::from(*byte).to_le_bytes())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_classifies_ascii_letter_as_alpha() {
        let table = build_char_class_table();
        assert_eq!(table[b'A' as usize], C_ALPHA);
        assert_eq!(table[b'z' as usize], C_ALPHA);
        assert_eq!(table[b'_' as usize], C_ALPHA);
    }

    #[test]
    fn table_classifies_digits() {
        let table = build_char_class_table();
        for byte in b'0'..=b'9' {
            assert_eq!(table[byte as usize], C_DIGIT);
        }
    }

    #[test]
    fn cpu_ref_walks_table() {
        let table = build_char_class_table();
        assert_eq!(cpu_ref(b"A1 ", &table), vec![C_ALPHA, C_DIGIT, C_WS]);
    }
}
