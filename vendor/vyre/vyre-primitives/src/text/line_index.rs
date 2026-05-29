//! Tier 2.5 line-index  -  write a per-byte line number into `lines[i]`.
//!
//! Every parser dialect that reports diagnostics needs line numbers.
//! This op walks the source serially (single invocation) maintaining a
//! line counter that increments on every `\n` (`0x0A`). The current
//! line number is written to every byte position.
//!
//! Carriage-return handling: `\r` alone (Mac classic), `\r\n` (Windows),
//! and bare `\n` (Unix) are all normalized  -  `\r` does NOT increment
//! the counter (the following `\n` does), and a `\r` not followed by
//! `\n` increments on the `\r` itself. This matches `str::lines()`
//! semantics for byte-counting purposes.
//!
//! Ranged use: `column_for_byte(idx)` is `idx - line_start_offset`.
//! This primitive deliberately publishes per-byte line numbers only;
//! dialects that need column offsets derive them from their own
//! line-start representation.

use std::sync::Arc;
use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Stable op id for the registered Tier 3 wrapper.
pub const OP_ID: &str = "vyre-primitives::text::line_index";

/// Build a Program that writes `lines[i] = line_number_of(source[i])`.
///
/// Single-invocation serial scan  -  bytes are read in order, the line
/// counter starts at 0 and increments on each `\n` byte. The increment
/// is applied AFTER the assignment for the newline byte itself, so
/// `lines[idx_of_newline]` reads the line that contained the newline.
#[must_use]
pub fn line_index(source: &str, lines: &str, n: u32) -> Program {
    let body = vec![Node::Region {
        generator: Ident::from(OP_ID),
        source_region: None,
        body: Arc::new(vec![Node::if_then(
            Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
            vec![
                Node::let_bind("line", Expr::u32(0)),
                Node::let_bind("prev_was_cr", Expr::u32(0)),
                Node::loop_for(
                    "i",
                    Expr::u32(0),
                    Expr::u32(n),
                    vec![
                        Node::let_bind(
                            "byte",
                            Expr::bitand(Expr::load(source, Expr::var("i")), Expr::u32(0xFF)),
                        ),
                        // Lone-CR catch-up: if the previous byte was a
                        // bare '\r' and the current byte is NOT '\n',
                        // the current byte belongs to the next line.
                        // Apply the increment BEFORE storing so the
                        // current byte records its new line. (CPU
                        // does the same  -  see reference_line_index lines 112-114.)
                        Node::if_then(
                            Expr::and(
                                Expr::eq(Expr::var("prev_was_cr"), Expr::u32(1)),
                                Expr::ne(Expr::var("byte"), Expr::u32(0x0A)),
                            ),
                            vec![
                                Node::assign("line", Expr::add(Expr::var("line"), Expr::u32(1))),
                                Node::assign("prev_was_cr", Expr::u32(0)),
                            ],
                        ),
                        // Write the current line number after applying
                        // the lone-CR catch-up but before any increment
                        // induced by the current byte itself.
                        Node::store(lines, Expr::var("i"), Expr::var("line")),
                        // Increment when we see '\n' (0x0A) regardless
                        // of prev_was_cr  -  '\r\n' increments only once
                        // because the prior '\r' did NOT increment.
                        Node::if_then_else(
                            Expr::eq(Expr::var("byte"), Expr::u32(0x0A)),
                            vec![
                                Node::assign("line", Expr::add(Expr::var("line"), Expr::u32(1))),
                                Node::assign("prev_was_cr", Expr::u32(0)),
                            ],
                            vec![Node::if_then_else(
                                Expr::eq(Expr::var("byte"), Expr::u32(0x0D)),
                                vec![
                                    // '\r' marks state but doesn't yet
                                    // increment  -  wait until we see what
                                    // follows.
                                    Node::assign("prev_was_cr", Expr::u32(1)),
                                ],
                                vec![
                                    // Any other byte: prev_was_cr is
                                    // already cleared by the catch-up
                                    // above.
                                    Node::assign("prev_was_cr", Expr::u32(0)),
                                ],
                            )],
                        ),
                    ],
                ),
            ],
        )]),
    }];

    Program::wrapped(
        vec![
            BufferDecl::storage(source, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::output(lines, 1, DataType::U32).with_count(n),
        ],
        [1, 1, 1],
        body,
    )
}

/// Reference oracle: same line-counting semantics as the GPU kernel.
#[must_use]
#[cfg(any(test, feature = "cpu-parity", feature = "text"))]
pub fn reference_line_index(source: &[u8]) -> Vec<u32> {
    let mut out = Vec::with_capacity(source.len());
    let mut line: u32 = 0;
    let mut prev_was_cr = false;
    for &byte in source {
        // Lone `\r` (not followed by `\n`) means the current byte
        // belongs to the next line  -  increment BEFORE recording this
        // byte's line number.
        if prev_was_cr && byte != b'\n' {
            line += 1;
        }
        out.push(line);
        if byte == b'\n' {
            line += 1;
            prev_was_cr = false;
        } else {
            prev_was_cr = byte == b'\r';
        }
    }
    out
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || line_index("source", "lines", 5),
        Some(|| {
            vec![vec![
                vec![0x61, 0x00, 0x00, 0x00, 0x62, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x63, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00],
                vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            ]]
        }),
        Some(|| {
            vec![vec![
                vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
            ]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_no_newlines() {
        assert_eq!(reference_line_index(b"Hello"), vec![0; 5]);
    }

    #[test]
    fn reference_unix_lf() {
        // "ab\ncd" → lines [0, 0, 0, 1, 1]
        assert_eq!(reference_line_index(b"ab\ncd"), vec![0, 0, 0, 1, 1]);
    }

    #[test]
    fn reference_windows_crlf() {
        // "ab\r\ncd" → lines [0, 0, 0, 0, 1, 1]
        assert_eq!(reference_line_index(b"ab\r\ncd"), vec![0, 0, 0, 0, 1, 1]);
    }

    #[test]
    fn reference_mac_classic_cr() {
        // "ab\rcd" → lines [0, 0, 0, 1, 1]
        assert_eq!(reference_line_index(b"ab\rcd"), vec![0, 0, 0, 1, 1]);
    }

    #[test]
    fn reference_multiple_newlines() {
        // "a\n\nb" → lines [0, 0, 1, 2]
        assert_eq!(reference_line_index(b"a\n\nb"), vec![0, 0, 1, 2]);
    }

    #[test]
    fn reference_trailing_lone_cr_does_not_increment_after_eof() {
        // "ab\r" → lines [0, 0, 0]; we don't see a follow-up byte.
        assert_eq!(reference_line_index(b"ab\r"), vec![0, 0, 0]);
    }
}
