//! GPU char-constant scanner.
//!
//! Phase 17b.3: parse C char constants like `'A'`, `'\n'`, `L'X'`,
//! `'\\\''`, etc. Returns `(value, bytes_consumed, ok)`.
//!
//! ## Pass split
//!
//! - **17b.3a (this commit):** prefix tolerance (`L`, `u`, `U`, `u8`),
//!   single-char constants, and the simple escape table
//!   (`\\ \' \" \? \a \b \f \n \r \t \v \0` and `\<otherbyte> → otherbyte`).
//! - **17b.3b (follow-up):** numeric escapes — octal (`\012`), hex
//!   (`\xff`), and universal-character escapes (`A`, `\U00000041`).
//!   Land in the same kernel by extending the escape branch.
//!
//! ## Limitation
//!
//! `value` is `u32` with wrapping arithmetic, mirroring the
//! `gpu_int_literal_scan` contract. Multi-char concatenation
//! (`'ABCD'`) is supported via `value = (value << 8) | (byte & 0xff)`
//! — this matches the CPU `consume_char_constant`'s `wrapping_shl(8)`
//! semantics on a u64 truncated to u32.
//!
//! ## Wire layout
//!
//! Inputs:
//!   - `source` (U8)
//!   - `start_pos` (U32, single element).
//!
//! Outputs:
//!   - `value_out` (U32, single element).
//!   - `bytes_consumed_out` (U32, single element).
//!   - `ok_out` (U32, single element). `1` if a valid char constant
//!     was scanned; `0` if no constant at this position OR it was
//!     malformed (unterminated, embedded newline, empty `''`).

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-libs::parsing::c::preprocess::gpu_char_constant_scan";

/// Canonical binding indices.
pub const BINDING_SOURCE: u32 = 0;
/// Canonical binding for the input start position.
pub const BINDING_START_POS: u32 = 1;
/// Canonical binding for the output literal value.
pub const BINDING_VALUE_OUT: u32 = 2;
/// Canonical binding for the output bytes-consumed count.
pub const BINDING_BYTES_CONSUMED_OUT: u32 = 3;
/// Canonical binding for the output ok flag.
pub const BINDING_OK_OUT: u32 = 4;

/// Maximum byte iterations inside the `'…'`. Covers up to four-byte
/// multi-char constants plus the longest single-byte escape.
pub const MAX_CONTENT_BYTES: u32 = 8;

/// Build the 17b.3a char-constant scanner `Program`.
#[must_use]
pub fn gpu_char_constant_scan(source_len: u32) -> Program {
    // Real-GPU note: U8 storage buffers are emitted as `array<u32>`;
    // `Expr::load(buf, addr)` returns the u32 word at index `addr`.
    // Reference-eval treats U8 as byte-addressed. Declaring `source`
    // as packed U32 below makes both backends agree on word-indexed
    // access; this helper extracts the byte explicitly.
    let load_byte_u32 = |addr: Expr| -> Expr {
        let word_idx = Expr::div(addr.clone(), Expr::u32(4));
        let byte_in_word = Expr::rem(addr, Expr::u32(4));
        let word = Expr::cast(DataType::U32, Expr::load("source", word_idx));
        let shift = Expr::mul(byte_in_word, Expr::u32(8));
        Expr::bitand(Expr::shr(word, shift), Expr::u32(0xFF))
    };
    let safe_load = |addr: Expr| -> Expr {
        Expr::select(
            Expr::lt(addr.clone(), Expr::u32(source_len)),
            load_byte_u32(addr),
            Expr::u32(0),
        )
    };

    let body: Vec<Node> = vec![
        Node::if_then(
            Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
            vec![
                Node::let_bind("start", Expr::load("start_pos", Expr::u32(0))),
                Node::let_bind("idx", Expr::var("start")),
                // Detect prefix: u8 (2 bytes), L/u/U (1 byte).
                Node::let_bind("p0", safe_load(Expr::var("idx"))),
                Node::let_bind("p1", safe_load(Expr::add(Expr::var("idx"), Expr::u32(1)))),
                Node::let_bind(
                    "is_u8_prefix",
                    Expr::select(
                        Expr::and(
                            Expr::eq(Expr::var("p0"), Expr::u32(b'u' as u32)),
                            Expr::eq(Expr::var("p1"), Expr::u32(b'8' as u32)),
                        ),
                        Expr::u32(1),
                        Expr::u32(0),
                    ),
                ),
                Node::let_bind(
                    "is_single_prefix",
                    Expr::select(
                        Expr::and(
                            Expr::eq(Expr::var("is_u8_prefix"), Expr::u32(0)),
                            Expr::or(
                                Expr::eq(Expr::var("p0"), Expr::u32(b'L' as u32)),
                                Expr::or(
                                    Expr::eq(Expr::var("p0"), Expr::u32(b'u' as u32)),
                                    Expr::eq(Expr::var("p0"), Expr::u32(b'U' as u32)),
                                ),
                            ),
                        ),
                        Expr::u32(1),
                        Expr::u32(0),
                    ),
                ),
                // Tentatively advance past the prefix.
                Node::if_then(
                    Expr::eq(Expr::var("is_u8_prefix"), Expr::u32(1)),
                    vec![Node::assign("idx", Expr::add(Expr::var("idx"), Expr::u32(2)))],
                ),
                Node::if_then(
                    Expr::eq(Expr::var("is_single_prefix"), Expr::u32(1)),
                    vec![Node::assign("idx", Expr::add(Expr::var("idx"), Expr::u32(1)))],
                ),
                // Expect opening `'`.
                Node::let_bind("opener", safe_load(Expr::var("idx"))),
                Node::let_bind(
                    "opened",
                    Expr::select(
                        Expr::eq(Expr::var("opener"), Expr::u32(b'\'' as u32)),
                        Expr::u32(1),
                        Expr::u32(0),
                    ),
                ),
                // If we didn't find an opener: this isn't a char
                // constant; return ok=0, consumed=0. Reset idx so the
                // post-loop math doesn't double-count the prefix skip.
                Node::let_bind("ok_so_far", Expr::var("opened")),
                Node::let_bind("value", Expr::u32(0)),
                Node::let_bind("saw_char", Expr::u32(0)),
                Node::if_then(
                    Expr::eq(Expr::var("opened"), Expr::u32(1)),
                    vec![
                        // Step past `'`.
                        Node::assign("idx", Expr::add(Expr::var("idx"), Expr::u32(1))),
                        Node::let_bind("done_content", Expr::u32(0)),
                        Node::loop_for(
                            "k",
                            Expr::u32(0),
                            Expr::u32(MAX_CONTENT_BYTES),
                            vec![Node::if_then(
                                Expr::eq(Expr::var("done_content"), Expr::u32(0)),
                                vec![
                                    Node::let_bind("ch", safe_load(Expr::var("idx"))),
                                    // Closing quote → break.
                                    Node::if_then(
                                        Expr::eq(Expr::var("ch"), Expr::u32(b'\'' as u32)),
                                        vec![Node::assign("done_content", Expr::u32(1))],
                                    ),
                                    // Embedded newline → error.
                                    Node::if_then(
                                        Expr::and(
                                            Expr::eq(Expr::var("done_content"), Expr::u32(0)),
                                            Expr::or(
                                                Expr::eq(Expr::var("ch"), Expr::u32(b'\n' as u32)),
                                                Expr::eq(Expr::var("ch"), Expr::u32(b'\r' as u32)),
                                            ),
                                        ),
                                        vec![
                                            Node::assign("ok_so_far", Expr::u32(0)),
                                            Node::assign("done_content", Expr::u32(1)),
                                        ],
                                    ),
                                    // Truncated buffer → error.
                                    Node::if_then(
                                        Expr::and(
                                            Expr::eq(Expr::var("done_content"), Expr::u32(0)),
                                            Expr::ge(Expr::var("idx"), Expr::u32(source_len)),
                                        ),
                                        vec![
                                            Node::assign("ok_so_far", Expr::u32(0)),
                                            Node::assign("done_content", Expr::u32(1)),
                                        ],
                                    ),
                                    // Otherwise: regular char or escape.
                                    Node::if_then(
                                        Expr::eq(Expr::var("done_content"), Expr::u32(0)),
                                        vec![
                                            Node::let_bind(
                                                "is_escape",
                                                Expr::select(
                                                    Expr::eq(
                                                        Expr::var("ch"),
                                                        Expr::u32(b'\\' as u32),
                                                    ),
                                                    Expr::u32(1),
                                                    Expr::u32(0),
                                                ),
                                            ),
                                            Node::if_then_else(
                                                Expr::eq(Expr::var("is_escape"), Expr::u32(1)),
                                                vec![
                                                    // Read the byte after `\`.
                                                    Node::let_bind(
                                                        "esc",
                                                        safe_load(Expr::add(
                                                            Expr::var("idx"),
                                                            Expr::u32(1),
                                                        )),
                                                    ),
                                                    // Categorize the escape: numeric kinds need
                                                    // dedicated greedy scanners; everything else
                                                    // decodes via the simple-escape lookup.
                                                    Node::let_bind(
                                                        "is_octal_start",
                                                        Expr::select(
                                                            Expr::and(
                                                                Expr::ge(
                                                                    Expr::var("esc"),
                                                                    Expr::u32(b'0' as u32),
                                                                ),
                                                                Expr::le(
                                                                    Expr::var("esc"),
                                                                    Expr::u32(b'7' as u32),
                                                                ),
                                                            ),
                                                            Expr::u32(1),
                                                            Expr::u32(0),
                                                        ),
                                                    ),
                                                    Node::let_bind(
                                                        "is_hex_start",
                                                        Expr::select(
                                                            Expr::eq(
                                                                Expr::var("esc"),
                                                                Expr::u32(b'x' as u32),
                                                            ),
                                                            Expr::u32(1),
                                                            Expr::u32(0),
                                                        ),
                                                    ),
                                                    Node::let_bind(
                                                        "is_ucn4_start",
                                                        Expr::select(
                                                            Expr::eq(
                                                                Expr::var("esc"),
                                                                Expr::u32(b'u' as u32),
                                                            ),
                                                            Expr::u32(1),
                                                            Expr::u32(0),
                                                        ),
                                                    ),
                                                    Node::let_bind(
                                                        "is_ucn8_start",
                                                        Expr::select(
                                                            Expr::eq(
                                                                Expr::var("esc"),
                                                                Expr::u32(b'U' as u32),
                                                            ),
                                                            Expr::u32(1),
                                                            Expr::u32(0),
                                                        ),
                                                    ),
                                                    // Simple-escape lookup. The numeric-start
                                                    // categories take precedence below; for now
                                                    // this provides the fallback.
                                                    Node::let_bind(
                                                        "simple_val",
                                                        Expr::select(
                                                            Expr::eq(
                                                                Expr::var("esc"),
                                                                Expr::u32(b'n' as u32),
                                                            ),
                                                            Expr::u32(b'\n' as u32),
                                                            Expr::select(
                                                                Expr::eq(
                                                                    Expr::var("esc"),
                                                                    Expr::u32(b't' as u32),
                                                                ),
                                                                Expr::u32(b'\t' as u32),
                                                                Expr::select(
                                                                    Expr::eq(
                                                                        Expr::var("esc"),
                                                                        Expr::u32(b'r' as u32),
                                                                    ),
                                                                    Expr::u32(b'\r' as u32),
                                                                    Expr::select(
                                                                        Expr::eq(
                                                                            Expr::var("esc"),
                                                                            Expr::u32(b'a' as u32),
                                                                        ),
                                                                        Expr::u32(7),
                                                                        Expr::select(
                                                                            Expr::eq(
                                                                                Expr::var("esc"),
                                                                                Expr::u32(b'b' as u32),
                                                                            ),
                                                                            Expr::u32(8),
                                                                            Expr::select(
                                                                                Expr::eq(
                                                                                    Expr::var("esc"),
                                                                                    Expr::u32(b'f' as u32),
                                                                                ),
                                                                                Expr::u32(12),
                                                                                Expr::select(
                                                                                    Expr::eq(
                                                                                        Expr::var("esc"),
                                                                                        Expr::u32(b'v' as u32),
                                                                                    ),
                                                                                    Expr::u32(11),
                                                                                    // Default: the literal byte after `\`
                                                                                    // (covers ' " ? \\ and `\<other>`).
                                                                                    Expr::var("esc"),
                                                                                ),
                                                                            ),
                                                                        ),
                                                                    ),
                                                                ),
                                                            ),
                                                        ),
                                                    ),
                                                    // ---- Octal: \0..\7, up to 3 digits ----
                                                    // Read up to 3 octal digits starting at
                                                    // idx+1. octal_value accumulates; octal_len
                                                    // counts digits actually consumed.
                                                    Node::let_bind("octal_value", Expr::u32(0)),
                                                    Node::let_bind("octal_len", Expr::u32(0)),
                                                    Node::let_bind("octal_done", Expr::u32(0)),
                                                    Node::loop_for(
                                                        "od",
                                                        Expr::u32(0),
                                                        Expr::u32(3),
                                                        vec![Node::if_then(
                                                            Expr::and(
                                                                Expr::eq(
                                                                    Expr::var("is_octal_start"),
                                                                    Expr::u32(1),
                                                                ),
                                                                Expr::eq(
                                                                    Expr::var("octal_done"),
                                                                    Expr::u32(0),
                                                                ),
                                                            ),
                                                            vec![
                                                                Node::let_bind(
                                                                    "ob",
                                                                    safe_load(Expr::add(
                                                                        Expr::add(
                                                                            Expr::var("idx"),
                                                                            Expr::u32(1),
                                                                        ),
                                                                        Expr::var("od"),
                                                                    )),
                                                                ),
                                                                Node::let_bind(
                                                                    "is_oct",
                                                                    Expr::select(
                                                                        Expr::and(
                                                                            Expr::ge(
                                                                                Expr::var("ob"),
                                                                                Expr::u32(b'0' as u32),
                                                                            ),
                                                                            Expr::le(
                                                                                Expr::var("ob"),
                                                                                Expr::u32(b'7' as u32),
                                                                            ),
                                                                        ),
                                                                        Expr::u32(1),
                                                                        Expr::u32(0),
                                                                    ),
                                                                ),
                                                                Node::if_then_else(
                                                                    Expr::eq(
                                                                        Expr::var("is_oct"),
                                                                        Expr::u32(1),
                                                                    ),
                                                                    vec![
                                                                        Node::assign(
                                                                            "octal_value",
                                                                            Expr::add(
                                                                                Expr::mul(
                                                                                    Expr::var("octal_value"),
                                                                                    Expr::u32(8),
                                                                                ),
                                                                                Expr::sub(
                                                                                    Expr::var("ob"),
                                                                                    Expr::u32(b'0' as u32),
                                                                                ),
                                                                            ),
                                                                        ),
                                                                        Node::assign(
                                                                            "octal_len",
                                                                            Expr::add(
                                                                                Expr::var("octal_len"),
                                                                                Expr::u32(1),
                                                                            ),
                                                                        ),
                                                                    ],
                                                                    vec![Node::assign(
                                                                        "octal_done",
                                                                        Expr::u32(1),
                                                                    )],
                                                                ),
                                                            ],
                                                        )],
                                                    ),
                                                    // ---- Hex: \xH+, greedy ----
                                                    Node::let_bind("hex_value", Expr::u32(0)),
                                                    Node::let_bind("hex_len", Expr::u32(0)),
                                                    Node::let_bind("hex_done", Expr::u32(0)),
                                                    Node::loop_for(
                                                        "hd",
                                                        Expr::u32(0),
                                                        Expr::u32(8),
                                                        vec![Node::if_then(
                                                            Expr::and(
                                                                Expr::eq(
                                                                    Expr::var("is_hex_start"),
                                                                    Expr::u32(1),
                                                                ),
                                                                Expr::eq(
                                                                    Expr::var("hex_done"),
                                                                    Expr::u32(0),
                                                                ),
                                                            ),
                                                            vec![
                                                                Node::let_bind(
                                                                    "hb",
                                                                    safe_load(Expr::add(
                                                                        Expr::add(
                                                                            Expr::var("idx"),
                                                                            Expr::u32(2),
                                                                        ),
                                                                        Expr::var("hd"),
                                                                    )),
                                                                ),
                                                                Node::let_bind(
                                                                    "hb_dec",
                                                                    Expr::select(
                                                                        Expr::and(
                                                                            Expr::ge(
                                                                                Expr::var("hb"),
                                                                                Expr::u32(b'0' as u32),
                                                                            ),
                                                                            Expr::le(
                                                                                Expr::var("hb"),
                                                                                Expr::u32(b'9' as u32),
                                                                            ),
                                                                        ),
                                                                        Expr::u32(1),
                                                                        Expr::u32(0),
                                                                    ),
                                                                ),
                                                                Node::let_bind(
                                                                    "hb_lc",
                                                                    Expr::select(
                                                                        Expr::and(
                                                                            Expr::ge(
                                                                                Expr::var("hb"),
                                                                                Expr::u32(b'a' as u32),
                                                                            ),
                                                                            Expr::le(
                                                                                Expr::var("hb"),
                                                                                Expr::u32(b'f' as u32),
                                                                            ),
                                                                        ),
                                                                        Expr::u32(1),
                                                                        Expr::u32(0),
                                                                    ),
                                                                ),
                                                                Node::let_bind(
                                                                    "hb_uc",
                                                                    Expr::select(
                                                                        Expr::and(
                                                                            Expr::ge(
                                                                                Expr::var("hb"),
                                                                                Expr::u32(b'A' as u32),
                                                                            ),
                                                                            Expr::le(
                                                                                Expr::var("hb"),
                                                                                Expr::u32(b'F' as u32),
                                                                            ),
                                                                        ),
                                                                        Expr::u32(1),
                                                                        Expr::u32(0),
                                                                    ),
                                                                ),
                                                                Node::let_bind(
                                                                    "hb_val",
                                                                    Expr::select(
                                                                        Expr::eq(
                                                                            Expr::var("hb_dec"),
                                                                            Expr::u32(1),
                                                                        ),
                                                                        Expr::sub(
                                                                            Expr::var("hb"),
                                                                            Expr::u32(b'0' as u32),
                                                                        ),
                                                                        Expr::select(
                                                                            Expr::eq(
                                                                                Expr::var("hb_lc"),
                                                                                Expr::u32(1),
                                                                            ),
                                                                            Expr::add(
                                                                                Expr::sub(
                                                                                    Expr::var("hb"),
                                                                                    Expr::u32(b'a' as u32),
                                                                                ),
                                                                                Expr::u32(10),
                                                                            ),
                                                                            Expr::select(
                                                                                Expr::eq(
                                                                                    Expr::var("hb_uc"),
                                                                                    Expr::u32(1),
                                                                                ),
                                                                                Expr::add(
                                                                                    Expr::sub(
                                                                                        Expr::var("hb"),
                                                                                        Expr::u32(b'A' as u32),
                                                                                    ),
                                                                                    Expr::u32(10),
                                                                                ),
                                                                                Expr::u32(99),
                                                                            ),
                                                                        ),
                                                                    ),
                                                                ),
                                                                Node::let_bind(
                                                                    "is_hexd",
                                                                    Expr::select(
                                                                        Expr::lt(
                                                                            Expr::var("hb_val"),
                                                                            Expr::u32(16),
                                                                        ),
                                                                        Expr::u32(1),
                                                                        Expr::u32(0),
                                                                    ),
                                                                ),
                                                                Node::if_then_else(
                                                                    Expr::eq(
                                                                        Expr::var("is_hexd"),
                                                                        Expr::u32(1),
                                                                    ),
                                                                    vec![
                                                                        Node::assign(
                                                                            "hex_value",
                                                                            Expr::add(
                                                                                Expr::mul(
                                                                                    Expr::var("hex_value"),
                                                                                    Expr::u32(16),
                                                                                ),
                                                                                Expr::var("hb_val"),
                                                                            ),
                                                                        ),
                                                                        Node::assign(
                                                                            "hex_len",
                                                                            Expr::add(
                                                                                Expr::var("hex_len"),
                                                                                Expr::u32(1),
                                                                            ),
                                                                        ),
                                                                    ],
                                                                    vec![Node::assign(
                                                                        "hex_done",
                                                                        Expr::u32(1),
                                                                    )],
                                                                ),
                                                            ],
                                                        )],
                                                    ),
                                                    // ---- UCN: \uHHHH or \UHHHHHHHH, fixed length ----
                                                    Node::let_bind(
                                                        "ucn_digits",
                                                        Expr::select(
                                                            Expr::eq(
                                                                Expr::var("is_ucn4_start"),
                                                                Expr::u32(1),
                                                            ),
                                                            Expr::u32(4),
                                                            Expr::select(
                                                                Expr::eq(
                                                                    Expr::var("is_ucn8_start"),
                                                                    Expr::u32(1),
                                                                ),
                                                                Expr::u32(8),
                                                                Expr::u32(0),
                                                            ),
                                                        ),
                                                    ),
                                                    Node::let_bind("ucn_value", Expr::u32(0)),
                                                    Node::let_bind("ucn_ok", Expr::u32(1)),
                                                    Node::loop_for(
                                                        "ud",
                                                        Expr::u32(0),
                                                        Expr::u32(8),
                                                        vec![Node::if_then(
                                                            Expr::lt(
                                                                Expr::var("ud"),
                                                                Expr::var("ucn_digits"),
                                                            ),
                                                            vec![
                                                                Node::let_bind(
                                                                    "ub",
                                                                    safe_load(Expr::add(
                                                                        Expr::add(
                                                                            Expr::var("idx"),
                                                                            Expr::u32(2),
                                                                        ),
                                                                        Expr::var("ud"),
                                                                    )),
                                                                ),
                                                                Node::let_bind(
                                                                    "ub_dec",
                                                                    Expr::select(
                                                                        Expr::and(
                                                                            Expr::ge(
                                                                                Expr::var("ub"),
                                                                                Expr::u32(b'0' as u32),
                                                                            ),
                                                                            Expr::le(
                                                                                Expr::var("ub"),
                                                                                Expr::u32(b'9' as u32),
                                                                            ),
                                                                        ),
                                                                        Expr::u32(1),
                                                                        Expr::u32(0),
                                                                    ),
                                                                ),
                                                                Node::let_bind(
                                                                    "ub_lc",
                                                                    Expr::select(
                                                                        Expr::and(
                                                                            Expr::ge(
                                                                                Expr::var("ub"),
                                                                                Expr::u32(b'a' as u32),
                                                                            ),
                                                                            Expr::le(
                                                                                Expr::var("ub"),
                                                                                Expr::u32(b'f' as u32),
                                                                            ),
                                                                        ),
                                                                        Expr::u32(1),
                                                                        Expr::u32(0),
                                                                    ),
                                                                ),
                                                                Node::let_bind(
                                                                    "ub_uc",
                                                                    Expr::select(
                                                                        Expr::and(
                                                                            Expr::ge(
                                                                                Expr::var("ub"),
                                                                                Expr::u32(b'A' as u32),
                                                                            ),
                                                                            Expr::le(
                                                                                Expr::var("ub"),
                                                                                Expr::u32(b'F' as u32),
                                                                            ),
                                                                        ),
                                                                        Expr::u32(1),
                                                                        Expr::u32(0),
                                                                    ),
                                                                ),
                                                                Node::let_bind(
                                                                    "ub_val",
                                                                    Expr::select(
                                                                        Expr::eq(
                                                                            Expr::var("ub_dec"),
                                                                            Expr::u32(1),
                                                                        ),
                                                                        Expr::sub(
                                                                            Expr::var("ub"),
                                                                            Expr::u32(b'0' as u32),
                                                                        ),
                                                                        Expr::select(
                                                                            Expr::eq(
                                                                                Expr::var("ub_lc"),
                                                                                Expr::u32(1),
                                                                            ),
                                                                            Expr::add(
                                                                                Expr::sub(
                                                                                    Expr::var("ub"),
                                                                                    Expr::u32(b'a' as u32),
                                                                                ),
                                                                                Expr::u32(10),
                                                                            ),
                                                                            Expr::select(
                                                                                Expr::eq(
                                                                                    Expr::var("ub_uc"),
                                                                                    Expr::u32(1),
                                                                                ),
                                                                                Expr::add(
                                                                                    Expr::sub(
                                                                                        Expr::var("ub"),
                                                                                        Expr::u32(b'A' as u32),
                                                                                    ),
                                                                                    Expr::u32(10),
                                                                                ),
                                                                                Expr::u32(99),
                                                                            ),
                                                                        ),
                                                                    ),
                                                                ),
                                                                Node::if_then_else(
                                                                    Expr::lt(
                                                                        Expr::var("ub_val"),
                                                                        Expr::u32(16),
                                                                    ),
                                                                    vec![Node::assign(
                                                                        "ucn_value",
                                                                        Expr::add(
                                                                            Expr::mul(
                                                                                Expr::var("ucn_value"),
                                                                                Expr::u32(16),
                                                                            ),
                                                                            Expr::var("ub_val"),
                                                                        ),
                                                                    )],
                                                                    vec![Node::assign(
                                                                        "ucn_ok",
                                                                        Expr::u32(0),
                                                                    )],
                                                                ),
                                                            ],
                                                        )],
                                                    ),
                                                    // ---- Compose final esc_val + extra_advance ----
                                                    Node::let_bind(
                                                        "esc_val",
                                                        Expr::select(
                                                            Expr::eq(
                                                                Expr::var("is_octal_start"),
                                                                Expr::u32(1),
                                                            ),
                                                            Expr::var("octal_value"),
                                                            Expr::select(
                                                                Expr::eq(
                                                                    Expr::var("is_hex_start"),
                                                                    Expr::u32(1),
                                                                ),
                                                                Expr::var("hex_value"),
                                                                Expr::select(
                                                                    Expr::or(
                                                                        Expr::eq(
                                                                            Expr::var("is_ucn4_start"),
                                                                            Expr::u32(1),
                                                                        ),
                                                                        Expr::eq(
                                                                            Expr::var("is_ucn8_start"),
                                                                            Expr::u32(1),
                                                                        ),
                                                                    ),
                                                                    Expr::var("ucn_value"),
                                                                    Expr::var("simple_val"),
                                                                ),
                                                            ),
                                                        ),
                                                    ),
                                                    // Bytes to advance from the `\`. Octal: 1
                                                    // (for `\`) + octal_len. Hex: 2 (for `\x`) +
                                                    // hex_len. UCN: 2 (for `\u`/`\U`) + ucn_digits.
                                                    // Simple: 2 (for `\<one>`).
                                                    Node::let_bind(
                                                        "extra_advance",
                                                        Expr::select(
                                                            Expr::eq(
                                                                Expr::var("is_octal_start"),
                                                                Expr::u32(1),
                                                            ),
                                                            Expr::add(
                                                                Expr::u32(1),
                                                                Expr::var("octal_len"),
                                                            ),
                                                            Expr::select(
                                                                Expr::eq(
                                                                    Expr::var("is_hex_start"),
                                                                    Expr::u32(1),
                                                                ),
                                                                Expr::add(
                                                                    Expr::u32(2),
                                                                    Expr::var("hex_len"),
                                                                ),
                                                                Expr::select(
                                                                    Expr::or(
                                                                        Expr::eq(
                                                                            Expr::var("is_ucn4_start"),
                                                                            Expr::u32(1),
                                                                        ),
                                                                        Expr::eq(
                                                                            Expr::var("is_ucn8_start"),
                                                                            Expr::u32(1),
                                                                        ),
                                                                    ),
                                                                    Expr::add(
                                                                        Expr::u32(2),
                                                                        Expr::var("ucn_digits"),
                                                                    ),
                                                                    Expr::u32(2),
                                                                ),
                                                            ),
                                                        ),
                                                    ),
                                                    // Hex with no digits is an error per CPU
                                                    // ref. Same for UCN with bad digits.
                                                    Node::if_then(
                                                        Expr::and(
                                                            Expr::eq(
                                                                Expr::var("is_hex_start"),
                                                                Expr::u32(1),
                                                            ),
                                                            Expr::eq(
                                                                Expr::var("hex_len"),
                                                                Expr::u32(0),
                                                            ),
                                                        ),
                                                        vec![Node::assign(
                                                            "ok_so_far",
                                                            Expr::u32(0),
                                                        )],
                                                    ),
                                                    Node::if_then(
                                                        Expr::and(
                                                            Expr::or(
                                                                Expr::eq(
                                                                    Expr::var("is_ucn4_start"),
                                                                    Expr::u32(1),
                                                                ),
                                                                Expr::eq(
                                                                    Expr::var("is_ucn8_start"),
                                                                    Expr::u32(1),
                                                                ),
                                                            ),
                                                            Expr::eq(
                                                                Expr::var("ucn_ok"),
                                                                Expr::u32(0),
                                                            ),
                                                        ),
                                                        vec![Node::assign(
                                                            "ok_so_far",
                                                            Expr::u32(0),
                                                        )],
                                                    ),
                                                    // Append to value.
                                                    Node::assign(
                                                        "value",
                                                        Expr::bitor(
                                                            Expr::shl(
                                                                Expr::var("value"),
                                                                Expr::u32(8),
                                                            ),
                                                            Expr::bitand(
                                                                Expr::var("esc_val"),
                                                                Expr::u32(0xff),
                                                            ),
                                                        ),
                                                    ),
                                                    Node::assign(
                                                        "saw_char",
                                                        Expr::u32(1),
                                                    ),
                                                    Node::assign(
                                                        "idx",
                                                        Expr::add(
                                                            Expr::var("idx"),
                                                            Expr::var("extra_advance"),
                                                        ),
                                                    ),
                                                ],
                                                vec![
                                                    // Plain byte.
                                                    Node::assign(
                                                        "value",
                                                        Expr::bitor(
                                                            Expr::shl(
                                                                Expr::var("value"),
                                                                Expr::u32(8),
                                                            ),
                                                            Expr::bitand(
                                                                Expr::var("ch"),
                                                                Expr::u32(0xff),
                                                            ),
                                                        ),
                                                    ),
                                                    Node::assign(
                                                        "saw_char",
                                                        Expr::u32(1),
                                                    ),
                                                    Node::assign(
                                                        "idx",
                                                        Expr::add(
                                                            Expr::var("idx"),
                                                            Expr::u32(1),
                                                        ),
                                                    ),
                                                ],
                                            ),
                                        ],
                                    ),
                                ],
                            )],
                        ),
                        // After the loop, idx must be at the closing `'`.
                        Node::let_bind("closer", safe_load(Expr::var("idx"))),
                        Node::if_then(
                            Expr::ne(Expr::var("closer"), Expr::u32(b'\'' as u32)),
                            vec![Node::assign("ok_so_far", Expr::u32(0))],
                        ),
                        // Empty `''` is an error.
                        Node::if_then(
                            Expr::eq(Expr::var("saw_char"), Expr::u32(0)),
                            vec![Node::assign("ok_so_far", Expr::u32(0))],
                        ),
                        // On success, step past closing `'`.
                        Node::if_then(
                            Expr::eq(Expr::var("ok_so_far"), Expr::u32(1)),
                            vec![Node::assign(
                                "idx",
                                Expr::add(Expr::var("idx"), Expr::u32(1)),
                            )],
                        ),
                    ],
                ),
                Node::let_bind(
                    "consumed",
                    Expr::select(
                        Expr::eq(Expr::var("ok_so_far"), Expr::u32(1)),
                        Expr::sub(Expr::var("idx"), Expr::var("start")),
                        Expr::u32(0),
                    ),
                ),
                Node::let_bind(
                    "value_final",
                    Expr::select(
                        Expr::eq(Expr::var("ok_so_far"), Expr::u32(1)),
                        Expr::var("value"),
                        Expr::u32(0),
                    ),
                ),
                Node::store("value_out", Expr::u32(0), Expr::var("value_final")),
                Node::store("bytes_consumed_out", Expr::u32(0), Expr::var("consumed")),
                Node::store("ok_out", Expr::u32(0), Expr::var("ok_so_far")),
            ],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage("source", BINDING_SOURCE, BufferAccess::ReadOnly, DataType::U32)
                .with_count(source_len.div_ceil(4).max(1)),
            BufferDecl::storage(
                "start_pos",
                BINDING_START_POS,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(1),
            BufferDecl::storage(
                "value_out",
                BINDING_VALUE_OUT,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(1),
            BufferDecl::storage(
                "bytes_consumed_out",
                BINDING_BYTES_CONSUMED_OUT,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(1),
            BufferDecl::storage("ok_out", BINDING_OK_OUT, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
        ],
        [256, 1, 1],
        body,
    )
    .with_entry_op_id(OP_ID)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_id_is_canonical_and_stable() {
        assert_eq!(
            OP_ID,
            "vyre-libs::parsing::c::preprocess::gpu_char_constant_scan"
        );
    }

    #[test]
    fn binding_indices_are_canonical_and_stable() {
        assert_eq!(BINDING_SOURCE, 0);
        assert_eq!(BINDING_START_POS, 1);
        assert_eq!(BINDING_VALUE_OUT, 2);
        assert_eq!(BINDING_BYTES_CONSUMED_OUT, 3);
        assert_eq!(BINDING_OK_OUT, 4);
    }

    #[test]
    fn build_program_returns_well_formed_program() {
        let p = gpu_char_constant_scan(64);
        assert_eq!(p.buffers().len(), 5);
        assert_eq!(p.workgroup_size(), [256, 1, 1]);
    }
}
