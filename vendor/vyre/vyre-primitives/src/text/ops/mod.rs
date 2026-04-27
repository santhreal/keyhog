//! Registered text primitive ops.
//!
//! Compatibility shim for the flattened text primitives

/// Character class testing
pub mod char_class {
    pub use crate::text::char_class::{
        build_char_class_table, char_class, cpu_ref, pack_bytes_as_u32, pack_u32, C_ALPHA, C_AMP,
        C_BACKSLASH, C_BANG, C_CARET, C_CLOSE_BRACE, C_CLOSE_BRACKET, C_CLOSE_PAREN, C_COMMA,
        C_DIGIT, C_DOT, C_DQUOTE, C_EOF, C_EQUALS, C_GT, C_HASH, C_LT, C_MINUS, C_NEWLINE,
        C_OPEN_BRACE, C_OPEN_BRACKET, C_OPEN_PAREN, C_OTHER, C_PERCENT, C_PIPE, C_PLUS, C_QUOTE,
        C_SEMICOLON, C_SLASH, C_STAR, C_TILDE, C_WS, OP_ID,
    };
}

/// UTF8 string boundary verification
pub mod utf8_validate {
    pub use crate::text::utf8_validate::{
        cpu_ref, utf8_validate, OP_ID, UTF8_ASCII, UTF8_CONT, UTF8_INVALID, UTF8_LEAD_2,
        UTF8_LEAD_3, UTF8_LEAD_4,
    };
}

/// Line index lookup
pub mod line_index {
    pub use crate::text::line_index::{cpu_ref, line_index, OP_ID};
}
