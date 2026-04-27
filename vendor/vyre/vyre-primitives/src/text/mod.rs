//! Tier 2.5 text primitives.
//!
//! The path IS the interface. Callers write
//! `vyre_primitives::text::char_class::char_class(...)` — explicit
//! paths keep the LEGO substrate visible at every call site. No
//! wildcard re-exports; the subsystem exposes its sub-modules, not a
//! flat namespace.
//!
//! See `docs/primitives-tier.md` and `docs/lego-block-rule.md`.

/// Back-compat module tree for older `text::ops::*` imports.
pub mod ops;

/// 256-bin byte histogram over u32-packed bytes.
pub mod byte_histogram;
/// Byte classifier — host 256-entry lookup table classifies each source byte.
pub mod char_class;
/// Histogram-based encoding classifier.
#[cfg(feature = "reduce")]
pub mod encoding_classify;

/// UTF-8 byte classifier — single-pass sequence-shape detection.
pub mod utf8_validate;

/// Line-number-per-byte index for diagnostic-producing parsers.
pub mod line_index;
/// UTF-8 shape counters over byte histograms.
pub mod utf8_shape_counts;

pub use byte_histogram::{
    byte_histogram_256, byte_histogram_256_body, byte_histogram_256_child,
    cpu_ref as byte_histogram_256_cpu_ref, BYTE_HISTOGRAM_256_OP_ID,
};
pub use char_class::{
    build_char_class_table, char_class, cpu_ref as char_class_cpu_ref, pack_bytes_as_u32,
    pack_u32 as pack_classified_u32, C_ALPHA, C_AMP, C_BACKSLASH, C_BANG, C_CARET, C_CLOSE_BRACE,
    C_CLOSE_BRACKET, C_CLOSE_PAREN, C_COMMA, C_DIGIT, C_DOT, C_DQUOTE, C_EOF, C_EQUALS, C_GT,
    C_HASH, C_LT, C_MINUS, C_NEWLINE, C_OPEN_BRACE, C_OPEN_BRACKET, C_OPEN_PAREN, C_OTHER,
    C_PERCENT, C_PIPE, C_PLUS, C_QUOTE, C_SEMICOLON, C_SLASH, C_STAR, C_TILDE, C_WS,
};
#[cfg(feature = "reduce")]
pub use encoding_classify::{
    classify_from_histogram as encoding_classify_cpu_ref, encoding_classify,
    encoding_classify_body, encoding_classify_child, ENCODING_CLASSIFY_OP_ID, ENC_ASCII,
    ENC_BINARY, ENC_ISO8859_1, ENC_UTF16BE, ENC_UTF16LE, ENC_UTF8,
};
pub use line_index::{cpu_ref as line_index_cpu_ref, line_index};
pub use utf8_shape_counts::{
    cpu_ref as utf8_shape_counts_cpu_ref, utf8_shape_counts, utf8_shape_counts_body,
    utf8_shape_counts_child, UTF8_SHAPE_COUNTS_OP_ID,
};
pub use utf8_validate::{
    cpu_ref as utf8_validate_cpu_ref, utf8_validate, UTF8_ASCII, UTF8_CONT, UTF8_INVALID,
    UTF8_LEAD_2, UTF8_LEAD_3, UTF8_LEAD_4,
};
