//! C11 pipeline modules — lex / preprocess / parse / pipeline.

/// DFA lexer pipeline (lexer, tokens, keywords).
pub mod lex;
/// Lowering from structural parse to packed graph (PG) nodes.
pub mod lower;
/// Structural parser.
pub mod parse;
/// End-to-end example Programs for the C11 pipeline.
pub mod pipeline;
/// Preprocessor expansion.
pub mod preprocess;
/// Semantic analysis of C structures and declarations.
pub mod sema;
