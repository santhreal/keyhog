//! The `vyre-libs` parsing and AST building domain library.
//!
//! Exposes registered `OpEntry` definitions for structural analysis and
//! full-grammar Shunting-Yard AST generation entirely on GPU.
//!
//! Architected as disjoint, language-isolated registered passes:
//!
//! - `core` — substrate-neutral parsing primitives (AST node kinds,
//!   delimiter handling, grammar table walkers).
//! - `c` — C11 pipeline: lex / preprocess / parse / sema / lower.
//!   Feature-gated behind `c-parser`.
//! - `python` — Python 3.12 sparse lex + structural extraction.
//!   Feature-gated behind `python-parser`.

/// Substrate-neutral parsing primitives (AST, delimiter, grammar).
pub mod core;

/// Precomputed LR action/goto tables and CPU reference parser.
pub mod lr_tables;

/// Packed AST (VAST) wire + host walks — re-export from `vyre-foundation`.
pub mod vast;

/// C11 pipeline (lex / preprocess / parse / sema / lower).
#[cfg(feature = "c-parser")]
pub mod c;

/// Go 1.21 pipeline (lex / structural parse / AST ops).
#[cfg(feature = "go-parser")]
pub mod go;

/// Python 3.12 pipeline (lex / structural parse / AST ops).
#[cfg(feature = "python-parser")]
pub mod python;
