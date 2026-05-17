//! C11 lexer split (audit-fix A33). The `c11_lexer` builder constructs a
//! single Vec<Node> by appending classifier sub-builders. Each sub-builder
//! lives in its own file:
//!  - `helpers.rs`: byte-class predicates + `set_token` + `classify_keyword`
//!  - `sections.rs`: large extracted operator-table + epilogue builders
//!  - `core.rs`: top-level `c11_lexer` orchestrator
//!  - `digraphs.rs`: digraph + line-splice resolution pass

mod core;
mod digraphs;
mod helpers;
mod sections;
mod single_pass;

pub use core::{c11_lexer, c11_lexer_regular, c11_lexer_regular_ranked, c11_lexer_regular_sparse};
pub use digraphs::c11_lex_digraphs;
pub use single_pass::{c11_lex_regular_single_pass, c11_lex_single_pass};

// Sibling re-exports so child modules can `use super::*;` and reach
// every helper that A33 split out (`helpers::*` for byte-class
// predicates, `sections::*` for operator tables). Mirrors the
// A35/A36 fix pattern.
