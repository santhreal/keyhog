//! GPU lexer plan builder for Rust source text.

use vyre::ir::Program;

/// Builder for the GPU Rust lexer.
pub struct RustLexerPlan;

impl RustLexerPlan {
    /// Create a new lexer plan.
    pub fn new() -> Self {
        Self
    }

    /// Build the vyre::Program that lexes a source buffer.
    ///
    /// **Not implemented:** returns an empty program. `vyre-frontend-rust` must
    /// use the host `core::lex` path until GPU lexer IR lands (tracked OPEN).
    pub fn build(&self) -> Program {
        Program::default()
    }
}

impl Default for RustLexerPlan {
    fn default() -> Self {
        Self::new()
    }
}
