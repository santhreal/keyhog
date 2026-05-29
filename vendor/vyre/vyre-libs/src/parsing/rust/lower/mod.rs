//! Rust AST to Vyre IR lowering (reusable substrate, Tier 3).
//!
//! Mirrors `vyre-libs::parsing::c::lower`: lowering a resolved language AST to a
//! `vyre::ir::Program` is a Tier-3 concern and lives in the library, not the
//! frontend driver. Lowering borrows the AST plus its resolution. Not yet
//! implemented for the nano-subset; returns a loud error rather than a fake
//! empty Program.

use thiserror::Error;
use vyre::ir::Program;

use super::parse::Module;
use super::sema::Resolution;

/// Errors from Rust to Vyre IR lowering.
#[derive(Debug, Clone, Error)]
pub enum RustLowerError {
    /// Lowering is not implemented for the nano-subset.
    #[error("Rust AST to Vyre IR lowering is not wired yet; do not consume a default empty Program as compiled output")]
    LoweringUnavailable,
}

/// Lower a resolved module to a Vyre IR program.
///
/// # Errors
/// Returns [`RustLowerError::LoweringUnavailable`] until lowering is wired.
pub fn lower(module: &Module, resolution: &Resolution) -> Result<Program, RustLowerError> {
    let _ = (module, resolution);
    Err(RustLowerError::LoweringUnavailable)
}
