//! Decentralized Trait-Owned Lowering Interfaces
//!
//! This module defines the core trait boundaries for operations to emit
//! themselves into target IRs (Naga, SPIR-V, etc.) directly. This decentralizes
//! the lowering monolith and ensures operations own their compilation rules.

use vyre_foundation::ir::Program;

/// Represents context provided to an operation during Naga AST generation.
pub trait NagaGenCtx {
    // Methods for allocating Naga components as needed by ops.
    fn register_expression(&mut self, format: &str) -> Result<(), ()>;
}

/// A target-agnostic context payload bounds ops that can be lowered.
pub trait LowerableOp: Send + Sync + 'static {
    /// Lower the operation targeting Naga.
    fn lower_naga(&self, ctx: &mut dyn NagaGenCtx, program: &Program) -> Result<(), String>;

    /// Lower the operation targeting SPIR-V.
    fn lower_spirv(&self, ctx: &mut (), program: &Program) -> Result<(), String>;
}
