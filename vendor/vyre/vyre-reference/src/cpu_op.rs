//! CPU reference execution contract for operation implementations.

use vyre::ir::Program;

/// CPU reference implementation for an operation.
pub trait CpuOp {
    /// Execute one flat byte payload and append the byte output to `output`.
    fn cpu(input: &[u8], output: &mut Vec<u8>);
}

/// Marker trait for Category A operations with an executable IR program.
pub trait CategoryAOp {
    /// Build the canonical Category A IR program.
    fn program() -> Program;
}

/// Function pointer used by Category C descriptors.
pub type CpuFn = fn(input: &[u8], output: &mut Vec<u8>);
