//! Canonical pre-emit lowering pipeline.
//!
//! This is the single production boundary from high-level `Program` IR to
//! emitter-ready `KernelDescriptor`: inline calls, run semantic Program
//! optimization, lower to descriptor form, verify, run descriptor cleanup, and
//! verify again. Backends should not assemble their own partial version of
//! this sequence.

use crate::descriptor::KernelDescriptor;
use crate::lower::lower;
use crate::rewrites::OptimizationStats;
use crate::{verify_then_optimize, VerifyFailure};
use std::fmt;
use vyre_foundation::ir::Program;

/// Program + descriptor pair produced by the canonical pre-emit pipeline.
#[derive(Debug, Clone)]
pub struct LoweredKernel {
    /// Program after call inlining and IR-semantic optimization.
    pub program: Program,
    /// Verified descriptor after descriptor-level cleanup rewrites.
    pub descriptor: KernelDescriptor,
    /// Descriptor rewrite statistics collected from the cleanup phase.
    pub descriptor_stats: OptimizationStats,
}

/// Error raised by the canonical pre-emit pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreEmitError {
    message: String,
}

impl PreEmitError {
    fn new(message: impl Into<String>) -> Self {
        let message = message.into();
        debug_assert!(message.contains("Fix:"));
        Self { message }
    }

    /// Return the actionable diagnostic.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for PreEmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PreEmitError {}

/// Inline calls and run the semantic Program-level optimizer.
///
/// This prepares high-level IR for descriptor lowering while preserving the
/// distinction between Layer-1 semantic rewrites and lowered descriptor
/// cleanup.
///
/// # Errors
///
/// Returns [`PreEmitError`] when call inlining fails.
pub fn prepare_program_for_emit(program: &Program) -> Result<Program, PreEmitError> {
    let pruned = vyre_foundation::optimizer::pre_lowering::optimize(program.clone());
    let inlined = vyre_foundation::ir::inline_calls(&pruned).map_err(|error| {
        PreEmitError::new(format!(
            "call inlining failed before descriptor lowering: {error}. Fix: register every Expr::Call target with the active dialect resolver or eliminate the call before backend emission."
        ))
    })?;
    Ok(vyre_foundation::optimizer::pre_lowering::optimize(inlined))
}

/// Run the complete canonical pre-emit pipeline.
///
/// # Errors
///
/// Returns [`PreEmitError`] when inlining, descriptor lowering, input
/// verification, descriptor cleanup, or output verification fails.
pub fn lower_for_emit(program: &Program) -> Result<LoweredKernel, PreEmitError> {
    let program = prepare_program_for_emit(program)?;
    let descriptor = lower(&program).map_err(|error| {
        PreEmitError::new(format!(
            "KernelDescriptor lowering failed after semantic Program optimization: {error}. Fix: add the missing neutral descriptor mapping before any concrete backend emits this Program."
        ))
    })?;
    let (descriptor, descriptor_stats) = verify_then_optimize(&descriptor).map_err(|error| {
        PreEmitError::new(format!(
            "KernelDescriptor verification/cleanup failed in the canonical pre-emit pipeline: {}. Fix: repair vyre-lower so descriptor validation succeeds before concrete emission.",
            format_verify_failure(&error)
        ))
    })?;
    Ok(LoweredKernel {
        program,
        descriptor,
        descriptor_stats,
    })
}

fn format_verify_failure(error: &VerifyFailure) -> String {
    let stage = match error {
        VerifyFailure::Input(_) => "input",
        VerifyFailure::Output(_) => "output",
    };
    let mut out = format!("{stage} descriptor invalid");
    for (index, err) in error.errors().iter().take(4).enumerate() {
        if index == 0 {
            out.push_str(": ");
        } else {
            out.push_str("; ");
        }
        out.push_str(&format!("{err:?}"));
    }
    if error.errors().len() > 4 {
        out.push_str("; ...");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Ident, Node};

    #[test]
    fn lower_for_emit_runs_program_and_descriptor_pipeline() {
        let buffer =
            BufferDecl::storage("out", 0, BufferAccess::ReadWrite, DataType::U32).with_count(16);
        let program = Program::wrapped(
            vec![buffer],
            [64, 1, 1],
            vec![Node::Store {
                buffer: Ident::from("out"),
                index: Expr::InvocationId { axis: 0 },
                value: Expr::LitU32(7),
            }],
        );

        let lowered = lower_for_emit(&program).expect("pre-emit lowering must pass");

        assert_eq!(lowered.program.workgroup_size(), [64, 1, 1]);
        assert_eq!(lowered.descriptor.dispatch.workgroup_size, [64, 1, 1]);
        assert_eq!(lowered.descriptor.bindings.slots.len(), 1);
        assert!(crate::verify::verify(&lowered.descriptor).is_ok());
        assert!(lowered.descriptor_stats.iterations >= 1);
    }

    #[test]
    fn lower_for_emit_rejects_invalid_descriptor_before_backend_emit() {
        let program = Program::wrapped(Vec::new(), [0, 1, 1], Vec::new());

        let error = lower_for_emit(&program).expect_err("zero dispatch must fail");

        assert!(error.message().contains("KernelDescriptor"));
        assert!(error.message().contains("Fix:"));
    }
}
