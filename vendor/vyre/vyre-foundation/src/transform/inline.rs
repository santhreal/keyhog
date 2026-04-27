//! Compile-time expansion of `Expr::Call` composition nodes.
//!
//! Calls are resolved against Category A operation programs and expanded into
//! ordinary IR before backend lowering. No runtime dispatch or GPU-side
//! interpreter is introduced by this pass.

use crate::error::{Error, Result};
use crate::ir_inner::model::expr::Expr;
use crate::ir_inner::model::node::Node;
use crate::ir_inner::model::program::{BufferDecl, Program};
use crate::ir_inner::model::types::{BufferAccess, DataType};
use std::collections::HashMap;

/// Resolve an operation id to the canonical IR program for that operation.
pub type OpResolver = fn(&str) -> Option<Program>;

/// Inline all `Expr::Call` nodes in a program using the built-in operation set.
///
/// # Errors
///
/// Returns [`Error::InlineUnknownOp`] when a call cannot be resolved,
/// [`Error::InlineNonInlinable`] when a registered operation must dispatch as a
/// separate kernel, and [`Error::InlineCycle`] when recursive operation
/// composition is detected.
#[inline]
#[must_use]
pub fn inline_calls(program: &Program) -> Result<Program> {
    inline_calls_with_resolver(program, default_resolver)
}

/// Inline all `Expr::Call` nodes with a caller-supplied operation resolver.
///
/// This entry point exists for tests and embedders that provide their own
/// operation registry. The resolver must return complete Category A programs;
/// intrinsic-only operations are not valid inline targets.
///
/// # Errors
///
/// Returns [`Error::InlineUnknownOp`] when a call cannot be resolved,
/// [`Error::InlineNonInlinable`] when a registered operation must dispatch as a
/// separate kernel, and [`Error::InlineCycle`] when recursive operation
/// composition is detected.
#[inline]
#[must_use]
pub fn inline_calls_with_resolver(program: &Program, resolver: OpResolver) -> Result<Program> {
    let mut ctx = InlineCtx::new(resolver);
    let entry = ctx.inline_nodes(program.entry())?;
    Ok(Program::wrapped(
        program.buffers().to_vec(),
        program.workgroup_size(),
        entry,
    ))
}

/// Resolve inline calls against the foundation-level empty registry.
///
/// Foundation does not host a dialect registry; the driver layer plugs its
/// `vyre_driver::registry::DialectRegistry` into call sites via
/// [`inline_calls_with_resolver`]. The default resolver therefore returns
/// `None` so that a direct call to [`inline_calls`] inside tests or
/// foundation-only consumers fails with [`Error::InlineUnknownOp`] on any
/// `Expr::Call`.
#[inline]
#[must_use]
pub fn default_resolver(_op_id: &str) -> Option<Program> {
    None
}

/// Mutable state for one inline expansion pass.
pub struct InlineCtx {
    /// Operation resolver used for `Expr::Call` targets.
    resolver: OpResolver,
    /// Active expansion stack used to reject recursive composition.
    stack: Vec<String>,
    /// Monotonic suffix for generated temporary names.
    next_call_id: usize,
}

mod expand;
mod impl_inlinectx;

/// Map a callee's input buffers to the argument expressions from a call site.
#[inline]
pub(crate) fn input_arg_map(callee: &Program, args: Vec<Expr>) -> HashMap<String, Expr> {
    let mut inputs = input_buffers(callee);
    inputs.sort_by_key(|buf| buf.binding());
    inputs
        .into_iter()
        .zip(args)
        .map(|(buf, arg)| (buf.name().to_string(), arg))
        .collect()
}

/// Return read-only and uniform buffers that receive call arguments.
#[must_use]
#[inline]
pub(crate) fn input_buffers(callee: &Program) -> Vec<&BufferDecl> {
    callee
        .buffers()
        .iter()
        .filter(|buf| matches!(buf.access(), BufferAccess::ReadOnly | BufferAccess::Uniform))
        .collect()
}

/// Return the single output buffer required for an inlineable callee.
///
/// # Errors
///
/// Returns an inline error when the callee has no output buffer or more than
/// one output buffer.
#[inline]
#[must_use]
pub fn output_buffer<'a>(op_id: &str, program: &'a Program) -> Result<&'a BufferDecl> {
    let outputs: Vec<&BufferDecl> = program
        .buffers()
        .iter()
        .filter(|buf| buf.is_output())
        .collect();
    match outputs.as_slice() {
        [output] => Ok(output),
        [] => Err(Error::InlineNoOutput {
            op_id: op_id.to_string(),
        }),
        outputs => Err(Error::InlineOutputCountMismatch {
            op_id: op_id.to_string(),
            got: outputs.len(),
        }),
    }
}

/// Construct the zero literal used when an inline target needs a default value.
#[inline]
pub fn zero_value(ty: DataType) -> Expr {
    match ty {
        DataType::I32 => Expr::i32(0),
        DataType::Bool => Expr::LitBool(false),
        DataType::F32 | DataType::F16 | DataType::BF16 | DataType::F64 => Expr::f32(0.0),
        DataType::U32
        | DataType::U64
        | DataType::Vec2U32
        | DataType::Vec4U32
        | DataType::Bytes
        | DataType::Array { .. }
        | DataType::Tensor => Expr::u32(0),
        _ => Expr::u32(0),
    }
}
