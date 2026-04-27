use super::CseCtx;
use crate::ir_inner::model::program::Program;

/// Run local value-numbering CSE over pure expressions, reusing an existing
/// scratchpad context.
///
/// The context is automatically [`clear`](CseCtx::clear)ed before use so that
/// callers can amortize allocation costs across multiple programs.
#[must_use]
#[inline]
pub fn cse_into(program: Program, ctx: &mut CseCtx) -> Program {
    ctx.clear();
    program.with_rewritten_entry(ctx.nodes(program.entry()))
}

/// Run local value-numbering CSE over pure expressions.
#[must_use]
#[inline]
pub fn cse(program: Program) -> Program {
    let mut ctx = CseCtx::default();
    cse_into(program, &mut ctx)
}
