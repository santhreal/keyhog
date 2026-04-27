use super::{eliminate_dead_lets, eliminate_unreachable};
use crate::ir_inner::model::program::Program;
use im::HashSet;

/// Remove unreachable statements and unused pure `let` bindings.
#[must_use]
#[inline]
pub fn dce(program: Program) -> Program {
    let template = program.with_rewritten_entry(Vec::new());
    let entry = eliminate_dead_lets(program.into_entry_vec(), HashSet::new()).nodes;
    let entry = eliminate_unreachable(entry);
    let entry = eliminate_dead_lets(entry, HashSet::new()).nodes;
    template.with_rewritten_entry(entry)
}
