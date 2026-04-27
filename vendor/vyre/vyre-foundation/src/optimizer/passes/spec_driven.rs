//! Spec-driven optimizer rewrites derived from operation algebraic laws.

use crate::ir::Program;
use crate::optimizer::{fingerprint_program, vyre_pass, PassAnalysis, PassResult};

#[derive(Debug, Default)]
#[vyre_pass(name = "spec_driven", requires = [], invalidates = [])]
/// Protocol for running spec-driven optimizer passes.
pub struct SpecDriven;

impl SpecDriven {
    /// Skip this pass: foundation does not link a dialect registry and
    /// therefore cannot run spec-driven algebraic rewrites. The driver
    /// layer reruns the pass with a registry-backed resolver.
    #[must_use]
    #[inline]
    pub fn analyze(_program: &Program) -> PassAnalysis {
        PassAnalysis::SKIP
    }

    /// No-op at foundation tier; driver layer applies algebraic rewrites.
    #[must_use]
    pub fn transform(program: Program) -> PassResult {
        // VYRE_IR_HOTSPOTS CRIT: the previous `from_programs(&program.clone(), program)`
        // paid a whole-Program clone and an O(N) PartialEq just to report
        // changed=false. The pass is declared a no-op; bypass both.
        PassResult::unchanged(program)
    }

    /// Passthrough fingerprint so cache invalidation matches identity.
    #[must_use]
    #[inline]
    pub fn fingerprint(program: &Program) -> u64 {
        fingerprint_program(program)
    }
}
