//! Canonicalize-form pass registered through the unified pass substrate.
//!
//! The canonical-form rewrite (literal hoisting on commutative ops,
//! idempotent) is the load-bearing pre-lowering normalization. Wrapping
//! it as a `ProgramPass` puts it on the same scheduler / invalidates / requires
//! substrate as `const_fold` / `fusion` / `dead_buffer_elim` /
//! `normalize_atomics` / `strength_reduce` / `autotune` / `spec_driven`.
//! The free [`canonicalize_engine::run`] / [`canonicalize_engine::run_borrowed`]
//! entry points stay available for hot paths (e.g. pipeline fingerprinting)
//! that need the canonical form without running the full pass scheduler.

use crate::ir::Program;
use crate::optimizer::{fingerprint_program, vyre_pass, PassResult};

#[vyre_pass(name = "canonicalize", requires = [], invalidates = ["fusion", "const_fold"], analyze = "always")]
/// Optimizer pass that rewrites `Program` IR into canonical form.
pub struct Canonicalize;

impl Canonicalize {
    /// Run the canonical-form rewrite on `program`.
    pub fn transform(program: Program) -> PassResult {
        let before_fingerprint = fingerprint_program(&program);
        let canonical = super::canonicalize_engine::run(program);
        let after_fingerprint = fingerprint_program(&canonical);
        let changed = before_fingerprint != after_fingerprint;
        PassResult {
            program: canonical,
            changed,
        }
    }}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BufferDecl, DataType, Expr, Node, Program};

    #[test]
    fn canonicalize_pass_runs_idempotently() {
        // `1 + a` should canonicalize to `a + 1`. Running twice changes nothing.
        let program = Program::wrapped(
            vec![
                BufferDecl::read("a", 0, DataType::U32).with_count(64),
                BufferDecl::output("out", 1, DataType::U32)
                    .with_count(64)
                    .with_output_byte_range(0..256),
            ],
            [64, 1, 1],
            vec![Node::store(
                "out",
                Expr::gid_x(),
                Expr::add(Expr::u32(1), Expr::load("a", Expr::gid_x())),
            )],
        );
        let first = Canonicalize::transform(program);
        let second = Canonicalize::transform(first.program);
        assert!(!second.changed, "Fix: canonicalize must be idempotent");
    }

    #[test]
    fn canonicalize_pass_skips_already_canonical() {
        let program = Program::wrapped(
            vec![
                BufferDecl::read("a", 0, DataType::U32).with_count(64),
                BufferDecl::output("out", 1, DataType::U32)
                    .with_count(64)
                    .with_output_byte_range(0..256),
            ],
            [64, 1, 1],
            vec![Node::store(
                "out",
                Expr::gid_x(),
                Expr::add(Expr::load("a", Expr::gid_x()), Expr::u32(1)),
            )],
        );
        let result = Canonicalize::transform(program);
        assert!(
            !result.changed,
            "Fix: canonical-form input must not flip the changed flag"
        );
    }
}
