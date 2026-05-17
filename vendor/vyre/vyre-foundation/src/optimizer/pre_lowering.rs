//! Pre-lowering optimization pipeline.
//!
//! Composes the small set of expression-level passes (canonicalize,
//! region_inline, const_fold, loop_strip_mine, loop_unroll, strength_reduce,
//! normalize_atomics, then CSE+DCE) that every backend wants run
//! before lowering. Frontends emit naive IR and rely on this entry
//! to clean it up; backends with fixed bind-group layouts can call
//! it directly without spinning up the full `PassScheduler`.
//!
//! Buffer-level passes (dead_buffer_elim, fusion, autotune) are
//! available via [`crate::optimizer::PassScheduler`] for callers
//! that control the full pipeline and can reconcile ABI changes
//! with their host dispatch.

use crate::ir_inner::model::program::Program;

/// Run the unified pre-lowering optimization pipeline.
///
/// Pipeline stages (in order):
/// 1. **Canonicalize** — deterministic operand ordering so downstream
///    passes see a stable, content-addressable form.
/// 2. **Region inline** — flatten small `Node::Region` debug-wrappers
///    so the optimizer sees one unit.
/// 3. **Expression-level optimizer fixpoint** — runs safe, ABI-preserving
///    passes (const_fold, loop_strip_mine, loop_unroll, strength_reduce, normalize_atomics)
///    to a fixed point. These passes preserve buffer declarations and the
///    top-level runnable shape.
/// 4. **CSE** — common-subexpression elimination on the optimized IR.
/// 5. **DCE** — dead-code elimination cleans up anything CSE exposed.
#[must_use]
#[inline]
pub fn optimize(program: Program) -> Program {
    use crate::optimizer::passes::algebraic::canonicalize_engine;
    use crate::optimizer::passes::cleanup::region_inline_engine;

    // Phase 1: canonicalize + region_inline (preparation)
    let prepared =
        region_inline_engine::run(canonicalize_engine::run(program)).reconcile_runnable_top_level();

    // Phase 2: expression-level optimizer fixpoint.
    // Only runs passes that preserve buffer declarations and top-level
    // runnable shape — safe for programs with fixed GPU bind-group layouts.
    let scheduled = {
        use crate::optimizer::passes::const_fold::ConstFold;
        use crate::optimizer::passes::loop_strip_mine::LoopStripMine;
        use crate::optimizer::passes::loop_unroll::LoopUnroll;
        use crate::optimizer::passes::normalize_atomics::NormalizeAtomicsPass;
        use crate::optimizer::passes::strength_reduce::StrengthReduce;
        use crate::optimizer::{PassScheduler, ProgramPassKind};

        PassScheduler::with_passes(vec![
            ProgramPassKind::new(ConstFold),
            ProgramPassKind::new(LoopStripMine),
            ProgramPassKind::new(LoopUnroll),
            ProgramPassKind::new(StrengthReduce),
            ProgramPassKind::new(NormalizeAtomicsPass),
        ])
        .run(prepared)
        .unwrap_or_else(|_| {
            // Convergence failure is near-impossible on the small set of
            // safe ABI-preserving passes. If it does happen the last-good
            // result is inside the error — callers surface a warning.
            // The original `prepared` was moved into `.run()`, so we
            // accept the scheduler’s partial output here.
            panic!(
                "pre-lowering phase 2 did not converge. \
                 Fix: inspect the pass set for oscillating rewrites."
            )
        })
    };

    // Phase 3: CSE + DCE (cleanup), then region-inline (flatten any empty
    // regions DCE exposed), then re-canonicalize so a second optimize run
    // is byte-stable.
    let cleaned = canonicalize_engine::run(region_inline_engine::run(
        crate::optimizer::passes::fusion_cse::dce::engine::dce(
            crate::optimizer::passes::fusion_cse::cse::engine::cse(scheduled),
        ),
    ));

    // Phase 4: final ConstFold sweep. The phase-3 canonicalize sometimes
    // exposes new fold-eligible patterns by sorting commutative-op
    // operands so any literal lands on the right (e.g. an upstream
    // `Ge(t, 0)` that the PassScheduler folded to `LitBool(true)` then
    // appears as `BinOp::And { right: LitBool(true) }` after the final
    // canonicalize, which the binop_identities `And(x, true) → x` rule
    // catches in one more pass). Without this sweep, `optimize(p)` is
    // not idempotent on programs whose Select.cond chains contain
    // mixed literal-and-non-literal logical ops; the universal_cat_a
    // harness on `vyre-libs::visual::gradient` catches that gap.
    let phase4 = {
        use crate::optimizer::passes::algebraic::canonicalize::Canonicalize;
        use crate::optimizer::passes::cleanup::if_constant_branch_eliminate::IfConstantBranchEliminatePass;
        use crate::optimizer::passes::const_fold::ConstFold;
        use crate::optimizer::passes::fusion_cse::dce::DcePass;
        use crate::optimizer::passes::region_inline::RegionInlinePass;
        use crate::optimizer::{PassScheduler, ProgramPassKind};

        PassScheduler::with_passes(vec![
            ProgramPassKind::new(ConstFold),
            ProgramPassKind::new(IfConstantBranchEliminatePass),
            ProgramPassKind::new(Canonicalize),
            ProgramPassKind::new(DcePass),
            ProgramPassKind::new(RegionInlinePass),
        ])
        .run(cleaned)
        .unwrap_or_else(|e| {
            panic!(
                "pre-lowering phase 4 did not converge after 50 iterations: {:?}. \
                 Fix: inspect the phase for oscillating rewrites or raise the cap only with a convergence certificate.",
                e
            )
        })
    };

    let final_prog = phase4.reconcile_runnable_top_level();
    std::fs::write("ast_dump.txt", format!("{:#?}", final_prog)).unwrap();
    final_prog
}

#[cfg(test)]
mod tests {
    use super::optimize;
    use crate::ir::{BufferDecl, DataType, Expr, Node, Program};

    #[test]
    fn optimize_preserves_top_level_region_wrap_after_inline() {
        // A wrapped program with a single small region that region_inline
        // may flatten. After the full optimize() pipeline the top-level
        // region-wrap invariant must still hold.
        let program = Program::wrapped(
            vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
            [1, 1, 1],
            vec![Node::store("out", Expr::u32(0), Expr::u32(7))],
        );
        assert!(program.is_top_level_region_wrapped());
        let optimized = optimize(program);
        assert!(
            optimized.is_top_level_region_wrapped(),
            "Fix: optimize() must preserve top-level region-wrap invariant after region_inline"
        );
    }
}
