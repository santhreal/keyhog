/// Optimization pass test suites.
pub mod cse;

#[cfg(test)]
mod region_reconcile {
    use crate::ir::{BufferDecl, DataType, Expr, Node, Program};
    use crate::transform::optimize::optimize;

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
