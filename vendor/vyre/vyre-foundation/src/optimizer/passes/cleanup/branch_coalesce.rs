//! `branch_coalesce` — collapse nested `Node::If` whose outer body is
//! exactly one inner `If` with no `otherwise` arm into a single `If`
//! whose condition is `And(outer_cond, inner_cond)`.
//!
//! Op id: `vyre-foundation::optimizer::passes::branch_coalesce`.
//! Soundness: `Exact` — both `Then` arms run only when both
//! conditions are true; both `Otherwise` arms are empty so there is no
//! else-arm semantics to preserve. Cost direction: monotone-down on
//! `node_count + control_flow_count`. Preserves: every analysis.
//! Invalidates: nothing.
//!
//! ## Rule
//!
//! ```text
//! Node::If {
//!     cond: c1,
//!     then: [Node::If { cond: c2, then: body, otherwise: [] }],
//!     otherwise: [],
//! }
//! →
//! Node::If {
//!     cond: And(c1, c2),
//!     then: body,
//!     otherwise: [],
//! }
//! ```
//!
//! Comes up frequently after region inlining and CSE: domain code
//! often writes `if (in_bounds(x)) { if (matches_pattern(x)) { ... } }`
//! and the optimizer should see one combined predicate instead of two
//! nested branches. Coalescing also unblocks downstream
//! const-fold/boolean-simplification (ROADMAP A25) since the combined
//! predicate may collapse further when one of the conditions is a
//! literal.
//!
//! Does NOT fire (deliberately):
//!   - when the outer `then` has more than one child node — sibling
//!     statements would otherwise be hoisted into the inner branch and
//!     change observable order.
//!   - when either `otherwise` arm is non-empty — would lose else-arm
//!     semantics.
//!   - when the conditions involve side-effects (Load, Atomic, Call,
//!     Opaque). Even pure-looking expression evaluation may matter when
//!     the inner cond depends on a state mutation hidden inside the
//!     outer cond's evaluation; the conservative rule keeps both
//!     conditions evaluated lexically by skipping when either touches
//!     impure constructs.

use crate::ir::{Expr, Node, Program};
use crate::optimizer::{vyre_pass, PassAnalysis, PassResult};
use crate::visit::node_map;

/// Drop the inner `Node::If` and merge its condition into the outer's
/// via logical AND.
#[derive(Debug, Default)]
#[vyre_pass(
    name = "branch_coalesce",
    requires = [],
    invalidates = []
)]
pub struct BranchCoalesce;

impl BranchCoalesce {
    /// Skip the pass when no body in the program contains a nested-If
    /// pair matching the rule.
    #[must_use]
    fn analyze_impl(program: &Program) -> PassAnalysis {
        if program
            .entry()
            .iter()
            .any(|n| node_map::any_descendant(n, &mut is_coalesceable_if))
        {
            PassAnalysis::RUN
        } else {
            PassAnalysis::SKIP
        }
    }

    /// Walk the program; replace every coalesceable nested If with a
    /// single If carrying the conjoined predicate.
    #[must_use]
    pub fn transform(program: Program) -> PassResult {
        let scaffold = program.with_rewritten_entry(Vec::new());
        let mut changed = false;
        let entry: Vec<Node> = program
            .into_entry_vec()
            .into_iter()
            .map(|n| rewrite_node(n, &mut changed))
            .collect();
        PassResult {
            program: scaffold.with_rewritten_entry(entry),
            changed,
        }
    }}

/// Recurse into `node`'s descendants, then attempt to coalesce at
/// `node` itself. Children are rewritten first so deeply-nested
/// `If(c1) { If(c2) { If(c3) { ... } } }` chains coalesce bottom-up
/// in a single pass.
fn rewrite_node(node: Node, changed: &mut bool) -> Node {
    let recursed = node_map::map_children(node, &mut |child| rewrite_node(child, changed));
    let recursed = node_map::map_body(recursed, &mut |body| {
        body.into_iter().map(|n| rewrite_node(n, changed)).collect()
    });
    coalesce_if(recursed, changed)
}

/// Apply the coalesce rule to `node` if it matches; otherwise return
/// it unchanged.
fn coalesce_if(node: Node, changed: &mut bool) -> Node {
    let Node::If {
        cond: outer_cond,
        then,
        otherwise,
    } = node
    else {
        return node_unchanged_helper(node);
    };
    if !otherwise.is_empty() || then.len() != 1 {
        return Node::If {
            cond: outer_cond,
            then,
            otherwise,
        };
    }
    let mut then_iter = then.into_iter();
    let inner = then_iter.next().expect("then.len() == 1 by guard above");
    let Node::If {
        cond: inner_cond,
        then: inner_then,
        otherwise: inner_otherwise,
    } = inner
    else {
        return Node::If {
            cond: outer_cond,
            then: vec![inner],
            otherwise,
        };
    };
    if !inner_otherwise.is_empty() {
        return Node::If {
            cond: outer_cond,
            then: vec![Node::If {
                cond: inner_cond,
                then: inner_then,
                otherwise: inner_otherwise,
            }],
            otherwise,
        };
    }
    if !is_pure_bool_expr(&outer_cond) || !is_pure_bool_expr(&inner_cond) {
        return Node::If {
            cond: outer_cond,
            then: vec![Node::If {
                cond: inner_cond,
                then: inner_then,
                otherwise: inner_otherwise,
            }],
            otherwise,
        };
    }
    *changed = true;
    Node::If {
        cond: Expr::and(outer_cond, inner_cond),
        then: inner_then,
        otherwise,
    }
}

fn node_unchanged_helper(node: Node) -> Node {
    node
}

/// Cheap matcher used by `analyze`: true iff `node` is an outer-If
/// whose body is a single inner-If with empty otherwise. Keeps the
/// scheduler from running `transform` on programs that have no work.
fn is_coalesceable_if(node: &Node) -> bool {
    let Node::If {
        cond: outer_cond,
        then,
        otherwise,
    } = node
    else {
        return false;
    };
    if !otherwise.is_empty() || then.len() != 1 {
        return false;
    }
    let Node::If {
        cond: inner_cond,
        otherwise: inner_otherwise,
        ..
    } = &then[0]
    else {
        return false;
    };
    if !inner_otherwise.is_empty() {
        return false;
    }
    is_pure_bool_expr(outer_cond) && is_pure_bool_expr(inner_cond)
}

/// True iff `expr` produces a boolean value via pure operations only.
/// Loads, atomics, calls, and opaque extensions are rejected — their
/// repeated or reordered evaluation could change observable behavior.
fn is_pure_bool_expr(expr: &Expr) -> bool {
    match expr {
        Expr::LitBool(_) => true,
        Expr::Var(_) => true,
        Expr::BinOp { left, right, .. } => is_pure_bool_expr(left) && is_pure_bool_expr(right),
        Expr::UnOp { operand, .. } => is_pure_bool_expr(operand),
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => is_pure_bool_expr(cond) && is_pure_bool_expr(true_val) && is_pure_bool_expr(false_val),
        Expr::Cast { value, .. } => is_pure_bool_expr(value),
        // Builtins are pure and observably free.
        Expr::InvocationId { .. }
        | Expr::WorkgroupId { .. }
        | Expr::LocalId { .. }
        | Expr::SubgroupLocalId
        | Expr::SubgroupSize => true,
        // Literals other than bool are fine as operands of pure binops
        // (e.g. `i < n` where `n` is a u32 literal).
        Expr::LitU32(_) | Expr::LitI32(_) | Expr::LitF32(_) => true,
        // Anything that reads memory or invokes side effects is
        // rejected to keep ordering observable.
        Expr::Load { .. }
        | Expr::BufLen { .. }
        | Expr::Atomic { .. }
        | Expr::Call { .. }
        | Expr::Opaque(_)
        | Expr::Fma { .. }
        | Expr::SubgroupBallot { .. }
        | Expr::SubgroupShuffle { .. }
        | Expr::SubgroupAdd { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BufferAccess, BufferDecl, DataType, Expr, Ident, Node};

    fn buf() -> BufferDecl {
        BufferDecl::storage("buf", 0, BufferAccess::ReadWrite, DataType::U32).with_count(4)
    }

    fn program_with_entry(entry: Vec<Node>) -> Program {
        Program::wrapped(vec![buf()], [1, 1, 1], entry)
    }

    fn count_ifs(node: &Node) -> usize {
        match node {
            Node::If {
                then, otherwise, ..
            } => {
                1 + then.iter().map(count_ifs).sum::<usize>()
                    + otherwise.iter().map(count_ifs).sum::<usize>()
            }
            Node::Loop { body, .. } | Node::Block(body) => body.iter().map(count_ifs).sum(),
            Node::Region { body, .. } => body.iter().map(count_ifs).sum(),
            _ => 0,
        }
    }

    fn first_if_cond(entry: &[Node]) -> Option<&Expr> {
        for node in entry {
            match node {
                Node::If { cond, .. } => return Some(cond),
                Node::Region { body, .. } => {
                    if let Some(c) = first_if_cond(body.as_ref()) {
                        return Some(c);
                    }
                }
                Node::Block(body) | Node::Loop { body, .. } => {
                    if let Some(c) = first_if_cond(body) {
                        return Some(c);
                    }
                }
                _ => {}
            }
        }
        None
    }

    #[test]
    fn coalesces_nested_if_with_two_pure_conds() {
        let entry = vec![Node::if_then(
            Expr::var("c1"),
            vec![Node::if_then(
                Expr::var("c2"),
                vec![Node::store("buf", Expr::u32(0), Expr::u32(7))],
            )],
        )];
        let program = program_with_entry(entry);
        let result = BranchCoalesce::transform(program);
        assert!(result.changed);
        let entry: Vec<&Node> = result.program.entry().iter().collect();
        let total: usize = entry.iter().map(|n| count_ifs(n)).sum();
        assert_eq!(total, 1, "two nested Ifs collapse into one");
        let cond = first_if_cond(result.program.entry()).expect("Fix: must have an If");
        assert_eq!(cond, &Expr::and(Expr::var("c1"), Expr::var("c2")));
    }

    #[test]
    fn does_not_coalesce_when_outer_has_sibling() {
        // Outer If body has an extra Store sibling alongside the inner
        // If — coalescing would change observable order.
        let entry = vec![Node::if_then(
            Expr::var("c1"),
            vec![
                Node::store("buf", Expr::u32(0), Expr::u32(7)),
                Node::if_then(
                    Expr::var("c2"),
                    vec![Node::store("buf", Expr::u32(1), Expr::u32(8))],
                ),
            ],
        )];
        let program = program_with_entry(entry);
        let result = BranchCoalesce::transform(program);
        assert!(
            !result.changed,
            "must not hoist sibling Store into combined branch"
        );
    }

    #[test]
    fn does_not_coalesce_when_outer_has_otherwise() {
        let entry = vec![Node::if_then_else(
            Expr::var("c1"),
            vec![Node::if_then(
                Expr::var("c2"),
                vec![Node::store("buf", Expr::u32(0), Expr::u32(7))],
            )],
            vec![Node::store("buf", Expr::u32(0), Expr::u32(9))],
        )];
        let program = program_with_entry(entry);
        let result = BranchCoalesce::transform(program);
        assert!(!result.changed, "outer else-arm must be preserved");
    }

    #[test]
    fn does_not_coalesce_when_inner_has_otherwise() {
        let entry = vec![Node::if_then(
            Expr::var("c1"),
            vec![Node::if_then_else(
                Expr::var("c2"),
                vec![Node::store("buf", Expr::u32(0), Expr::u32(7))],
                vec![Node::store("buf", Expr::u32(0), Expr::u32(9))],
            )],
        )];
        let program = program_with_entry(entry);
        let result = BranchCoalesce::transform(program);
        assert!(!result.changed, "inner else-arm must be preserved");
    }

    #[test]
    fn does_not_coalesce_when_outer_cond_loads_memory() {
        let entry = vec![Node::if_then(
            Expr::eq(Expr::load("buf", Expr::u32(0)), Expr::u32(0)),
            vec![Node::if_then(
                Expr::var("c2"),
                vec![Node::store("buf", Expr::u32(0), Expr::u32(7))],
            )],
        )];
        let program = program_with_entry(entry);
        let result = BranchCoalesce::transform(program);
        assert!(
            !result.changed,
            "outer cond reads memory; conjoining could change ordering"
        );
    }

    #[test]
    fn does_not_coalesce_when_inner_cond_loads_memory() {
        let entry = vec![Node::if_then(
            Expr::var("c1"),
            vec![Node::if_then(
                Expr::eq(Expr::load("buf", Expr::u32(0)), Expr::u32(0)),
                vec![Node::store("buf", Expr::u32(0), Expr::u32(7))],
            )],
        )];
        let program = program_with_entry(entry);
        let result = BranchCoalesce::transform(program);
        assert!(
            !result.changed,
            "inner cond reads memory; conjoining could change ordering"
        );
    }

    #[test]
    fn coalesces_three_level_nesting_in_one_pass() {
        // If(c1) { If(c2) { If(c3) { body } } } → If(And(And(c1,c2),c3)) { body }
        // bottom-up rewrite: inner two coalesce first, then outer
        // joins.
        let entry = vec![Node::if_then(
            Expr::var("c1"),
            vec![Node::if_then(
                Expr::var("c2"),
                vec![Node::if_then(
                    Expr::var("c3"),
                    vec![Node::store("buf", Expr::u32(0), Expr::u32(1))],
                )],
            )],
        )];
        let program = program_with_entry(entry);
        let result = BranchCoalesce::transform(program);
        assert!(result.changed);
        let total: usize = result.program.entry().iter().map(|n| count_ifs(n)).sum();
        assert_eq!(total, 1, "three nested Ifs collapse into one");
        let cond = first_if_cond(result.program.entry()).expect("Fix: must have an If");
        // Order: c2 and c3 join first, then c1 ANDed with that.
        let expected = Expr::and(Expr::var("c1"), Expr::and(Expr::var("c2"), Expr::var("c3")));
        assert_eq!(cond, &expected);
    }

    #[test]
    fn analyze_skips_program_with_no_coalesceable_pair() {
        let entry = vec![Node::if_then(
            Expr::var("c1"),
            vec![Node::store("buf", Expr::u32(0), Expr::u32(1))],
        )];
        let program = program_with_entry(entry);
        assert_eq!(crate::optimizer::ProgramPass::analyze(&BranchCoalesce, &program), PassAnalysis::SKIP);
    }

    #[test]
    fn analyze_runs_when_coalesceable_pair_present() {
        let entry = vec![Node::if_then(
            Expr::var("c1"),
            vec![Node::if_then(
                Expr::var("c2"),
                vec![Node::store("buf", Expr::u32(0), Expr::u32(7))],
            )],
        )];
        let program = program_with_entry(entry);
        assert_eq!(crate::optimizer::ProgramPass::analyze(&BranchCoalesce, &program), PassAnalysis::RUN);
    }

    #[test]
    fn coalesces_inside_loop_body() {
        // Nested If inside a Loop body still coalesces — the Loop
        // itself is not the trigger; the rule fires on the inner pair.
        let loop_var = Ident::from("i");
        let entry = vec![Node::loop_for(
            loop_var.as_str(),
            Expr::u32(0),
            Expr::u32(8),
            vec![Node::if_then(
                Expr::var("c1"),
                vec![Node::if_then(
                    Expr::var("c2"),
                    vec![Node::store("buf", Expr::var("i"), Expr::u32(7))],
                )],
            )],
        )];
        let program = program_with_entry(entry);
        let result = BranchCoalesce::transform(program);
        assert!(result.changed);
        let total: usize = result.program.entry().iter().map(|n| count_ifs(n)).sum();
        assert_eq!(total, 1, "nested If inside Loop coalesces");
    }
}
