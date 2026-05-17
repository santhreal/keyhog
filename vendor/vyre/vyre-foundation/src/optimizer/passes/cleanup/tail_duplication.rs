//! `tail_duplication` — hoist a common tail out of a divergent `Node::If`.
//!
//! Op id: `vyre-foundation::optimizer::passes::tail_duplication`.
//! Soundness: `Exact` — when both arms end with an identical, side-effect-free
//! tail node, that tail is observably equivalent to executing it after the If.
//! Cost-direction: monotone-down on code_size (removes one duplicated node).
//! Preserves: every analysis. Invalidates: nothing.
//!
//! ## Pattern
//!
//! ```text
//! If(c, [a, b], [a', b])
//!   where b == b' (identical tail)
//!   and b has length 1
//!   and b is observably side-effect-free
//!   → If(c, [a], [a']); b
//! ```
//!
//! ## ROADMAP
//!
//! A32 — tail duplication for divergent branches.

use crate::ir::{Node, Program};
use crate::optimizer::{vyre_pass, PassAnalysis, PassResult};
use crate::visit::node_map;

/// Hoist common side-effect-free tails out of `Node::If`.
#[derive(Debug, Default)]
#[vyre_pass(
    name = "tail_duplication",
    requires = [],
    invalidates = []
)]
pub struct TailDuplicationPass;

impl TailDuplicationPass {
    /// Skip programs without any candidate If.
    #[must_use]
    fn analyze_impl(program: &Program) -> PassAnalysis {
        if program
            .entry()
            .iter()
            .any(|n| node_map::any_descendant(n, &mut is_tail_candidate))
        {
            PassAnalysis::RUN
        } else {
            PassAnalysis::SKIP
        }
    }

    /// Walk the entry tree; hoist common tails.
    #[must_use]
    pub fn transform(program: Program) -> PassResult {
        let scaffold = program.with_rewritten_entry(Vec::new());
        let mut changed = false;
        let entry: Vec<Node> = program
            .into_entry_vec()
            .into_iter()
            .flat_map(|node| hoist_tail(node, &mut changed))
            .collect();
        PassResult {
            program: scaffold.with_rewritten_entry(entry),
            changed,
        }
    }}

/// Recurse into descendants, then try to hoist this node's tail.
fn hoist_tail(node: Node, changed: &mut bool) -> Vec<Node> {
    // First recurse into children
    let recursed = node_map::map_children(node, &mut |child| {
        let hoisted = hoist_tail(child, changed);
        if hoisted.len() == 1 {
            hoisted
                .into_iter()
                .next()
                .unwrap_or(Node::Block(Vec::new()))
        } else {
            Node::Block(hoisted)
        }
    });

    // Then try to hoist from this node's body
    if let Node::If {
        cond,
        then,
        otherwise,
    } = recursed
    {
        if let Some((new_then, new_otherwise, tail)) = try_extract_tail(&then, &otherwise) {
            *changed = true;
            let new_if = Node::If {
                cond,
                then: new_then,
                otherwise: new_otherwise,
            };
            return vec![new_if, tail];
        }
        return vec![Node::If {
            cond,
            then,
            otherwise,
        }];
    }

    vec![recursed]
}

/// Try to extract a common tail from `then` and `otherwise` arms.
///
/// Returns `Some((new_then, new_otherwise, tail))` when:
/// - Both arms are non-empty
/// - Last node of each arm is identical
/// - The common tail is a single node that is observably free
fn try_extract_tail(then: &[Node], otherwise: &[Node]) -> Option<(Vec<Node>, Vec<Node>, Node)> {
    if then.is_empty() || otherwise.is_empty() {
        return None;
    }

    let then_tail = then.last()?;
    let otherwise_tail = otherwise.last()?;

    if then_tail != otherwise_tail {
        return None;
    }

    if !node_is_observably_free(then_tail) {
        return None;
    }

    let tail = then_tail.clone();
    let new_then = then[..then.len() - 1].to_vec();
    let new_otherwise = otherwise[..otherwise.len() - 1].to_vec();
    Some((new_then, new_otherwise, tail))
}

/// True iff `node` has no observable side effects (no Store, Atomic,
/// Loop, Barrier, AsyncLoad/AsyncStore, etc.).
fn node_is_observably_free(node: &Node) -> bool {
    match node {
        Node::Let { .. } => true,
        Node::Block(body) => body.iter().all(node_is_observably_free),
        // Everything else has or may have side effects.
        Node::Store { .. }
        | Node::Assign { .. }
        | Node::If { .. }
        | Node::Loop { .. }
        | Node::Region { .. }
        | Node::Return
        | Node::Barrier { .. }
        | Node::IndirectDispatch { .. }
        | Node::AsyncLoad { .. }
        | Node::AsyncStore { .. }
        | Node::AsyncWait { .. }
        | Node::Trap { .. }
        | Node::Resume { .. }
        | Node::Opaque(_) => false,
    }
}

/// True iff `node` is an `If` whose arms have an extractable common tail.
fn is_tail_candidate(node: &Node) -> bool {
    if let Node::If {
        then, otherwise, ..
    } = node
    {
        try_extract_tail(then, otherwise).is_some()
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BufferAccess, BufferDecl, DataType, Expr, Node};

    fn buf() -> BufferDecl {
        BufferDecl::storage("buf", 0, BufferAccess::ReadWrite, DataType::U32).with_count(4)
    }

    fn program_with_entry(entry: Vec<Node>) -> Program {
        Program::wrapped(vec![buf()], [1, 1, 1], entry)
    }

    /// Positive: common Let tail is hoisted out.
    #[test]
    fn hoists_common_let_tail() {
        let common = Node::let_bind("x", Expr::u32(42));
        let entry = vec![Node::If {
            cond: Expr::var("c"),
            then: vec![
                Node::store("buf", Expr::u32(0), Expr::u32(1)),
                common.clone(),
            ],
            otherwise: vec![Node::store("buf", Expr::u32(0), Expr::u32(2)), common],
        }];
        let program = program_with_entry(entry);
        let result = TailDuplicationPass::transform(program);
        assert!(result.changed, "common tail must be hoisted");
    }

    /// Negative: tails differ.
    #[test]
    fn keeps_when_tails_differ() {
        let entry = vec![Node::If {
            cond: Expr::var("c"),
            then: vec![Node::let_bind("x", Expr::u32(1))],
            otherwise: vec![Node::let_bind("x", Expr::u32(2))],
        }];
        let program = program_with_entry(entry);
        let result = TailDuplicationPass::transform(program);
        assert!(!result.changed, "must not hoist when tails are different");
    }

    /// Negative: tail has side effects (Store).
    #[test]
    fn keeps_when_tail_has_side_effects() {
        let common = Node::store("buf", Expr::u32(0), Expr::u32(7));
        let entry = vec![Node::If {
            cond: Expr::var("c"),
            then: vec![Node::let_bind("x", Expr::u32(1)), common.clone()],
            otherwise: vec![Node::let_bind("x", Expr::u32(2)), common],
        }];
        let program = program_with_entry(entry);
        let result = TailDuplicationPass::transform(program);
        assert!(
            !result.changed,
            "must not hoist tail with Store (side effects)"
        );
    }

    #[test]
    fn keeps_when_tail_is_loop() {
        let common = Node::Loop {
            var: crate::ir::Ident::from("i"),
            from: Expr::u32(0),
            to: Expr::u32(5),
            body: vec![],
        };
        let entry = vec![Node::If {
            cond: Expr::var("c"),
            then: vec![Node::let_bind("x", Expr::u32(1)), common.clone()],
            otherwise: vec![Node::let_bind("x", Expr::u32(2)), common],
        }];
        let program = program_with_entry(entry);
        let result = TailDuplicationPass::transform(program);
        assert!(!result.changed, "must not hoist Loop as tail");
    }

    #[test]
    fn analyze_skips_program_with_no_tail_candidates() {
        let entry = vec![Node::store("buf", Expr::u32(0), Expr::u32(7))];
        let program = program_with_entry(entry);
        assert_eq!(crate::optimizer::ProgramPass::analyze(&TailDuplicationPass, &program), PassAnalysis::SKIP);
    }

    #[test]
    fn analyze_runs_when_tail_candidate_present() {
        let common = Node::let_bind("x", Expr::u32(42));
        let entry = vec![Node::If {
            cond: Expr::var("c"),
            then: vec![
                Node::store("buf", Expr::u32(0), Expr::u32(1)),
                common.clone(),
            ],
            otherwise: vec![Node::store("buf", Expr::u32(0), Expr::u32(2)), common],
        }];
        let program = program_with_entry(entry);
        assert_eq!(crate::optimizer::ProgramPass::analyze(&TailDuplicationPass, &program), PassAnalysis::RUN);
    }
}
