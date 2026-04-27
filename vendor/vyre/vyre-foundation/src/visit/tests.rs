use super::*;
use crate::ir_inner::model::expr::{Expr, ExprNode, GeneratorRef, Ident};
use crate::ir_inner::model::generated::Node;
use crate::ir_inner::model::types::{AtomicOp, BinOp, DataType, UnOp};
use std::convert::Infallible;
use std::ops::ControlFlow::{self, Break, Continue};
use std::sync::Arc;

struct CountingExprVisitor {
    count: usize,
}

impl ExprVisitor for CountingExprVisitor {
    type Break = Infallible;

    fn visit_lit_u32(&mut self, _: &Expr, _: u32) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
    fn visit_lit_i32(&mut self, _: &Expr, _: i32) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
    fn visit_lit_f32(&mut self, _: &Expr, _: f32) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
    fn visit_lit_bool(&mut self, _: &Expr, _: bool) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
    fn visit_var(&mut self, _: &Expr, _: &Ident) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
    fn visit_load(&mut self, _: &Expr, _: &Ident, _: &Expr) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
    fn visit_buf_len(&mut self, _: &Expr, _: &Ident) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
    fn visit_invocation_id(&mut self, _: &Expr, _: u32) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
    fn visit_workgroup_id(&mut self, _: &Expr, _: u32) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
    fn visit_local_id(&mut self, _: &Expr, _: u32) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
    fn visit_bin_op(
        &mut self,
        expr: &Expr,
        _: &BinOp,
        _: &Expr,
        _: &Expr,
    ) -> ControlFlow<Self::Break> {
        self.count += 1;
        let _ = expr;
        Continue(())
    }
    fn visit_un_op(&mut self, expr: &Expr, _: &UnOp, _: &Expr) -> ControlFlow<Self::Break> {
        self.count += 1;
        let _ = expr;
        Continue(())
    }
    fn visit_call(&mut self, expr: &Expr, _: &str, _: &[Expr]) -> ControlFlow<Self::Break> {
        self.count += 1;
        let _ = expr;
        Continue(())
    }
    fn visit_sequence(&mut self, parts: &[Expr]) -> ControlFlow<Self::Break> {
        self.count += 1;
        let _ = parts;
        Continue(())
    }
    fn visit_fma(&mut self, expr: &Expr, _: &Expr, _: &Expr, _: &Expr) -> ControlFlow<Self::Break> {
        self.count += 1;
        let _ = expr;
        Continue(())
    }
    fn visit_select(
        &mut self,
        expr: &Expr,
        _: &Expr,
        _: &Expr,
        _: &Expr,
    ) -> ControlFlow<Self::Break> {
        self.count += 1;
        let _ = expr;
        Continue(())
    }
    fn visit_cast(&mut self, expr: &Expr, _: &DataType, _: &Expr) -> ControlFlow<Self::Break> {
        self.count += 1;
        let _ = expr;
        Continue(())
    }
    fn visit_atomic(
        &mut self,
        expr: &Expr,
        _: &AtomicOp,
        _: &Ident,
        _: &Expr,
        _: Option<&Expr>,
        _: &Expr,
    ) -> ControlFlow<Self::Break> {
        self.count += 1;
        let _ = expr;
        Continue(())
    }
    fn visit_subgroup_ballot(&mut self, expr: &Expr, _: &Expr) -> ControlFlow<Self::Break> {
        self.count += 1;
        let _ = expr;
        Continue(())
    }
    fn visit_subgroup_shuffle(
        &mut self,
        expr: &Expr,
        _: &Expr,
        _: &Expr,
    ) -> ControlFlow<Self::Break> {
        self.count += 1;
        let _ = expr;
        Continue(())
    }
    fn visit_subgroup_add(&mut self, expr: &Expr, _: &Expr) -> ControlFlow<Self::Break> {
        self.count += 1;
        let _ = expr;
        Continue(())
    }
    fn visit_subgroup_local_id(&mut self, _: &Expr) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
    fn visit_subgroup_size(&mut self, _: &Expr) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
    fn visit_opaque_expr(&mut self, _: &Expr, _: &dyn ExprNode) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
}

#[test]
fn expr_preorder_visits_every_node_once() {
    let expr = Expr::add(
        Expr::u32(1),
        Expr::select(Expr::bool(true), Expr::u32(2), Expr::u32(3)),
    );
    let mut visitor = CountingExprVisitor { count: 0 };
    visit_preorder(&mut visitor, &expr);
    assert_eq!(visitor.count, 6);
}

struct OrderVisitor {
    seen: Vec<&'static str>,
}

impl ExprVisitor for OrderVisitor {
    type Break = Infallible;

    fn visit_lit_u32(&mut self, _: &Expr, _: u32) -> ControlFlow<Self::Break> {
        self.seen.push("lit");
        Continue(())
    }
    fn visit_lit_i32(&mut self, _: &Expr, _: i32) -> ControlFlow<Self::Break> {
        unreachable!()
    }
    fn visit_lit_f32(&mut self, _: &Expr, _: f32) -> ControlFlow<Self::Break> {
        unreachable!()
    }
    fn visit_lit_bool(&mut self, _: &Expr, _: bool) -> ControlFlow<Self::Break> {
        self.seen.push("bool");
        Continue(())
    }
    fn visit_var(&mut self, _: &Expr, _: &Ident) -> ControlFlow<Self::Break> {
        unreachable!()
    }
    fn visit_load(&mut self, _: &Expr, _: &Ident, _: &Expr) -> ControlFlow<Self::Break> {
        unreachable!()
    }
    fn visit_buf_len(&mut self, _: &Expr, _: &Ident) -> ControlFlow<Self::Break> {
        unreachable!()
    }
    fn visit_invocation_id(&mut self, _: &Expr, _: u32) -> ControlFlow<Self::Break> {
        unreachable!()
    }
    fn visit_workgroup_id(&mut self, _: &Expr, _: u32) -> ControlFlow<Self::Break> {
        unreachable!()
    }
    fn visit_local_id(&mut self, _: &Expr, _: u32) -> ControlFlow<Self::Break> {
        unreachable!()
    }
    fn visit_bin_op(
        &mut self,
        _: &Expr,
        _: &BinOp,
        _: &Expr,
        _: &Expr,
    ) -> ControlFlow<Self::Break> {
        self.seen.push("bin");
        Continue(())
    }
    fn visit_un_op(&mut self, _: &Expr, _: &UnOp, _: &Expr) -> ControlFlow<Self::Break> {
        unreachable!()
    }
    fn visit_call(&mut self, _: &Expr, _: &str, _: &[Expr]) -> ControlFlow<Self::Break> {
        unreachable!()
    }
    fn visit_sequence(&mut self, _: &[Expr]) -> ControlFlow<Self::Break> {
        unreachable!()
    }
    fn visit_fma(&mut self, _: &Expr, _: &Expr, _: &Expr, _: &Expr) -> ControlFlow<Self::Break> {
        unreachable!()
    }
    fn visit_select(&mut self, _: &Expr, _: &Expr, _: &Expr, _: &Expr) -> ControlFlow<Self::Break> {
        self.seen.push("select");
        Continue(())
    }
    fn visit_cast(&mut self, _: &Expr, _: &DataType, _: &Expr) -> ControlFlow<Self::Break> {
        unreachable!()
    }
    fn visit_atomic(
        &mut self,
        _: &Expr,
        _: &AtomicOp,
        _: &Ident,
        _: &Expr,
        _: Option<&Expr>,
        _: &Expr,
    ) -> ControlFlow<Self::Break> {
        unreachable!()
    }
    fn visit_subgroup_ballot(&mut self, _: &Expr, _: &Expr) -> ControlFlow<Self::Break> {
        unreachable!()
    }
    fn visit_subgroup_shuffle(&mut self, _: &Expr, _: &Expr, _: &Expr) -> ControlFlow<Self::Break> {
        unreachable!()
    }
    fn visit_subgroup_add(&mut self, _: &Expr, _: &Expr) -> ControlFlow<Self::Break> {
        unreachable!()
    }
    fn visit_subgroup_local_id(&mut self, _: &Expr) -> ControlFlow<Self::Break> {
        unreachable!()
    }
    fn visit_subgroup_size(&mut self, _: &Expr) -> ControlFlow<Self::Break> {
        unreachable!()
    }
    fn visit_opaque_expr(&mut self, _: &Expr, _: &dyn ExprNode) -> ControlFlow<Self::Break> {
        unreachable!()
    }
}

#[test]
fn expr_postorder_visits_children_before_parent() {
    let expr = Expr::select(
        Expr::bool(true),
        Expr::u32(1),
        Expr::add(Expr::u32(2), Expr::u32(3)),
    );
    let mut visitor = OrderVisitor { seen: Vec::new() };
    visit_postorder(&mut visitor, &expr);
    assert_eq!(
        visitor.seen,
        vec!["bool", "lit", "lit", "lit", "bin", "select"]
    );
}

struct FirstAtomicVisitor;

impl ExprVisitor for FirstAtomicVisitor {
    type Break = &'static str;

    fn visit_lit_u32(&mut self, _: &Expr, _: u32) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_lit_i32(&mut self, _: &Expr, _: i32) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_lit_f32(&mut self, _: &Expr, _: f32) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_lit_bool(&mut self, _: &Expr, _: bool) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_var(&mut self, _: &Expr, _: &Ident) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_load(&mut self, expr: &Expr, _: &Ident, _: &Expr) -> ControlFlow<Self::Break> {
        let _ = expr;
        Continue(())
    }
    fn visit_buf_len(&mut self, _: &Expr, _: &Ident) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_invocation_id(&mut self, _: &Expr, _: u32) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_workgroup_id(&mut self, _: &Expr, _: u32) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_local_id(&mut self, _: &Expr, _: u32) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_bin_op(
        &mut self,
        expr: &Expr,
        _: &BinOp,
        _: &Expr,
        _: &Expr,
    ) -> ControlFlow<Self::Break> {
        let _ = expr;
        Continue(())
    }
    fn visit_un_op(&mut self, expr: &Expr, _: &UnOp, _: &Expr) -> ControlFlow<Self::Break> {
        let _ = expr;
        Continue(())
    }
    fn visit_call(&mut self, expr: &Expr, _: &str, _: &[Expr]) -> ControlFlow<Self::Break> {
        let _ = expr;
        Continue(())
    }
    fn visit_sequence(&mut self, _: &[Expr]) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_fma(&mut self, expr: &Expr, _: &Expr, _: &Expr, _: &Expr) -> ControlFlow<Self::Break> {
        let _ = expr;
        Continue(())
    }
    fn visit_select(
        &mut self,
        expr: &Expr,
        _: &Expr,
        _: &Expr,
        _: &Expr,
    ) -> ControlFlow<Self::Break> {
        let _ = expr;
        Continue(())
    }
    fn visit_cast(&mut self, expr: &Expr, _: &DataType, _: &Expr) -> ControlFlow<Self::Break> {
        let _ = expr;
        Continue(())
    }
    fn visit_atomic(
        &mut self,
        _: &Expr,
        _: &AtomicOp,
        _: &Ident,
        _: &Expr,
        _: Option<&Expr>,
        _: &Expr,
    ) -> ControlFlow<Self::Break> {
        Break("atomic")
    }
    fn visit_subgroup_ballot(&mut self, expr: &Expr, _: &Expr) -> ControlFlow<Self::Break> {
        let _ = expr;
        Continue(())
    }
    fn visit_subgroup_shuffle(
        &mut self,
        expr: &Expr,
        _: &Expr,
        _: &Expr,
    ) -> ControlFlow<Self::Break> {
        let _ = expr;
        Continue(())
    }
    fn visit_subgroup_add(&mut self, expr: &Expr, _: &Expr) -> ControlFlow<Self::Break> {
        let _ = expr;
        Continue(())
    }
    fn visit_subgroup_local_id(&mut self, _: &Expr) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_subgroup_size(&mut self, _: &Expr) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_opaque_expr(&mut self, _: &Expr, _: &dyn ExprNode) -> ControlFlow<Self::Break> {
        Continue(())
    }
}

#[test]
fn expr_visitor_can_short_circuit() {
    let expr = Expr::select(
        Expr::bool(true),
        Expr::Atomic {
            op: AtomicOp::Add,
            buffer: "out".into(),
            index: Box::new(Expr::u32(0)),
            expected: None,
            value: Box::new(Expr::u32(1)),
        },
        Expr::u32(0),
    );
    assert_eq!(
        visit_preorder(&mut FirstAtomicVisitor, &expr),
        Break("atomic")
    );
}

#[derive(Debug)]
struct TestOpaqueExpr;

impl ExprNode for TestOpaqueExpr {
    fn extension_kind(&self) -> &'static str {
        "test.opaque_expr"
    }

    fn debug_identity(&self) -> &str {
        "test"
    }

    fn result_type(&self) -> Option<DataType> {
        None
    }

    fn cse_safe(&self) -> bool {
        false
    }

    fn stable_fingerprint(&self) -> [u8; 32] {
        [7; 32]
    }

    fn validate_extension(&self) -> std::result::Result<(), String> {
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct CountingNodeVisitor {
    count: usize,
}

impl NodeVisitor for CountingNodeVisitor {
    type Break = Infallible;

    fn visit_let(&mut self, node: &Node, _: &Ident, _: &Expr) -> ControlFlow<Self::Break> {
        self.count += 1;
        let _ = node;
        Continue(())
    }
    fn visit_assign(&mut self, node: &Node, _: &Ident, _: &Expr) -> ControlFlow<Self::Break> {
        self.count += 1;
        let _ = node;
        Continue(())
    }
    fn visit_store(
        &mut self,
        node: &Node,
        _: &Ident,
        _: &Expr,
        _: &Expr,
    ) -> ControlFlow<Self::Break> {
        self.count += 1;
        let _ = node;
        Continue(())
    }
    fn visit_if(
        &mut self,
        node: &Node,
        _: &Expr,
        _: &[Node],
        _: &[Node],
    ) -> ControlFlow<Self::Break> {
        self.count += 1;
        let _ = node;
        Continue(())
    }
    fn visit_loop(
        &mut self,
        node: &Node,
        _: &Ident,
        _: &Expr,
        _: &Expr,
        _: &[Node],
    ) -> ControlFlow<Self::Break> {
        self.count += 1;
        let _ = node;
        Continue(())
    }
    fn visit_indirect_dispatch(&mut self, _: &Node, _: &Ident, _: u64) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
    fn visit_async_load(
        &mut self,
        _: &Node,
        _: &Ident,
        _: &Ident,
        _: &Expr,
        _: &Expr,
        _: &Ident,
    ) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
    fn visit_async_store(
        &mut self,
        _: &Node,
        _: &Ident,
        _: &Ident,
        _: &Expr,
        _: &Expr,
        _: &Ident,
    ) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
    fn visit_async_wait(&mut self, _: &Node, _: &Ident) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
    fn visit_trap(&mut self, _: &Node, _: &Expr, _: &Ident) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
    fn visit_resume(&mut self, _: &Node, _: &Ident) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
    fn visit_return(&mut self, _: &Node) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
    fn visit_barrier(&mut self, _: &Node) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
    fn visit_block(&mut self, node: &Node, _: &[Node]) -> ControlFlow<Self::Break> {
        self.count += 1;
        let _ = node;
        Continue(())
    }
    fn visit_region(
        &mut self,
        node: &Node,
        _: &Ident,
        _: &Option<GeneratorRef>,
        _: &[Node],
    ) -> ControlFlow<Self::Break> {
        self.count += 1;
        let _ = node;
        Continue(())
    }
    fn visit_opaque_node(
        &mut self,
        _: &Node,
        _: &dyn crate::ir_inner::model::node::NodeExtension,
    ) -> ControlFlow<Self::Break> {
        self.count += 1;
        Continue(())
    }
}

#[test]
fn node_preorder_visits_nested_nodes() {
    let node = Node::if_then(
        Expr::bool(true),
        vec![Node::loop_for(
            "i",
            Expr::u32(0),
            Expr::u32(2),
            vec![Node::return_()],
        )],
    );
    let mut visitor = CountingNodeVisitor { count: 0 };
    visit_node_preorder(&mut visitor, &node);
    assert_eq!(visitor.count, 3);
}

#[test]
fn expr_entry_point_handles_opaque_expr_explicitly() {
    let expr = Expr::Opaque(Arc::new(TestOpaqueExpr));
    let mut visitor = CountingExprVisitor { count: 0 };
    visit_expr(&mut visitor, &expr);
    assert_eq!(visitor.count, 1);
}

// ------------------------------------------------------------------
// Adversarial ControlFlow::Break tests for F-IR visitor exhaustiveness.
// ------------------------------------------------------------------

struct BreakOnFirstLitU32 {
    seen: Vec<u32>,
}

impl ExprVisitor for BreakOnFirstLitU32 {
    type Break = ();

    fn visit_lit_u32(&mut self, _: &Expr, value: u32) -> ControlFlow<Self::Break> {
        self.seen.push(value);
        Break(())
    }
    fn visit_lit_i32(&mut self, _: &Expr, _: i32) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_lit_f32(&mut self, _: &Expr, _: f32) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_lit_bool(&mut self, _: &Expr, _: bool) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_var(&mut self, _: &Expr, _: &Ident) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_load(&mut self, _: &Expr, _: &Ident, _: &Expr) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_buf_len(&mut self, _: &Expr, _: &Ident) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_invocation_id(&mut self, _: &Expr, _: u32) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_workgroup_id(&mut self, _: &Expr, _: u32) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_local_id(&mut self, _: &Expr, _: u32) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_bin_op(
        &mut self,
        _: &Expr,
        _: &BinOp,
        _: &Expr,
        _: &Expr,
    ) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_un_op(&mut self, _: &Expr, _: &UnOp, _: &Expr) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_call(&mut self, _: &Expr, _: &str, _: &[Expr]) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_sequence(&mut self, _: &[Expr]) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_fma(&mut self, _: &Expr, _: &Expr, _: &Expr, _: &Expr) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_select(&mut self, _: &Expr, _: &Expr, _: &Expr, _: &Expr) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_cast(&mut self, _: &Expr, _: &DataType, _: &Expr) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_atomic(
        &mut self,
        _: &Expr,
        _: &AtomicOp,
        _: &Ident,
        _: &Expr,
        _: Option<&Expr>,
        _: &Expr,
    ) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_subgroup_ballot(&mut self, _: &Expr, _: &Expr) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_subgroup_shuffle(&mut self, _: &Expr, _: &Expr, _: &Expr) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_subgroup_add(&mut self, _: &Expr, _: &Expr) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_subgroup_local_id(&mut self, _: &Expr) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_subgroup_size(&mut self, _: &Expr) -> ControlFlow<Self::Break> {
        Continue(())
    }
    fn visit_opaque_expr(&mut self, _: &Expr, _: &dyn ExprNode) -> ControlFlow<Self::Break> {
        Continue(())
    }
}

#[test]
fn preorder_breaks_at_first_literal_before_second() {
    // Adversarial: visit_preorder on a flat `LitU32 + LitU32` tree
    // must visit the root BinOp, then the left LitU32, then BREAK.
    // The right LitU32 must never be touched.
    let expr = Expr::add(Expr::u32(7), Expr::u32(9));
    let mut visitor = BreakOnFirstLitU32 { seen: Vec::new() };
    let result = visit_preorder(&mut visitor, &expr);
    assert_eq!(result, Break(()), "must short-circuit on first LitU32");
    assert_eq!(visitor.seen, vec![7], "must see ONLY the left literal");
}

#[test]
fn preorder_break_in_left_subtree_never_reaches_right() {
    // Adversarial: in a deeper tree `(1 + 2) + (3 + 4)`, preorder
    // visits the outer BinOp, then the left inner BinOp, then the
    // first LitU32 (1), then BREAK. The right subtree (3+4) must
    // never be visited.
    let expr = Expr::add(
        Expr::add(Expr::u32(1), Expr::u32(2)),
        Expr::add(Expr::u32(3), Expr::u32(4)),
    );
    let mut visitor = BreakOnFirstLitU32 { seen: Vec::new() };
    let result = visit_preorder(&mut visitor, &expr);
    assert_eq!(result, Break(()));
    assert_eq!(
        visitor.seen,
        vec![1],
        "must break in left subtree; right subtree unseen"
    );
}
