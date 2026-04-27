use crate::ir_inner::model::expr::{Expr, ExprNode, Ident};
use crate::ir_inner::model::types::{AtomicOp, BinOp, DataType, UnOp};
use crate::visit::VisitOrder;
use std::ops::ControlFlow;

/// Visitor over [`Expr`] trees.
///
/// Implementors must handle every core variant explicitly. This is
/// intentional: `Expr` is `#[non_exhaustive]`, so a new variant must
/// become a compile error in every visitor instead of silently
/// disappearing behind a default body.
///
/// Traversal order is explicit:
/// - [`visit_preorder`] visits the current expression before its children.
/// - [`visit_postorder`] visits children before the current expression.
///
/// Visitors that want pass-through recursion can call
/// [`ExprVisitor::walk_children_default`] from a variant method.
pub trait ExprVisitor {
    /// Break payload returned when traversal short-circuits.
    type Break;

    /// Integer literal (`u32`).
    fn visit_lit_u32(&mut self, expr: &Expr, value: u32) -> ControlFlow<Self::Break>;
    /// Integer literal (`i32`).
    fn visit_lit_i32(&mut self, expr: &Expr, value: i32) -> ControlFlow<Self::Break>;
    /// Float literal (`f32`).
    fn visit_lit_f32(&mut self, expr: &Expr, value: f32) -> ControlFlow<Self::Break>;
    /// Bool literal.
    fn visit_lit_bool(&mut self, expr: &Expr, value: bool) -> ControlFlow<Self::Break>;
    /// Variable reference.
    fn visit_var(&mut self, expr: &Expr, name: &Ident) -> ControlFlow<Self::Break>;
    /// Buffer load (`buffer[index]`).
    fn visit_load(&mut self, expr: &Expr, buffer: &Ident, index: &Expr)
        -> ControlFlow<Self::Break>;
    /// Buffer length.
    fn visit_buf_len(&mut self, expr: &Expr, buffer: &Ident) -> ControlFlow<Self::Break>;
    /// Invocation id axis (`gid.{x,y,z}`).
    fn visit_invocation_id(&mut self, expr: &Expr, axis: u32) -> ControlFlow<Self::Break>;
    /// Workgroup id axis.
    fn visit_workgroup_id(&mut self, expr: &Expr, axis: u32) -> ControlFlow<Self::Break>;
    /// Local id axis within the workgroup.
    fn visit_local_id(&mut self, expr: &Expr, axis: u32) -> ControlFlow<Self::Break>;
    /// Subgroup invocation id (lane index within subgroup).
    fn visit_subgroup_local_id(&mut self, expr: &Expr) -> ControlFlow<Self::Break>;
    /// Subgroup size.
    fn visit_subgroup_size(&mut self, expr: &Expr) -> ControlFlow<Self::Break>;
    /// Binary operation.
    fn visit_bin_op(
        &mut self,
        expr: &Expr,
        op: &BinOp,
        left: &Expr,
        right: &Expr,
    ) -> ControlFlow<Self::Break>;
    /// Unary operation.
    fn visit_un_op(&mut self, expr: &Expr, op: &UnOp, operand: &Expr) -> ControlFlow<Self::Break>;
    /// Function call.
    fn visit_call(&mut self, expr: &Expr, op_id: &str, args: &[Expr]) -> ControlFlow<Self::Break>;
    /// Sequence-valued extension hook.
    ///
    /// Core IR does not currently emit a dedicated `Expr::Sequence`
    /// variant, but downstream visitor implementations must still opt in
    /// explicitly so a future sequence node cannot compile behind a silent
    /// default body.
    fn visit_sequence(&mut self, parts: &[Expr]) -> ControlFlow<Self::Break>;
    /// Fused multiply-add (`a * b + c`).
    fn visit_fma(&mut self, expr: &Expr, a: &Expr, b: &Expr, c: &Expr) -> ControlFlow<Self::Break>;
    /// Ternary `select(cond, true_val, false_val)`.
    fn visit_select(
        &mut self,
        expr: &Expr,
        cond: &Expr,
        true_val: &Expr,
        false_val: &Expr,
    ) -> ControlFlow<Self::Break>;
    /// Numeric cast.
    fn visit_cast(
        &mut self,
        expr: &Expr,
        target: &DataType,
        value: &Expr,
    ) -> ControlFlow<Self::Break>;
    /// Atomic operation on a shared buffer.
    fn visit_atomic(
        &mut self,
        expr: &Expr,
        op: &AtomicOp,
        buffer: &Ident,
        index: &Expr,
        expected: Option<&Expr>,
        value: &Expr,
    ) -> ControlFlow<Self::Break>;
    /// Subgroup ballot.
    fn visit_subgroup_ballot(&mut self, expr: &Expr, cond: &Expr) -> ControlFlow<Self::Break>;
    /// Subgroup shuffle.
    fn visit_subgroup_shuffle(
        &mut self,
        expr: &Expr,
        value: &Expr,
        lane: &Expr,
    ) -> ControlFlow<Self::Break>;
    /// Subgroup add.
    fn visit_subgroup_add(&mut self, expr: &Expr, value: &Expr) -> ControlFlow<Self::Break>;
    /// Downstream opaque expression extension.
    fn visit_opaque_expr(
        &mut self,
        expr: &Expr,
        extension: &dyn ExprNode,
    ) -> ControlFlow<Self::Break>;

    /// Recursively walk this expression's children using the requested order.
    fn walk_children_default(&mut self, expr: &Expr, order: VisitOrder) -> ControlFlow<Self::Break>
    where
        Self: Sized,
    {
        walk_expr_children_default(self, expr, order)
    }
}

/// Visit an expression tree in pre-order.
///
/// This is the historical default entry point for expression traversal.
pub fn visit_expr<V: ExprVisitor>(visitor: &mut V, expr: &Expr) -> ControlFlow<V::Break> {
    visit_preorder(visitor, expr)
}

/// Visit an expression tree in pre-order.
pub fn visit_preorder<V: ExprVisitor>(visitor: &mut V, expr: &Expr) -> ControlFlow<V::Break> {
    dispatch_expr(visitor, expr)?;
    walk_expr_children_default(visitor, expr, VisitOrder::Preorder)
}

/// Visit an expression tree in post-order.
pub fn visit_postorder<V: ExprVisitor>(visitor: &mut V, expr: &Expr) -> ControlFlow<V::Break> {
    walk_expr_children_default(visitor, expr, VisitOrder::Postorder)?;
    dispatch_expr(visitor, expr)
}

/// Walk only the children of `expr`, leaving the current node to the caller.
pub fn walk_expr_children_default<V: ExprVisitor>(
    visitor: &mut V,
    expr: &Expr,
    order: VisitOrder,
) -> ControlFlow<V::Break> {
    match expr {
        Expr::LitU32(_)
        | Expr::LitI32(_)
        | Expr::LitF32(_)
        | Expr::LitBool(_)
        | Expr::Var(_)
        | Expr::BufLen { .. }
        | Expr::InvocationId { .. }
        | Expr::WorkgroupId { .. }
        | Expr::LocalId { .. }
        | Expr::SubgroupLocalId
        | Expr::SubgroupSize
        | Expr::Opaque(_) => ControlFlow::Continue(()),
        Expr::Load { index, .. } | Expr::UnOp { operand: index, .. } => {
            visit_with_order(visitor, index, order)
        }
        Expr::BinOp { left, right, .. } => {
            visit_with_order(visitor, left, order)?;
            visit_with_order(visitor, right, order)
        }
        Expr::Call { args, .. } => {
            for arg in args {
                visit_with_order(visitor, arg, order)?;
            }
            ControlFlow::Continue(())
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            visit_with_order(visitor, cond, order)?;
            visit_with_order(visitor, true_val, order)?;
            visit_with_order(visitor, false_val, order)
        }
        Expr::Cast { value, .. }
        | Expr::SubgroupBallot { cond: value }
        | Expr::SubgroupAdd { value } => visit_with_order(visitor, value, order),
        Expr::Fma { a, b, c } => {
            visit_with_order(visitor, a, order)?;
            visit_with_order(visitor, b, order)?;
            visit_with_order(visitor, c, order)
        }
        Expr::Atomic {
            index,
            expected,
            value,
            ..
        } => {
            visit_with_order(visitor, index, order)?;
            if let Some(expected) = expected.as_deref() {
                visit_with_order(visitor, expected, order)?;
            }
            visit_with_order(visitor, value, order)
        }
        Expr::SubgroupShuffle { value, lane } => {
            visit_with_order(visitor, value, order)?;
            visit_with_order(visitor, lane, order)
        }
    }
}

fn visit_with_order<V: ExprVisitor>(
    visitor: &mut V,
    expr: &Expr,
    order: VisitOrder,
) -> ControlFlow<V::Break> {
    match order {
        VisitOrder::Preorder => visit_preorder(visitor, expr),
        VisitOrder::Postorder => visit_postorder(visitor, expr),
    }
}

fn dispatch_expr<V: ExprVisitor>(visitor: &mut V, expr: &Expr) -> ControlFlow<V::Break> {
    match expr {
        Expr::LitU32(value) => visitor.visit_lit_u32(expr, *value),
        Expr::LitI32(value) => visitor.visit_lit_i32(expr, *value),
        Expr::LitF32(value) => visitor.visit_lit_f32(expr, *value),
        Expr::LitBool(value) => visitor.visit_lit_bool(expr, *value),
        Expr::Var(name) => visitor.visit_var(expr, name),
        Expr::Load { buffer, index } => visitor.visit_load(expr, buffer, index),
        Expr::BufLen { buffer } => visitor.visit_buf_len(expr, buffer),
        Expr::InvocationId { axis } => visitor.visit_invocation_id(expr, (*axis).into()),
        Expr::WorkgroupId { axis } => visitor.visit_workgroup_id(expr, (*axis).into()),
        Expr::LocalId { axis } => visitor.visit_local_id(expr, (*axis).into()),
        Expr::BinOp { op, left, right } => visitor.visit_bin_op(expr, op, left, right),
        Expr::UnOp { op, operand } => visitor.visit_un_op(expr, op, operand),
        Expr::Call { op_id, args } => visitor.visit_call(expr, op_id, args),
        Expr::Fma { a, b, c } => visitor.visit_fma(expr, a, b, c),
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => visitor.visit_select(expr, cond, true_val, false_val),
        Expr::Cast { target, value } => visitor.visit_cast(expr, target, value),
        Expr::Atomic {
            op,
            buffer,
            index,
            expected,
            value,
        } => visitor.visit_atomic(expr, op, buffer, index, expected.as_deref(), value),
        Expr::SubgroupBallot { cond } => visitor.visit_subgroup_ballot(expr, cond),
        Expr::SubgroupShuffle { value, lane } => visitor.visit_subgroup_shuffle(expr, value, lane),
        Expr::SubgroupAdd { value } => visitor.visit_subgroup_add(expr, value),
        Expr::SubgroupLocalId => visitor.visit_subgroup_local_id(expr),
        Expr::SubgroupSize => visitor.visit_subgroup_size(expr),
        Expr::Opaque(extension) => visitor.visit_opaque_expr(expr, extension.as_ref()),
    }
}
