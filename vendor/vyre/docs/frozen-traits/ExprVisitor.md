pub trait ExprVisitor {
/// Result type returned from each variant.
type Output;
/// Integer literal (`u32`).
///
/// # Errors
///
/// Returns an unsupported error by default; override to handle this variant.
fn visit_lit_u32(&mut self, _value: u32) -> Result<Self::Output, crate::error::Error> {
Err(crate::error::Error::lowering(
"Fix: implement ExprVisitor::visit_lit_u32 to handle u32 literal expressions.",
))
}
/// Integer literal (`i32`).
///
/// # Errors
///
/// Returns an unsupported error by default; override to handle this variant.
fn visit_lit_i32(&mut self, _value: i32) -> Result<Self::Output, crate::error::Error> {
Err(crate::error::Error::lowering(
"Fix: implement ExprVisitor::visit_lit_i32 to handle i32 literal expressions.",
))
}
/// Float literal (`f32`).
///
/// # Errors
///
/// Returns an unsupported error by default; override to handle this variant.
fn visit_lit_f32(&mut self, _value: f32) -> Result<Self::Output, crate::error::Error> {
Err(crate::error::Error::lowering(
"Fix: implement ExprVisitor::visit_lit_f32 to handle f32 literal expressions.",
))
}
/// Bool literal.
///
/// # Errors
///
/// Returns an unsupported error by default; override to handle this variant.
fn visit_lit_bool(&mut self, _value: bool) -> Result<Self::Output, crate::error::Error> {
Err(crate::error::Error::lowering(
"Fix: implement ExprVisitor::visit_lit_bool to handle bool literal expressions.",
))
}
/// Variable reference.
///
/// # Errors
///
/// Returns an unsupported error by default; override to handle this variant.
fn visit_var(&mut self, _name: &Ident) -> Result<Self::Output, crate::error::Error> {
Err(crate::error::Error::lowering(
"Fix: implement ExprVisitor::visit_var to handle variable reference expressions.",
))
}
/// Buffer load (`buffer[index]`).
///
/// # Errors
///
/// Returns an unsupported error by default; override to handle this variant.
fn visit_load(&mut self, _buffer: &Ident, _index: &Expr) -> Result<Self::Output, crate::error::Error> {
Err(crate::error::Error::lowering(
"Fix: implement ExprVisitor::visit_load to handle buffer load expressions.",
))
}
/// Buffer length.
///
/// # Errors
///
/// Returns an unsupported error by default; override to handle this variant.
fn visit_buf_len(&mut self, _buffer: &Ident) -> Result<Self::Output, crate::error::Error> {
Err(crate::error::Error::lowering(
"Fix: implement ExprVisitor::visit_buf_len to handle buffer length expressions.",
))
}
/// Invocation id axis (`gid.{x,y,z}`).
///
/// # Errors
///
/// Returns an unsupported error by default; override to handle this variant.
fn visit_invocation_id(&mut self, _axis: u8) -> Result<Self::Output, crate::error::Error> {
Err(crate::error::Error::lowering(
"Fix: implement ExprVisitor::visit_invocation_id to handle invocation-id expressions.",
))
}
/// Workgroup id axis.
///
/// # Errors
///
/// Returns an unsupported error by default; override to handle this variant.
fn visit_workgroup_id(&mut self, _axis: u8) -> Result<Self::Output, crate::error::Error> {
Err(crate::error::Error::lowering(
"Fix: implement ExprVisitor::visit_workgroup_id to handle workgroup-id expressions.",
))
}
/// Local id axis within the workgroup.
///
/// # Errors
///
/// Returns an unsupported error by default; override to handle this variant.
fn visit_local_id(&mut self, _axis: u8) -> Result<Self::Output, crate::error::Error> {
Err(crate::error::Error::lowering(
"Fix: implement ExprVisitor::visit_local_id to handle local-id expressions.",
))
}
/// Binary operation.
///
/// # Errors
///
/// Returns an unsupported error by default; override to handle this variant.
fn visit_bin_op(&mut self, _op: &BinOp, _left: &Expr, _right: &Expr) -> Result<Self::Output, crate::error::Error> {
Err(crate::error::Error::lowering(
"Fix: implement ExprVisitor::visit_bin_op to handle binary operation expressions.",
))
}
/// Unary operation.
///
/// # Errors
///
/// Returns an unsupported error by default; override to handle this variant.
fn visit_un_op(&mut self, _op: &UnOp, _operand: &Expr) -> Result<Self::Output, crate::error::Error> {
Err(crate::error::Error::lowering(
"Fix: implement ExprVisitor::visit_un_op to handle unary operation expressions.",
))
}
/// Function call.
///
/// # Errors
///
/// Returns an unsupported error by default; override to handle this variant.
fn visit_call(&mut self, _op_id: &str, _args: &[Expr]) -> Result<Self::Output, crate::error::Error> {
Err(crate::error::Error::lowering(
"Fix: implement ExprVisitor::visit_call to handle function call expressions.",
))
}
/// Fused multiply-add (`a * b + c`).
///
/// # Errors
///
/// Returns an unsupported error by default; override to handle this variant.
fn visit_fma(&mut self, _a: &Expr, _b: &Expr, _c: &Expr) -> Result<Self::Output, crate::error::Error> {
Err(crate::error::Error::lowering(
"Fix: implement ExprVisitor::visit_fma to handle fused multiply-add expressions.",
))
}
/// Ternary `select(cond, true_val, false_val)`.
///
/// # Errors
///
/// Returns an unsupported error by default; override to handle this variant.
fn visit_select(
&mut self,
_cond: &Expr,
_true_val: &Expr,
_false_val: &Expr,
) -> Result<Self::Output, crate::error::Error> {
Err(crate::error::Error::lowering(
"Fix: implement ExprVisitor::visit_select to handle select (ternary) expressions.",
))
}
/// Numeric cast.
///
/// # Errors
///
/// Returns an unsupported error by default; override to handle this variant.
fn visit_cast(&mut self, _target: &DataType, _value: &Expr) -> Result<Self::Output, crate::error::Error> {
Err(crate::error::Error::lowering(
"Fix: implement ExprVisitor::visit_cast to handle numeric cast expressions.",
))
}
/// Atomic operation on a shared buffer.
///
/// # Errors
///
/// Returns an unsupported error by default; override to handle this variant.
fn visit_atomic(
&mut self,
_op: &AtomicOp,
_buffer: &Ident,
_index: &Expr,
_expected: Option<&Expr>,
_value: &Expr,
) -> Result<Self::Output, crate::error::Error> {
Err(crate::error::Error::lowering(
"Fix: implement ExprVisitor::visit_atomic to handle atomic operation expressions.",
))
}
/// Hook for unrecognised variants introduced by extension crates.
///
/// The blanket adapter on `Expr` routes any variant not handled by a
/// dedicated method through this function. Default returns
/// [`VisitorError::Unsupported`]; specialized visitors can override
/// to accept external variants.
///
/// # Errors
///
/// Returns [`VisitorError::Unsupported`] by default, wrapped in the
/// crate's [`crate::error::Error`] type.
fn visit_unknown_expr(&mut self, _marker: &str) -> Result<Self::Output, crate::error::Error> {
Err(crate::error::Error::lowering(
"Fix: the visitor encountered an IR expression variant it does not handle. Implement ExprVisitor::visit_unknown_expr on the visitor, or narrow the IR input before visiting.".to_string(),
))
}
/// Downstream opaque expression extension.
///
/// # Errors
///
/// Returns an unsupported error by default; override to handle the extension.
fn visit_opaque_expr(&mut self, extension: &dyn ExprNode) -> Result<Self::Output, crate::error::Error> {
let _ = extension;
self.visit_unknown_expr("opaque")
}
}
