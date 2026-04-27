use vyre_core::ir::visit::ExprVisitor;
use vyre_core::ir::model::expr::{Expr, Ident};

struct ChildVisitor<'a> {
    current: &'a Expr,
    children: Vec<&'a Expr>,
}

impl<'a> ExprVisitor for ChildVisitor<'a> {
    type Output = ();

    fn visit_load(&mut self, _buffer: &Ident, _index: &Expr) -> Result<Self::Output, vyre_core::error::Error> {
        if let Expr::Load { index, .. } = self.current {
            self.children.push(index);
        }
        Ok(())
    }
    // ...
}
