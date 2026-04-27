use vyre_core::ir::{Expr, Node, Program};
use vyre_core::dialect::{OpDef, OpDefRegistration, DialectRegistry, Category};
use vyre_core::backend::BackendOp;

// Minimal opaque payload example. Production extensions also register an
// OpaqueExprResolver so the payload round-trips as passthrough bytes at
// decode time; consumers that do not link that resolver fail loudly.
pub fn create_opaque_extension() -> Expr {
    Expr::Opaque(42, vec![0x1, 0x2, 0x3])
}

fn main() {
    let expr = create_opaque_extension();
    println!("Successfully built external extension: {expr:?}");
}
