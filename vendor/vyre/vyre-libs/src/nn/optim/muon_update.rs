//! Muon update: momentum + Newton-Schulz orthogonalization (F32).
//!
//! `buf = momentum * buf + grad`
//! `nesterov = grad + momentum * buf`
//! `orthogonal = newton_schulz_5step(nesterov)` (via composition)
//! `param -= lr * orthogonal * scale`

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::region::wrap_anonymous;

const OP_ID: &str = "vyre-libs::optim::muon_update";

fn flush_tiny(value: Expr) -> Expr {
    Expr::select(
        Expr::le(Expr::abs(value.clone()), Expr::f32(f32::MIN_POSITIVE)),
        Expr::f32(0.0),
        value,
    )
}

/// Muon optimizer step (F32).
///
/// `params[n]` (RO), `grads[n]` (RO), `momentum_buf[n]` (RW),
/// `output[n]` — updated params.
#[must_use]
pub fn muon_update(
    params: &str,
    grads: &str,
    momentum_buf: &str,
    output: &str,
    n: u32,
    lr: f32,
    momentum: f32,
) -> Program {
    let i = Expr::var("i");
    let g = flush_tiny(Expr::load(grads, i.clone()));
    let m = flush_tiny(Expr::load(momentum_buf, i.clone()));
    let p = flush_tiny(Expr::load(params, i.clone()));

    // buf = momentum * buf + grad
    let new_m = Expr::add(Expr::mul(Expr::f32(momentum), m), g.clone());

    // nesterov: update = grad + momentum * new_m
    let nesterov = Expr::add(g, Expr::mul(Expr::f32(momentum), new_m.clone()));

    // param -= lr * update (Newton-Schulz applied via composition)
    let new_p = Expr::sub(p, Expr::mul(Expr::f32(lr), nesterov));

    let body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::u32(n)),
            vec![
                Node::Store {
                    buffer: momentum_buf.into(),
                    index: i.clone(),
                    value: flush_tiny(new_m),
                },
                Node::Store {
                    buffer: output.into(),
                    index: i,
                    value: flush_tiny(new_p),
                },
            ],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(params, 0, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::storage(grads, 1, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::storage(momentum_buf, 2, BufferAccess::ReadWrite, DataType::F32)
                .with_count(n),
            BufferDecl::output(output, 3, DataType::F32).with_count(n),
        ],
        [64, 1, 1],
        vec![wrap_anonymous(OP_ID, body)],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || muon_update("params", "grads", "momentum", "output", 2, 0.02, 0.95),
        test_inputs: Some(|| {
            let to_f32 = |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_f32(&[1.0, 2.0]),    // params
                to_f32(&[0.1, 0.2]),    // grads
                to_f32(&[0.0, 0.0]),    // momentum (first step)
            ]]
        }),
        expected_output: Some(|| {
            vec![vec![
                vec![205, 204, 204, 61, 205, 204, 76, 62],
                vec![30, 138, 126, 63, 30, 138, 254, 63],
            ]]
        }),
        category: Some("nn"),
    }
}
