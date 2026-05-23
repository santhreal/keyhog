//! MuonEq-R: Row-normalized Muon optimizer (F32).
//!
//! Muon + `scale = max(1, rows/cols)^0.5` row normalization.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::region::wrap_anonymous;

const OP_ID: &str = "vyre-libs::optim::muoneq_r";

fn flush_tiny(value: Expr) -> Expr {
    Expr::select(
        Expr::le(Expr::abs(value.clone()), Expr::f32(f32::MIN_POSITIVE)),
        Expr::f32(0.0),
        value,
    )
}

/// MuonEq-R step (F32).
///
/// Same as `muon_update` but with row-norm scaling baked in.
#[must_use]
pub fn muoneq_r(
    params: &str,
    grads: &str,
    momentum_buf: &str,
    output: &str,
    n: u32,
    rows: u32,
    cols: u32,
    lr: f32,
    momentum: f32,
) -> Program {
    // scale = max(1, rows/cols)^0.5
    let ratio = (rows as f32) / (cols as f32);
    let scale = ratio.max(1.0).sqrt();

    let i = Expr::var("i");
    let g = flush_tiny(Expr::load(grads, i.clone()));
    let m = flush_tiny(Expr::load(momentum_buf, i.clone()));
    let p = flush_tiny(Expr::load(params, i.clone()));

    let new_m = Expr::add(Expr::mul(Expr::f32(momentum), m), g.clone());
    let nesterov = Expr::add(g, Expr::mul(Expr::f32(momentum), new_m.clone()));
    let scaled_update = Expr::mul(Expr::f32(scale * lr), nesterov);
    let new_p = Expr::sub(p, scaled_update);

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
        build: || muoneq_r("params", "grads", "momentum", "output", 4, 4, 2, 0.02, 0.95),
        test_inputs: Some(|| {
            let to_f32 = |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_f32(&[1.0, 2.0, 3.0, 4.0]),
                to_f32(&[0.1, 0.2, 0.3, 0.4]),
                to_f32(&[0.0, 0.0, 0.0, 0.0]),
            ]]
        }),
        expected_output: Some(|| {
            vec![vec![
                vec![
                    205, 204, 204, 61, 205, 204, 76, 62, 154, 153, 153, 62, 205, 204, 204, 62,
                ],
                vec![
                    64, 239, 125, 63, 64, 239, 253, 63, 112, 115, 62, 64, 64, 239, 125, 64,
                ],
            ]]
        }),
        category: Some("nn"),
    }
}
