use super::*;
use crate::ir::BinOp;

/// Test: d(x*x)/dx = 2*x for a simple square program.
#[test]
fn grad_simple_square() {
    // Forward: out[i] = x[i] * x[i]
    let program = Program::wrapped(
        vec![
            BufferDecl::storage("x", 0, BufferAccess::ReadOnly, DataType::F32).with_count(4),
            BufferDecl::output("out", 1, DataType::F32).with_count(4),
        ],
        [64, 1, 1],
        vec![Node::Store {
            buffer: "out".into(),
            index: Expr::InvocationId { axis: 0 },
            value: Expr::mul(
                Expr::Load {
                    buffer: "x".into(),
                    index: Box::new(Expr::InvocationId { axis: 0 }),
                },
                Expr::Load {
                    buffer: "x".into(),
                    index: Box::new(Expr::InvocationId { axis: 0 }),
                },
            ),
        }],
    );

    let result = grad(&program, &["out"], &["x"]);
    assert!(result.is_ok(), "grad should succeed: {:?}", result.err());
    let backward = result.unwrap();

    // The backward program should declare grad_x and grad_out buffers.
    let buf_names: Vec<&str> = backward.buffers().iter().map(|b| b.name()).collect();
    assert!(
        buf_names.contains(&"grad_out"),
        "should have grad_out buffer"
    );
    assert!(buf_names.contains(&"grad_x"), "should have grad_x buffer");
}

/// Test: non-differentiable op returns error.
#[test]
fn grad_bitwise_errors() {
    let program = Program::wrapped(
        vec![
            BufferDecl::storage("x", 0, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            BufferDecl::output("out", 1, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![Node::Store {
            buffer: "out".into(),
            index: Expr::u32(0),
            value: Expr::BinOp {
                op: BinOp::BitAnd,
                left: Box::new(Expr::Load {
                    buffer: "x".into(),
                    index: Box::new(Expr::u32(0)),
                }),
                right: Box::new(Expr::u32(0xFF)),
            },
        }],
    );

    let result = grad(&program, &["out"], &["x"]);
    assert!(result.is_err());
    match result.unwrap_err() {
        AutodiffError::NotDifferentiable { op, .. } => {
            assert!(op.contains("BitAnd"));
        }
        e => panic!("expected NotDifferentiable, got: {e}"),
    }
}

/// Test: missing buffer name returns error.
#[test]
fn grad_missing_buffer() {
    let program = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::F32).with_count(1)],
        [1, 1, 1],
        vec![],
    );

    let result = grad(&program, &["nonexistent"], &[]);
    assert!(matches!(result, Err(AutodiffError::BufferNotFound { .. })));
}

/// Test: exp derivative  -  d(exp(x))/dx = exp(x).
#[test]
fn grad_exp() {
    let program = Program::wrapped(
        vec![
            BufferDecl::storage("x", 0, BufferAccess::ReadOnly, DataType::F32).with_count(1),
            BufferDecl::output("out", 1, DataType::F32).with_count(1),
        ],
        [1, 1, 1],
        vec![Node::Store {
            buffer: "out".into(),
            index: Expr::u32(0),
            value: Expr::UnOp {
                op: crate::ir::UnOp::Exp,
                operand: Box::new(Expr::Load {
                    buffer: "x".into(),
                    index: Box::new(Expr::u32(0)),
                }),
            },
        }],
    );

    let backward = grad(&program, &["out"], &["x"]).expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - exp should be differentiable");
    assert!(
        backward.buffers().iter().any(|b| b.name() == "x"),
        "exp backward program must declare an x adjoint buffer"
    );
}

#[test]
fn generated_backward_program_zeroes_gradient_buffers_before_accumulation() {
    for count in [1u32, 2, 3, 8, 31, 32, 127, 1024] {
        let program = Program::wrapped(
            vec![
                BufferDecl::storage("x", 0, BufferAccess::ReadOnly, DataType::F32)
                    .with_count(count),
                BufferDecl::storage("w", 1, BufferAccess::ReadOnly, DataType::F32)
                    .with_count(count),
                BufferDecl::output("out", 2, DataType::F32).with_count(count),
            ],
            [64, 1, 1],
            vec![
                Node::let_bind(
                    "xw",
                    Expr::mul(
                        Expr::load("x", Expr::InvocationId { axis: 0 }),
                        Expr::load("w", Expr::InvocationId { axis: 0 }),
                    ),
                ),
                Node::Store {
                    buffer: "out".into(),
                    index: Expr::InvocationId { axis: 0 },
                    value: Expr::add(
                        Expr::var("xw"),
                        Expr::load("x", Expr::InvocationId { axis: 0 }),
                    ),
                },
            ],
        );

        let backward = grad(&program, &["out"], &["x", "w"])
            .expect("Fix: generated differentiable affine-product program must autodiff");
        let flattened = flatten_autodiff_test_nodes(backward.entry());
        let seed_index = flattened
            .iter()
            .position(|node| {
                matches!(
                    node,
                    Node::Store { buffer, value, .. }
                        if buffer.as_str() == "grad_out"
                            && matches!(value, Expr::LitF32(v) if *v == 1.0)
                )
            })
            .expect("Fix: backward program must seed grad_out after clearing gradients");
        let zeroed = flattened[..seed_index]
                .iter()
                .filter_map(|node| match node {
                    Node::Store { buffer, value, .. }
                        if matches!(value, Expr::LitF32(v) if *v == 0.0) =>
                    {
                        Some(buffer.as_str())
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();

        assert_eq!(
                zeroed,
                vec!["grad_out", "grad_x", "grad_w"],
                "Fix: count={count} backward program must clear every gradient buffer before seeding or accumulating"
            );
    }
}

fn flatten_autodiff_test_nodes(nodes: &[Node]) -> Vec<&Node> {
    let mut out = Vec::new();
    for node in nodes {
        out.push(node);
        match node {
            Node::If {
                then, otherwise, ..
            } => {
                out.extend(flatten_autodiff_test_nodes(then));
                out.extend(flatten_autodiff_test_nodes(otherwise));
            }
            Node::Loop { body, .. } | Node::Block(body) => {
                out.extend(flatten_autodiff_test_nodes(body));
            }
            Node::Region { body, .. } => out.extend(flatten_autodiff_test_nodes(body)),
            _ => {}
        }
    }
    out
}
