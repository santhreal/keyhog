//! Adversarial tests for validator depth-limit enforcement.
//!
//! The validator must reject programs that exceed the configured
//! maximum call depth, expression depth, nesting depth, or node count.
//! These limits prevent pathological inputs from causing stack
//! overflow or unbounded computation during optimization.

use vyre::ir::{BufferDecl, DataType, Expr, Node, Program};
use vyre::validate;

fn output_buf() -> BufferDecl {
    BufferDecl::output("out", 0, DataType::U32).with_count(1)
}

#[test]
fn deeply_nested_if_exceeds_nesting_limit() {
    // Build a program with 100 nested If nodes.
    let mut body = vec![Node::Return];
    for _ in 0..100 {
        body = vec![Node::if_then(Expr::bool(true), body)];
    }
    let program = Program::wrapped(vec![output_buf()], [1, 1, 1], body);

    let errors = validate(&program);
    assert!(
        !errors.is_empty(),
        "deeply nested If (100 levels) must exceed nesting limit, got no errors"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.message().contains("depth") || e.message().contains("limit")),
        "depth-limit error must mention 'depth' or 'limit', got: {:?}",
        errors
    );
}

#[test]
fn deeply_nested_loop_exceeds_nesting_limit() {
    // Build a program with 100 nested Loop nodes.
    let mut body = vec![Node::Return];
    for _ in 0..100 {
        body = vec![Node::loop_for("i", Expr::u32(0), Expr::u32(1), body)];
    }
    let program = Program::wrapped(vec![output_buf()], [1, 1, 1], body);

    let errors = validate(&program);
    assert!(
        errors
            .iter()
            .any(|e| e.message().contains("depth") || e.message().contains("limit")),
        "deeply nested Loop (100 levels) must exceed nesting limit, got: {:?}",
        errors
    );
}

#[test]
fn huge_node_count_exceeds_limit() {
    // Build a program with 10,000 sequential Let nodes.
    let mut body = Vec::new();
    for i in 0..10_000 {
        body.push(Node::let_bind(format!("v{i}"), Expr::u32(i as u32)));
    }
    body.push(Node::Return);
    let program = Program::wrapped(vec![output_buf()], [1, 1, 1], body);

    let errors = validate(&program);
    assert!(
        !errors.is_empty(),
        "program with 10,000 nodes must exceed node-count limit, got no errors"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.message().contains("count") || e.message().contains("limit")),
        "node-count error must mention 'count' or 'limit', got: {:?}",
        errors
    );
}

#[test]
fn deep_expr_tree_exceeds_expr_depth_limit() {
    // Build an expression with 200 nested Add operations.
    let mut expr = Expr::u32(0);
    for _ in 0..200 {
        expr = Expr::add(expr, Expr::u32(1));
    }
    let program = Program::wrapped(
        vec![output_buf()],
        [1, 1, 1],
        vec![Node::let_bind("deep", expr), Node::Return],
    );

    let errors = validate(&program);
    assert!(
        !errors.is_empty(),
        "expression with depth 200 must exceed expr-depth limit, got no errors"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.message().contains("expr") || e.message().contains("depth")),
        "expr-depth error must mention 'expr' or 'depth', got: {:?}",
        errors
    );
}
