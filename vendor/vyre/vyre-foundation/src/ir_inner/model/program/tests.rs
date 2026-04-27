use super::Program;
use crate::ir::{Expr, Node};
use crate::ir_inner::model::program::BufferDecl;
use crate::ir_inner::model::types::DataType;

fn sample_body() -> Vec<Node> {
    vec![
        Node::let_bind("value", Expr::u32(7)),
        Node::store("out", Expr::u32(0), Expr::var("value")),
        Node::Return,
    ]
}

#[test]
fn partial_eq_ignores_buffer_declaration_order() {
    let left = Program::wrapped(
        vec![
            BufferDecl::output("out", 0, DataType::U32).with_count(1),
            BufferDecl::read("input", 1, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        sample_body(),
    );
    let right = Program::wrapped(
        vec![
            BufferDecl::read("input", 1, DataType::U32).with_count(1),
            BufferDecl::output("out", 0, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        sample_body(),
    );

    assert_eq!(
        left, right,
        "Fix: Program equality must ignore buffer declaration order."
    );
    assert!(
        left.structural_eq(&right),
        "Fix: structural_eq must agree with PartialEq on reordered buffers."
    );
}

#[test]
fn structural_eq_rejects_semantic_entry_differences() {
    let left = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(7)), Node::Return],
    );
    let right = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(9)), Node::Return],
    );

    assert!(
        !left.structural_eq(&right),
        "Fix: structural_eq must reject programs whose observable writes differ."
    );
}
