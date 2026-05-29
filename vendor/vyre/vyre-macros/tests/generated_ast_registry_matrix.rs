#![allow(missing_docs)]

mod support;

pub use support::ir_inner;

use vyre_macros::vyre_ast_registry;

vyre_ast_registry! {
    GeneratedExpr {
        Const,
        Unary(u32),
        Pair(u32, u32),
        Binary { left: u32, right: u32 },
        Select { cond: u32, then_expr: u32, else_expr: u32 },
    }

    GeneratedNode {
        Return,
        Barrier,
        Store(u32, u32),
        Branch { cond: u32, then_node: u32, else_node: u32 },
    }

    GeneratedType {
        U32,
        F32,
        Ptr(u32),
        Tensor { element: u32, rank: u32 },
    }
}

fn expr_cases() -> Vec<(GeneratedExpr, &'static str)> {
    vec![
        (GeneratedExpr::Const, "vyre.generatedexpr.const"),
        (GeneratedExpr::Unary(7), "vyre.generatedexpr.unary"),
        (GeneratedExpr::Pair(3, 5), "vyre.generatedexpr.pair"),
        (
            GeneratedExpr::Binary { left: 11, right: 13 },
            "vyre.generatedexpr.binary",
        ),
        (
            GeneratedExpr::Select {
                cond: 1,
                then_expr: 21,
                else_expr: 34,
            },
            "vyre.generatedexpr.select",
        ),
    ]
}

fn node_cases() -> Vec<(GeneratedNode, &'static str)> {
    vec![
        (GeneratedNode::Return, "vyre.generatednode.return"),
        (GeneratedNode::Barrier, "vyre.generatednode.barrier"),
        (GeneratedNode::Store(8, 9), "vyre.generatednode.store"),
        (
            GeneratedNode::Branch {
                cond: 1,
                then_node: 2,
                else_node: 3,
            },
            "vyre.generatednode.branch",
        ),
    ]
}

fn type_cases() -> Vec<(GeneratedType, &'static str)> {
    vec![
        (GeneratedType::U32, "vyre.generatedtype.u32"),
        (GeneratedType::F32, "vyre.generatedtype.f32"),
        (GeneratedType::Ptr(4), "vyre.generatedtype.ptr"),
        (
            GeneratedType::Tensor {
                element: 32,
                rank: 4,
            },
            "vyre.generatedtype.tensor",
        ),
    ]
}

fn variant_hash(name: &str) -> u32 {
    name.bytes()
        .fold(0u32, |acc, byte| acc.wrapping_add(u32::from(byte)))
}

fn decoder_hashes(node: &ir_inner::model::node::Node, out: &mut Vec<u32>) {
    match node {
        ir_inner::model::node::Node::If {
            cond, otherwise, ..
        } => {
            if let ir_inner::model::expr::Expr::BinOp { right, .. } = cond {
                if let ir_inner::model::expr::Expr::LitU32(hash) = right.as_ref() {
                    out.push(*hash);
                }
            }
            for child in otherwise {
                decoder_hashes(child, out);
            }
        }
        ir_inner::model::node::Node::Barrier | ir_inner::model::node::Node::Return => {}
    }
}

fn sorted_decoder_hashes(node: &ir_inner::model::node::Node) -> Vec<u32> {
    let mut hashes = Vec::new();
    decoder_hashes(node, &mut hashes);
    hashes.sort();
    hashes
}

#[test]
fn generated_ast_registry_matrix_pins_op_ids_and_partial_eq() {
    let expr = expr_cases();
    let node = node_cases();
    let ty = type_cases();
    let mut assertions = 0usize;

    for seed in 0usize..4096 {
        let expr_case = &expr[seed % expr.len()];
        let node_case = &node[(seed / 3) % node.len()];
        let type_case = &ty[(seed / 5) % ty.len()];

        assert_eq!(generatedexpr_op_id(&expr_case.0), expr_case.1);
        assert_eq!(generatednode_op_id(&node_case.0), node_case.1);
        assert_eq!(generatedtype_op_id(&type_case.0), type_case.1);
        assert_eq!(expr_case.0, expr_case.0.clone());
        assert_eq!(node_case.0, node_case.0.clone());
        assert_eq!(type_case.0, type_case.0.clone());
        assertions += 6;
    }

    assert_ne!(GeneratedExpr::Unary(1), GeneratedExpr::Unary(2));
    assert_ne!(GeneratedExpr::Pair(1, 2), GeneratedExpr::Pair(2, 1));
    assert_ne!(
        GeneratedExpr::Binary { left: 1, right: 2 },
        GeneratedExpr::Binary { left: 2, right: 1 }
    );
    assert_ne!(GeneratedNode::Store(1, 2), GeneratedNode::Store(2, 1));
    assert_ne!(
        GeneratedNode::Branch {
            cond: 1,
            then_node: 2,
            else_node: 3,
        },
        GeneratedNode::Branch {
            cond: 1,
            then_node: 3,
            else_node: 2,
        }
    );
    assert_ne!(GeneratedType::Ptr(1), GeneratedType::Ptr(2));
    assert_ne!(
        GeneratedType::Tensor {
            element: 32,
            rank: 4,
        },
        GeneratedType::Tensor {
            element: 32,
            rank: 8,
        }
    );

    assert_eq!(assertions, 4096 * 6);
}

#[test]
fn generated_ast_registry_decoders_cover_every_variant_hash() {
    let mut expected_expr = ["Const", "Unary", "Pair", "Binary", "Select"]
        .into_iter()
        .map(variant_hash)
        .collect::<Vec<_>>();
    let mut expected_node = ["Return", "Barrier", "Store", "Branch"]
        .into_iter()
        .map(variant_hash)
        .collect::<Vec<_>>();
    let mut expected_type = ["U32", "F32", "Ptr", "Tensor"]
        .into_iter()
        .map(variant_hash)
        .collect::<Vec<_>>();
    expected_expr.sort();
    expected_node.sort();
    expected_type.sort();

    assert_eq!(
        sorted_decoder_hashes(&generate_generatedexpr_gpu_vm_decoder()),
        expected_expr
    );
    assert_eq!(
        sorted_decoder_hashes(&generate_generatednode_gpu_vm_decoder()),
        expected_node
    );
    assert_eq!(
        sorted_decoder_hashes(&generate_generatedtype_gpu_vm_decoder()),
        expected_type
    );
}
