//! Coverage for the new Sub/BitAnd/BitOr/BitXor identity rules in
//! the GPU pattern-match pass. Each test runs a Program through the
//! full persistent-resident pipeline and asserts the post-pipeline IR
//! has the expected collapsed form.

#![cfg(test)]

mod common;

use common::live_backend;
use vyre::ir::{BinOp, BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre_driver_cuda::CudaOptimizerDispatcher;
use vyre_self_substrate::optimizer::pipeline_resident::gpu_pipeline_resident;

/// Bind `x` to a non-literal value (`Load(input, 0)`) so const-prop
/// at the end of the pipeline can't fold `Var(x)` into a literal.
/// The `input` buffer is declared on the Program so the IR is
/// well-typed.
fn program_with_x_load_then(value: Expr) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::storage("input", 0, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            BufferDecl::storage("buf", 1, BufferAccess::ReadWrite, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![
            Node::let_bind("x", Expr::load("input", Expr::u32(0))),
            Node::store("buf", Expr::u32(0), value),
        ],
    )
}

fn run_pipeline(p: Program) -> Program {
    let backend = live_backend();
    let dispatcher = CudaOptimizerDispatcher::new(&backend);
    gpu_pipeline_resident(p, &dispatcher).expect("pipeline must succeed")
}

fn body_of(out: &Program) -> Vec<Node> {
    match out.entry() {
        [Node::Region { body, .. }] => body.as_ref().clone(),
        entry => entry.to_vec(),
    }
}

#[test]
fn cuda_sub_zero_collapses_to_left() {
    // store buf 0 (var("x") - 0)  →  store buf 0 var("x")
    let p = program_with_x_load_then(Expr::sub(Expr::var("x"), Expr::u32(0)));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::Var(n) if n.as_str() == "x"),
            "expected Var(x) after Sub-zero collapse; got {value:?}"
        );
    }
}

#[test]
fn cuda_bitand_zero_collapses_to_zero() {
    // store buf 0 (var("x") & 0)  →  store buf 0 0
    let p = program_with_x_load_then(Expr::bitand(Expr::var("x"), Expr::u32(0)));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::LitU32(0)),
            "expected LitU32(0) after BitAnd-zero collapse; got {value:?}"
        );
    }
}

#[test]
fn cuda_bitor_zero_collapses_to_left() {
    // store buf 0 (var("x") | 0)  →  store buf 0 var("x")
    let p = program_with_x_load_then(Expr::bitor(Expr::var("x"), Expr::u32(0)));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::Var(n) if n.as_str() == "x"),
            "expected Var(x) after BitOr-zero collapse; got {value:?}"
        );
    }
}

#[test]
fn cuda_sub_add_cancel_left_via_cse() {
    // store buf 0 ((Var(x) + Var(y)) - Var(x))  →  store buf 0 Var(y)
    // Both x and y are bound to non-literal Loads so they survive
    // const-prop and remain Var refs.
    let p = Program::wrapped(
        vec![
            BufferDecl::storage("inx", 0, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            BufferDecl::storage("iny", 1, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            BufferDecl::storage("buf", 2, BufferAccess::ReadWrite, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![
            Node::let_bind("x", Expr::load("inx", Expr::u32(0))),
            Node::let_bind("y", Expr::load("iny", Expr::u32(0))),
            Node::store(
                "buf",
                Expr::u32(0),
                Expr::sub(Expr::add(Expr::var("x"), Expr::var("y")), Expr::var("x")),
            ),
        ],
    );
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::Var(n) if n.as_str() == "y"),
            "expected Var(y) after `(x+y)-x` collapse; got {value:?}"
        );
    }
}

#[test]
fn cuda_sub_add_cancel_right_via_cse() {
    // store buf 0 ((Var(x) + Var(y)) - Var(y))  →  store buf 0 Var(x)
    let p = Program::wrapped(
        vec![
            BufferDecl::storage("inx", 0, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            BufferDecl::storage("iny", 1, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            BufferDecl::storage("buf", 2, BufferAccess::ReadWrite, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![
            Node::let_bind("x", Expr::load("inx", Expr::u32(0))),
            Node::let_bind("y", Expr::load("iny", Expr::u32(0))),
            Node::store(
                "buf",
                Expr::u32(0),
                Expr::sub(Expr::add(Expr::var("x"), Expr::var("y")), Expr::var("y")),
            ),
        ],
    );
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::Var(n) if n.as_str() == "x"),
            "expected Var(x) after `(x+y)-y` collapse; got {value:?}"
        );
    }
}

#[test]
fn cuda_add_sub_cancel_via_cse() {
    // store buf 0 ((Var(x) - Var(y)) + Var(y))  →  store buf 0 Var(x)
    let p = Program::wrapped(
        vec![
            BufferDecl::storage("inx", 0, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            BufferDecl::storage("iny", 1, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            BufferDecl::storage("buf", 2, BufferAccess::ReadWrite, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![
            Node::let_bind("x", Expr::load("inx", Expr::u32(0))),
            Node::let_bind("y", Expr::load("iny", Expr::u32(0))),
            Node::store(
                "buf",
                Expr::u32(0),
                Expr::add(Expr::sub(Expr::var("x"), Expr::var("y")), Expr::var("y")),
            ),
        ],
    );
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::Var(n) if n.as_str() == "x"),
            "expected Var(x) after `(x-y)+y` collapse; got {value:?}"
        );
    }
}

#[test]
fn cuda_div_by_one_collapses_to_left() {
    // store buf 0 (var("x") / 1) → store buf 0 var("x")
    let p = program_with_x_load_then(Expr::div(Expr::var("x"), Expr::u32(1)));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::Var(n) if n.as_str() == "x"),
            "expected Var(x) after Div-by-1 collapse; got {value:?}"
        );
    }
}

#[test]
fn cuda_mod_by_one_collapses_to_zero() {
    // store buf 0 (var("x") % 1) → store buf 0 0
    let p = program_with_x_load_then(Expr::rem(Expr::var("x"), Expr::u32(1)));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::LitU32(0)),
            "expected LitU32(0) after Mod-by-1 collapse; got {value:?}"
        );
    }
}

#[test]
fn cuda_double_abs_does_not_collapse_to_inner() {
    // Abs is idempotent (Abs(Abs(x)) == Abs(x)), NOT involutive
    // (Abs(Abs(x)) ≠ x in general). Adversarial test: catches a
    // previous bug where the UnOp double-application matcher fired
    // for any same-op pair, incorrectly collapsing Abs(Abs(x)) → x.
    use vyre::ir::model::types::UnOp;
    let p = program_with_x_load_then(Expr::UnOp {
        op: UnOp::Abs,
        operand: Box::new(Expr::UnOp {
            op: UnOp::Abs,
            operand: Box::new(Expr::var("x")),
        }),
    });
    let out = run_pipeline(p);
    let body = body_of(&out);
    if let Some(Node::Store { value, .. }) = body.iter().find(|n| matches!(n, Node::Store { .. })) {
        // Either the outer Abs is preserved (correct shape) OR it
        // collapsed to the inner Abs (also correct since Abs is
        // idempotent). Either way, the result must NOT be raw Var(x).
        assert!(
            !matches!(value, Expr::Var(n) if n.as_str() == "x"),
            "Abs(Abs(x)) must not collapse to Var(x); got {value:?}"
        );
    }
}

#[test]
fn cuda_double_bitnot_collapses() {
    // store buf 0 (~~ var("x"))  →  store buf 0 var("x")
    use vyre::ir::UnOp;
    let p = program_with_x_load_then(Expr::UnOp {
        op: UnOp::BitNot,
        operand: Box::new(Expr::UnOp {
            op: UnOp::BitNot,
            operand: Box::new(Expr::var("x")),
        }),
    });
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::Var(n) if n.as_str() == "x"),
            "expected Var(x) after `~~x` collapse; got {value:?}"
        );
    }
}

#[test]
fn cuda_bitand_max_collapses_to_left() {
    // store buf 0 (var("x") & u32::MAX)  →  store buf 0 var("x")
    let p = program_with_x_load_then(Expr::bitand(Expr::var("x"), Expr::u32(u32::MAX)));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::Var(n) if n.as_str() == "x"),
            "expected Var(x) after BitAnd-MAX collapse; got {value:?}"
        );
    }
}

#[test]
fn cuda_shl_zero_collapses_to_left() {
    // store buf 0 (var("x") << 0)  →  store buf 0 var("x")
    let p = program_with_x_load_then(Expr::shl(Expr::var("x"), Expr::u32(0)));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::Var(n) if n.as_str() == "x"),
            "expected Var(x) after Shl-by-zero collapse; got {value:?}"
        );
    }
}

#[test]
fn cuda_shr_zero_collapses_to_left() {
    // store buf 0 (var("x") >> 0)  →  store buf 0 var("x")
    let p = program_with_x_load_then(Expr::shr(Expr::var("x"), Expr::u32(0)));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::Var(n) if n.as_str() == "x"),
            "expected Var(x) after Shr-by-zero collapse; got {value:?}"
        );
    }
}

#[test]
fn cuda_zero_shl_collapses_to_zero() {
    // store buf 0 (0u32 << var("x"))  →  store buf 0 0
    let p = program_with_x_load_then(Expr::shl(Expr::u32(0), Expr::var("x")));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::LitU32(0)),
            "expected LitU32(0) after `0 << x` collapse; got {value:?}"
        );
    }
}

#[test]
fn cuda_eq_self_collapses_to_true_via_cse() {
    // store buf 0 (var("x") == var("x"))  →  store buf 0 LitBool(true)
    let p = program_with_x_load_then(Expr::eq(Expr::var("x"), Expr::var("x")));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::LitBool(true)),
            "expected LitBool(true) after `x == x` collapse via CSE; got {value:?}"
        );
    }
}

#[test]
fn cuda_bool_and_self_collapses_via_cse() {
    // (b && b) → b. Both operands are Var(b), CSE proves equality.
    // Use the cond inside an If to drive a Store decision.
    let p = Program::wrapped(
        vec![
            BufferDecl::storage("input", 0, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            BufferDecl::storage("buf", 1, BufferAccess::ReadWrite, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![
            Node::let_bind(
                "b",
                Expr::eq(Expr::load("input", Expr::u32(0)), Expr::u32(7)),
            ),
            Node::if_then_else(
                binop(BinOp::And, Expr::var("b"), Expr::var("b")),
                vec![Node::store("buf", Expr::u32(0), Expr::u32(1))],
                vec![Node::store("buf", Expr::u32(0), Expr::u32(2))],
            ),
        ],
    );
    let out = run_pipeline(p);
    let body = body_of(&out);
    // The (b && b) → b rewrite produces an If whose cond is Var(b)
    // (post-rewrite)  -  the cond no longer has BinOp::And at the top.
    let if_node = body.iter().find(|n| matches!(n, Node::If { .. }));
    if let Some(Node::If { cond, .. }) = if_node {
        assert!(
            !matches!(cond, Expr::BinOp { op: BinOp::And, .. }),
            "(b && b) must collapse; got cond={cond:?}"
        );
    }
}

#[test]
fn cuda_bool_and_with_false_collapses_to_false() {
    // (Var(b) && false) → false. The store's value is non-bool so
    // we put the test under an If cond.
    let p = Program::wrapped(
        vec![
            BufferDecl::storage("input", 0, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            BufferDecl::storage("buf", 1, BufferAccess::ReadWrite, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![
            Node::let_bind(
                "b",
                Expr::eq(Expr::load("input", Expr::u32(0)), Expr::u32(7)),
            ),
            Node::if_then_else(
                binop(BinOp::And, Expr::var("b"), Expr::bool(false)),
                vec![Node::store("buf", Expr::u32(0), Expr::u32(1))],
                vec![Node::store("buf", Expr::u32(0), Expr::u32(99))],
            ),
        ],
    );
    let out = run_pipeline(p);
    let body = body_of(&out);
    assert!(
        body.iter().all(|n| !matches!(n, Node::If { .. })),
        "(b && false) must fold to false and drop the If; body={body:?}"
    );
    if let Some(Node::Store { value, .. }) = body.iter().find(|n| matches!(n, Node::Store { .. })) {
        assert!(
            matches!(value, Expr::LitU32(99)),
            "(b && false) → false should pick else; got {value:?}"
        );
    }
}

#[test]

fn cuda_bool_or_with_true_collapses_to_true() {
    // (Var(b) || true) → true. Pick the then arm.
    let p = Program::wrapped(
        vec![
            BufferDecl::storage("input", 0, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            BufferDecl::storage("buf", 1, BufferAccess::ReadWrite, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![
            Node::let_bind(
                "b",
                Expr::eq(Expr::load("input", Expr::u32(0)), Expr::u32(7)),
            ),
            Node::if_then_else(
                binop(BinOp::Or, Expr::var("b"), Expr::bool(true)),
                vec![Node::store("buf", Expr::u32(0), Expr::u32(1))],
                vec![Node::store("buf", Expr::u32(0), Expr::u32(99))],
            ),
        ],
    );
    let out = run_pipeline(p);
    let body = body_of(&out);
    assert!(
        body.iter().all(|n| !matches!(n, Node::If { .. })),
        "(b || true) must fold to true and drop the If; body={body:?}"
    );
    if let Some(Node::Store { value, .. }) = body.iter().find(|n| matches!(n, Node::Store { .. })) {
        assert!(
            matches!(value, Expr::LitU32(1)),
            "(b || true) → true should pick then; got {value:?}"
        );
    }
}

#[test]
fn cuda_gt_self_collapses_to_false_via_cse() {
    // (var("x") > var("x")) → LitBool(false). Adversarial: catches
    // the previous miswiring where `is_cmp_gt` was bound to the
    // wrong op tag, which would've collapsed `Gt(x,x)` to `true`.
    let p = program_with_x_load_then(binop(BinOp::Gt, Expr::var("x"), Expr::var("x")));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::LitBool(false)),
            "Gt(x,x) must fold to false; got {value:?}"
        );
    }
}

#[test]
fn cuda_le_self_collapses_to_true_via_cse() {
    let p = program_with_x_load_then(binop(BinOp::Le, Expr::var("x"), Expr::var("x")));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::LitBool(true)),
            "Le(x,x) must fold to true; got {value:?}"
        );
    }
}

#[test]
fn cuda_ge_self_collapses_to_true_via_cse() {
    let p = program_with_x_load_then(binop(BinOp::Ge, Expr::var("x"), Expr::var("x")));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::LitBool(true)),
            "Ge(x,x) must fold to true; got {value:?}"
        );
    }
}

#[test]
fn cuda_lt_self_collapses_to_false_via_cse() {
    // store buf 0 (var("x") < var("x"))  →  store buf 0 LitBool(false)
    let p = program_with_x_load_then(Expr::lt(Expr::var("x"), Expr::var("x")));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::LitBool(false)),
            "expected LitBool(false) after `x < x` collapse via CSE; got {value:?}"
        );
    }
}

#[test]
fn cuda_xor_self_collapses_via_cse() {
    // store buf 0 (var("x") ^ var("x")) → store buf 0 0
    // Requires CSE-aware pattern_match: canonical[arg1] == canonical[arg2].
    let p = program_with_x_load_then(Expr::bitxor(Expr::var("x"), Expr::var("x")));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::LitU32(0)),
            "expected LitU32(0) after BitXor-self collapse via CSE; got {value:?}"
        );
    }
}

#[test]
fn cuda_sub_self_collapses_via_cse() {
    // store buf 0 (var("x") - var("x")) → store buf 0 0
    let p = program_with_x_load_then(Expr::sub(Expr::var("x"), Expr::var("x")));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::LitU32(0)),
            "expected LitU32(0) after Sub-self collapse via CSE; got {value:?}"
        );
    }
}

#[test]
fn cuda_bitand_self_collapses_via_cse() {
    // store buf 0 (var("x") & var("x")) → store buf 0 var("x")
    let p = program_with_x_load_then(Expr::bitand(Expr::var("x"), Expr::var("x")));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::Var(n) if n.as_str() == "x"),
            "expected Var(x) after BitAnd-self collapse via CSE; got {value:?}"
        );
    }
}

fn binop(op: BinOp, left: Expr, right: Expr) -> Expr {
    Expr::BinOp {
        op,
        left: Box::new(left),
        right: Box::new(right),
    }
}

#[test]
fn cuda_bitxor_chain_cancels_right_via_cse() {
    // Build `let y = Load(input, 0); store buf 0 ((x ^ y) ^ y)`
    //  -  both `y` operands are CSE-equivalent so the outer BitXor
    // cancels the inner pair and leaves `x`.
    let p = Program::wrapped(
        vec![
            BufferDecl::storage("input", 0, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            BufferDecl::storage("buf", 1, BufferAccess::ReadWrite, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![
            Node::let_bind("x", Expr::load("input", Expr::u32(0))),
            Node::let_bind("y", Expr::load("input", Expr::u32(0))),
            Node::store(
                "buf",
                Expr::u32(0),
                binop(
                    BinOp::BitXor,
                    binop(BinOp::BitXor, Expr::var("x"), Expr::var("y")),
                    Expr::var("y"),
                ),
            ),
        ],
    );
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        // After CSE proves x and y both alias Load(input,0) and the
        // outer BitXor folds, what remains is `Var(x)` (or potentially
        // const-prop'd to a single Load reference). Both forms pass.
        assert!(
            !matches!(
                value,
                Expr::BinOp {
                    op: BinOp::BitXor,
                    ..
                }
            ),
            "BitXor chain must collapse; got {value:?}"
        );
    }
}

#[test]
fn cuda_min_with_zero_collapses_to_zero() {
    // Min(x, 0u) → 0u (u32 minimum is 0).
    let p = program_with_x_load_then(binop(BinOp::Min, Expr::var("x"), Expr::u32(0)));
    let out = run_pipeline(p);
    let body = body_of(&out);
    if let Some(Node::Store { value, .. }) = body.iter().find(|n| matches!(n, Node::Store { .. })) {
        assert!(
            matches!(value, Expr::LitU32(0)),
            "Min(x, 0) must fold to 0; got {value:?}"
        );
    }
}

#[test]
fn cuda_max_with_max_collapses_to_max() {
    // Max(x, MAX) → MAX (u32 maximum saturates).
    let p = program_with_x_load_then(binop(BinOp::Max, Expr::var("x"), Expr::u32(u32::MAX)));
    let out = run_pipeline(p);
    let body = body_of(&out);
    if let Some(Node::Store { value, .. }) = body.iter().find(|n| matches!(n, Node::Store { .. })) {
        match value {
            Expr::LitU32(v) if *v == u32::MAX => {}
            other => panic!("Max(x, MAX) must fold to MAX; got {other:?}"),
        }
    }
}

#[test]
fn cuda_min_with_max_collapses_to_left() {
    // Min(x, MAX) → x (clamp to MAX is a no-op).
    let p = program_with_x_load_then(binop(BinOp::Min, Expr::var("x"), Expr::u32(u32::MAX)));
    let out = run_pipeline(p);
    let body = body_of(&out);
    if let Some(Node::Store { value, .. }) = body.iter().find(|n| matches!(n, Node::Store { .. })) {
        assert!(
            matches!(value, Expr::Var(n) if n.as_str() == "x"),
            "Min(x, MAX) must fold to x; got {value:?}"
        );
    }
}

#[test]
fn cuda_max_with_zero_collapses_to_left() {
    // Max(x, 0u) → x (clamp from below by 0 is a no-op for u32).
    let p = program_with_x_load_then(binop(BinOp::Max, Expr::var("x"), Expr::u32(0)));
    let out = run_pipeline(p);
    let body = body_of(&out);
    if let Some(Node::Store { value, .. }) = body.iter().find(|n| matches!(n, Node::Store { .. })) {
        assert!(
            matches!(value, Expr::Var(n) if n.as_str() == "x"),
            "Max(x, 0) must fold to x; got {value:?}"
        );
    }
}

#[test]
fn cuda_min_self_collapses_via_cse() {
    // store buf 0 (min(x, x)) → store buf 0 var("x")
    let p = program_with_x_load_then(binop(BinOp::Min, Expr::var("x"), Expr::var("x")));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::Var(n) if n.as_str() == "x"),
            "expected Var(x) after Min-self collapse; got {value:?}"
        );
    }
}

#[test]
fn cuda_max_self_collapses_via_cse() {
    let p = program_with_x_load_then(binop(BinOp::Max, Expr::var("x"), Expr::var("x")));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::Var(n) if n.as_str() == "x"),
            "expected Var(x) after Max-self collapse; got {value:?}"
        );
    }
}

#[test]
fn cuda_absdiff_self_collapses_to_zero() {
    let p = program_with_x_load_then(binop(BinOp::AbsDiff, Expr::var("x"), Expr::var("x")));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::LitU32(0)),
            "expected LitU32(0) after AbsDiff-self collapse; got {value:?}"
        );
    }
}

#[test]
fn cuda_bitxor_zero_collapses_to_left() {
    // store buf 0 (var("x") ^ 0)  →  store buf 0 var("x")
    let p = program_with_x_load_then(Expr::bitxor(Expr::var("x"), Expr::u32(0)));
    let out = run_pipeline(p);
    let body = body_of(&out);
    let store = body
        .iter()
        .find(|n| matches!(n, Node::Store { .. }))
        .expect("store survives");
    if let Node::Store { value, .. } = store {
        assert!(
            matches!(value, Expr::Var(n) if n.as_str() == "x"),
            "expected Var(x) after BitXor-zero collapse; got {value:?}"
        );
    }
}

