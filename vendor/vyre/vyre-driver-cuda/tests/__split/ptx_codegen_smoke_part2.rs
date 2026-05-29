use super::*;

#[test]
fn ptx_emits_bitwise_ops() {
    let ops = [
        (
            "and",
            Expr::bitand(Expr::gid_x(), Expr::u32(0xFF)),
            "and.b32",
        ),
        ("or", Expr::bitor(Expr::gid_x(), Expr::u32(0xFF)), "or.b32"),
        (
            "xor",
            Expr::bitxor(Expr::gid_x(), Expr::u32(0xFF)),
            "xor.b32",
        ),
        ("shl", Expr::shl(Expr::gid_x(), Expr::u32(2)), "shl.b32"),
        ("shr", Expr::shr(Expr::gid_x(), Expr::u32(2)), "shr.u32"),
    ];
    for (name, expr, expected_insn) in ops {
        let program = Program::wrapped(
            vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
            [1, 1, 1],
            vec![Node::store("out", Expr::u32(0), expr)],
        );
        let secondary_text = program_to_ptx(&program, &default_config())
            .unwrap_or_else(|e| panic!("Fix: {name} must lower to PTX: {e}"));
        assert!(
            secondary_text.contains(expected_insn),
            "Fix: {name} must emit {expected_insn}."
        );
    }
}

#[test]
fn ptx_emits_integer_comparisons() {
    let ops = [
        (
            "eq",
            Expr::eq(Expr::load("input", Expr::u32(0)), Expr::u32(5)),
            "setp.eq.u32",
        ),
        (
            "ne",
            Expr::ne(Expr::load("input", Expr::u32(0)), Expr::u32(5)),
            "setp.ne.u32",
        ),
        (
            "lt",
            Expr::lt(Expr::load("input", Expr::u32(0)), Expr::u32(5)),
            "setp.lt.u32",
        ),
        (
            "gt",
            Expr::gt(Expr::load("input", Expr::u32(0)), Expr::u32(5)),
            "setp.gt.u32",
        ),
        (
            "le",
            Expr::le(Expr::load("input", Expr::u32(0)), Expr::u32(5)),
            "setp.le.u32",
        ),
        (
            "ge",
            Expr::ge(Expr::load("input", Expr::u32(0)), Expr::u32(5)),
            "setp.ge.u32",
        ),
    ];
    for (name, expr, expected_insn) in ops {
        let program = Program::wrapped(
            vec![
                BufferDecl::read("input", 0, DataType::U32).with_count(1),
                BufferDecl::output("out", 1, DataType::U32).with_count(1),
            ],
            [1, 1, 1],
            vec![Node::store("out", Expr::u32(0), expr)],
        );
        let secondary_text = program_to_ptx(&program, &default_config())
            .unwrap_or_else(|e| panic!("Fix: {name} must lower to PTX: {e}"));
        assert!(
            secondary_text.contains(expected_insn),
            "Fix: {name} must emit {expected_insn}."
        );
    }
}

#[test]
fn ptx_emits_float_arithmetic() {
    let ops = [
        (
            "fadd",
            Expr::add(Expr::load("input", Expr::u32(0)), Expr::f32(2.0)),
            "add.f32",
        ),
        (
            "fsub",
            Expr::sub(Expr::load("input", Expr::u32(0)), Expr::f32(2.0)),
            "sub.f32",
        ),
        (
            "fmul",
            Expr::mul(Expr::load("input", Expr::u32(0)), Expr::f32(3.0)),
            "mul.f32",
        ),
        (
            "fdiv",
            Expr::div(Expr::load("input", Expr::u32(0)), Expr::f32(3.0)),
            "mul.f32",
        ),
    ];
    for (name, expr, expected_insn) in ops {
        let program = Program::wrapped(
            vec![
                BufferDecl::read("input", 0, DataType::F32).with_count(1),
                BufferDecl::output("out", 1, DataType::F32).with_count(1),
            ],
            [1, 1, 1],
            vec![Node::store("out", Expr::u32(0), expr)],
        );
        let secondary_text = program_to_ptx(&program, &default_config())
            .unwrap_or_else(|e| panic!("Fix: {name} must lower to PTX: {e}"));
        assert!(
            secondary_text.contains(expected_insn),
            "Fix: {name} must emit {expected_insn}."
        );
    }
}

// ── UnOp coverage ────────────────────────────────────────────────────

#[test]
fn ptx_emits_unary_ops() {
    let ops: Vec<(&str, Expr, &str, DataType, DataType)> = vec![
        (
            "neg_f32",
            Expr::negate(Expr::load("input", Expr::u32(0))),
            "neg.f32",
            DataType::F32,
            DataType::F32,
        ),
        (
            "not_b32",
            Expr::bitnot(Expr::load("input", Expr::u32(0))),
            "not.b32",
            DataType::U32,
            DataType::U32,
        ),
        (
            "abs_f32",
            Expr::abs(Expr::load("input", Expr::u32(0))),
            "abs.f32",
            DataType::F32,
            DataType::F32,
        ),
        (
            "sqrt_f32",
            Expr::sqrt(Expr::load("input", Expr::u32(0))),
            "sqrt.rn.f32",
            DataType::F32,
            DataType::F32,
        ),
        (
            "popc",
            Expr::popcount(Expr::load("input", Expr::u32(0))),
            "popc.b32",
            DataType::U32,
            DataType::U32,
        ),
        (
            "clz",
            Expr::clz(Expr::load("input", Expr::u32(0))),
            "clz.b32",
            DataType::U32,
            DataType::U32,
        ),
        (
            "is_inf",
            Expr::is_inf(Expr::load("input", Expr::u32(0))),
            "setp.eq.u32",
            DataType::F32,
            DataType::Bool,
        ),
        (
            "is_finite",
            Expr::is_finite(Expr::load("input", Expr::u32(0))),
            "setp.lt.u32",
            DataType::F32,
            DataType::Bool,
        ),
    ];
    for (name, expr, expected_insn, input_dt, output_dt) in ops {
        let program = Program::wrapped(
            vec![
                BufferDecl::read("input", 0, input_dt).with_count(1),
                BufferDecl::output("out", 1, output_dt).with_count(1),
            ],
            [1, 1, 1],
            vec![Node::store("out", Expr::u32(0), expr)],
        );
        let secondary_text = program_to_ptx(&program, &default_config())
            .unwrap_or_else(|e| panic!("Fix: {name} must lower to PTX: {e}"));
        assert!(
            secondary_text.contains(expected_insn),
            "Fix: {name} must emit {expected_insn}."
        );
    }
}

#[test]
fn ptx_uses_strict_inverse_sqrt_without_ulp_budget() {
    let program = Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::F32).with_count(1),
            BufferDecl::output("out", 1, DataType::F32).with_count(1),
        ],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::u32(0),
            Expr::inverse_sqrt(Expr::load("input", Expr::u32(0))),
        )],
    );
    let secondary_text = program_to_ptx(&program, &default_config())
        .expect("Fix: strict inverse-sqrt must lower without approximate PTX.");
    assert!(
        secondary_text.contains("sqrt.rn.f32")
            && secondary_text.contains("rcp.rn.f32")
            && !secondary_text.contains("rsqrt.approx.f32"),
        "Fix: strict inverse-sqrt must avoid rsqrt.approx without an explicit ULP budget; got:\n{secondary_text}"
    );
}

#[test]
fn ptx_requires_ulp_budget_for_approximate_transcendentals() {
    let program = Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::F32).with_count(1),
            BufferDecl::output("out", 1, DataType::F32).with_count(1),
        ],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::u32(0),
            Expr::UnOp {
                op: UnOp::Tanh,
                operand: Box::new(Expr::load("input", Expr::u32(0))),
            },
        )],
    );
    let err = program_to_ptx(&program, &default_config())
        .expect_err("Fix: CUDA tanh must reject implicit approximate lowering.");
    assert!(
        err.contains("tanh") && err.contains("ulp_budget") && err.contains("Fix:"),
        "Fix: approximate-transcendental rejection must name the op and remediation; got: {err}"
    );

    let mut config = default_config();
    config.ulp_budget = Some(64);
    let secondary_text = program_to_ptx(&program, &config)
        .expect("Fix: explicit ULP budget must permit approximate tanh PTX.");
    assert!(
        secondary_text.contains("tanh.approx.f32"),
        "Fix: budgeted tanh lowering must use the PTX fast approximation; got:\n{secondary_text}"
    );
}

#[test]
fn ptx_emits_integer_subgroup_ops() {
    let ops: Vec<(&str, Expr, &str)> = vec![
        (
            "subgroup_ballot",
            Expr::SubgroupBallot {
                cond: Box::new(Expr::eq(Expr::gid_x(), Expr::u32(0))),
            },
            "vote.sync.ballot.b32",
        ),
        (
            "subgroup_shuffle",
            Expr::SubgroupShuffle {
                value: Box::new(Expr::gid_x()),
                lane: Box::new(Expr::u32(0)),
            },
            "shfl.sync.idx.b32",
        ),
        (
            "subgroup_add",
            Expr::SubgroupAdd {
                value: Box::new(Expr::gid_x()),
            },
            "redux.sync.add.u32",
        ),
    ];
    for (name, expr, expected_insn) in ops {
        let program = Program::wrapped(
            vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
            [1, 1, 1],
            vec![Node::store("out", Expr::u32(0), expr)],
        );
        let secondary_text = program_to_ptx(&program, &default_config())
            .unwrap_or_else(|e| panic!("Fix: {name} must lower to PTX: {e}"));
        assert!(
            secondary_text.contains("activemask.b32") && secondary_text.contains(expected_insn),
            "Fix: {name} must emit active-mask guarded {expected_insn}."
        );
    }
}

// ── FMA ──────────────────────────────────────────────────────────────

#[test]
fn ptx_emits_fma() {
    let program = Program::wrapped(
        vec![
            BufferDecl::read("a", 0, DataType::F32).with_count(1),
            BufferDecl::read("b", 1, DataType::F32).with_count(1),
            BufferDecl::read("c", 2, DataType::F32).with_count(1),
            BufferDecl::output("out", 3, DataType::F32).with_count(1),
        ],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::u32(0),
            Expr::fma(
                Expr::load("a", Expr::u32(0)),
                Expr::load("b", Expr::u32(0)),
                Expr::load("c", Expr::u32(0)),
            ),
        )],
    );
    let secondary_text =
        program_to_ptx(&program, &default_config()).expect("Fix: FMA must lower to PTX.");
    assert!(
        secondary_text.contains("fma.rn.f32"),
        "Fix: FMA must emit fma.rn.f32 instruction."
    );
}

// ── Control flow ─────────────────────────────────────────────────────

#[test]
fn ptx_emits_if_then_else() {
    let program = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::If {
            cond: Expr::eq(Expr::gid_x(), Expr::u32(0)),
            then: vec![Node::store("out", Expr::u32(0), Expr::u32(1))],
            otherwise: vec![Node::store("out", Expr::u32(0), Expr::u32(2))],
        }],
    );
    let secondary_text =
        program_to_ptx(&program, &default_config()).expect("Fix: If/else must lower to PTX.");
    assert!(
        secondary_text.contains("@%") && secondary_text.contains("@!%"),
        "Fix: simple PTX if/else store bodies must lower to complementary predicated stores."
    );
    assert!(
        secondary_text.matches("st.global.u32").count() == 2,
        "Fix: PTX if/else must emit both predicated stores."
    );
    assert!(
        !secondary_text.contains("$L_if_else_") && !secondary_text.contains("$L_if_end_"),
        "Fix: branchless predication must not leave if/else labels in simple store bodies."
    );
}

#[test]
fn ptx_prunes_literal_false_if_branch_before_lowering_dead_code() {
    let program = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::If {
            cond: Expr::bool(false),
            then: vec![Node::let_bind(
                "dead_call",
                Expr::Call {
                    op_id: "unknown.op".into(),
                    args: Vec::new(),
                },
            )],
            otherwise: vec![Node::store("out", Expr::u32(0), Expr::u32(1))],
        }],
    );
    let secondary_text = program_to_ptx(&program, &default_config())
        .expect("Fix: literal-false If must prune unsupported dead branch before PTX lowering.");
    assert!(
        secondary_text.contains("st.global.u32") && !secondary_text.contains("dead_call"),
        "Fix: literal-false If lowering must emit only the reachable branch."
    );
}

#[test]
fn ptx_emits_trap_as_lane_exit() {
    let program = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::Trap {
            address: Box::new(Expr::u32(7)),
            tag: "decode.invalid".into(),
        }],
    );
    let secondary_text =
        program_to_ptx(&program, &default_config()).expect("Fix: Trap must lower to PTX.");
    assert!(
        secondary_text.contains("// trap tag: decode.invalid")
            && secondary_text.contains("bra $L_exit;"),
        "Fix: CUDA trap lowering must preserve the tag in PTX comments and terminate the lane."
    );
    assert!(
        !secondary_text.contains("__vyre_descriptor_trap_sidecar"),
        "Fix: CUDA PTX must not expose vyre-lower's internal trap sidecar in the kernel ABI until CUDA implements trap-sidecar readback."
    );
}

