// Tests for `validate.rs`. Split out per audit item #85 to keep the
// parent file focused on production code.

use super::*;
use crate::ir::{AtomicOp, BinOp, BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp};
use crate::validate::fusion_safety::validate_fusion_alias_hazards;
use crate::validate::self_composition::validate_self_composition;
use crate::MemoryOrdering;
use proptest::prelude::*;

// ------------------------------------------------------------------
// Legacy multi-walk validator (copied from pre-refactor code) for
// regression testing.
// ------------------------------------------------------------------
fn validate_with_options_legacy(
    program: &Program,
    options: ValidationOptions<'_>,
) -> ValidationReport {
    let mut report = ValidationReport {
        errors: Vec::with_capacity(program.buffers().len() + program.entry().len()),
        warnings: Vec::new(),
    };

    if let Some(message) = program.top_level_region_violation() {
        report.errors.push(err(message));
    }

    for (axis, &size) in program.workgroup_size.iter().enumerate() {
        if size == 0 {
            report.errors.push(err(format!(
                "workgroup_size[{axis}] is 0. Fix: all workgroup dimensions must be >= 1."
            )));
        }
    }

    let mut seen_names = FxHashSet::default();
    let mut seen_bindings = FxHashSet::default();
    for buf in program.buffers() {
        if !seen_names.insert(&buf.name) {
            report.errors.push(err(format!(
                "duplicate buffer name `{}`. Fix: each buffer must have a unique name.",
                buf.name
            )));
        }
        if buf.access != BufferAccess::Workgroup && !seen_bindings.insert(buf.binding) {
            report.errors.push(err(format!(
                    "duplicate binding slot {} (buffer `{}`). Fix: each buffer must have a unique binding.",
                    buf.binding, buf.name
                )));
        }
        if buf.access == BufferAccess::Workgroup && buf.count == 0 {
            report.errors.push(err(format!(
                "workgroup buffer `{}` has count 0. Fix: declare a positive element count.",
                buf.name
            )));
        }
        validate_output_buffer_element_type(buf, &mut report.errors);
    }
    validate_output_markers(program.buffers(), &mut report.errors);

    let mut buffer_map: FxHashMap<&str, &crate::ir_inner::model::program::BufferDecl> =
        FxHashMap::default();
    buffer_map.reserve(program.buffers().len());
    buffer_map.extend(program.buffers().iter().map(|b| (b.name.as_ref(), b)));

    let mut scope = FxHashMap::default();
    let mut limits = depth::LimitState::default();
    nodes::validate_nodes(
        program.entry(),
        &buffer_map,
        &mut scope,
        false,
        0,
        &mut limits,
        options,
        &mut report,
    );
    validate_fusion_alias_hazards(program.entry(), &mut report.errors);
    validate_self_composition(program.entry(), &mut report.errors);

    report
}

// ------------------------------------------------------------------
// Proptest generators (adapted from transform::visit tests).
// ------------------------------------------------------------------
fn arb_ident() -> BoxedStrategy<String> {
    prop::sample::select(&["x", "y", "idx", "i", "acc"][..])
        .prop_map(str::to_string)
        .boxed()
}

fn arb_buffer_name() -> BoxedStrategy<String> {
    prop::sample::select(&["out", "input", "rw", "counts", "scratch"][..])
        .prop_map(str::to_string)
        .boxed()
}

fn arb_expr() -> BoxedStrategy<Expr> {
    let leaf = prop_oneof![
        any::<u32>().prop_map(Expr::LitU32),
        any::<i32>().prop_map(Expr::LitI32),
        any::<bool>().prop_map(Expr::LitBool),
        arb_ident().prop_map(Expr::var),
        arb_buffer_name().prop_map(Expr::buf_len),
    ];

    leaf.prop_recursive(3, 48, 3, |inner| {
        prop_oneof![
            (arb_buffer_name(), inner.clone()).prop_map(|(buffer, index)| Expr::Load {
                buffer: buffer.into(),
                index: Box::new(index),
            }),
            (inner.clone(), inner.clone()).prop_map(|(left, right)| Expr::BinOp {
                op: BinOp::Add,
                left: Box::new(left),
                right: Box::new(right),
            }),
            (inner.clone(), inner.clone()).prop_map(|(left, right)| Expr::BinOp {
                op: BinOp::Sub,
                left: Box::new(left),
                right: Box::new(right),
            }),
            inner.clone().prop_map(|operand| Expr::UnOp {
                op: UnOp::Negate,
                operand: Box::new(operand),
            }),
            (inner.clone(), inner.clone(), inner.clone()).prop_map(
                |(cond, true_val, false_val)| Expr::Select {
                    cond: Box::new(cond),
                    true_val: Box::new(true_val),
                    false_val: Box::new(false_val),
                }
            ),
            inner.clone().prop_map(|value| Expr::Cast {
                target: DataType::U32,
                value: Box::new(value),
            }),
            (
                arb_buffer_name(),
                inner.clone(),
                proptest::option::of(inner.clone()),
                inner.clone(),
            )
                .prop_map(|(buffer, index, expected, value)| Expr::Atomic {
                    op: AtomicOp::Add,
                    buffer: buffer.into(),
                    index: Box::new(index),
                    expected: expected.map(Box::new),
                    value: Box::new(value),
                    ordering: MemoryOrdering::SeqCst,
                }),
        ]
    })
    .boxed()
}

fn arb_node() -> BoxedStrategy<Node> {
    arb_node_with_depth(3)
}

fn arb_node_with_depth(depth: u32) -> BoxedStrategy<Node> {
    let leaf = prop_oneof![
        (arb_ident(), arb_expr()).prop_map(|(name, value)| Node::Let {
            name: name.into(),
            value,
        }),
        (arb_ident(), arb_expr()).prop_map(|(name, value)| Node::Assign {
            name: name.into(),
            value,
        }),
        (arb_buffer_name(), arb_expr(), arb_expr()).prop_map(|(buffer, index, value)| {
            Node::Store {
                buffer: buffer.into(),
                index,
                value,
            }
        }),
        Just(Node::Return),
        Just(Node::barrier()),
    ];

    if depth == 0 {
        return leaf.boxed();
    }

    leaf.prop_recursive(2, 32, 2, move |inner| {
        prop_oneof![
            (
                arb_expr(),
                prop::collection::vec(inner.clone(), 0..=3),
                prop::collection::vec(inner.clone(), 0..=3),
            )
                .prop_map(|(cond, then, otherwise)| Node::If {
                    cond,
                    then,
                    otherwise,
                }),
            (
                arb_ident(),
                arb_expr(),
                arb_expr(),
                prop::collection::vec(inner.clone(), 0..=3),
            )
                .prop_map(|(var, from, to, body)| Node::Loop {
                    var: var.into(),
                    from,
                    to,
                    body,
                }),
            prop::collection::vec(inner, 0..=3).prop_map(Node::Block),
        ]
    })
    .boxed()
}

fn arb_program() -> BoxedStrategy<Program> {
    prop::collection::vec(arb_node(), 0..=8)
        .prop_map(|entry| {
            Program::wrapped(
                vec![
                    BufferDecl::output("out", 0, DataType::U32)
                        .with_count(8)
                        .with_output_byte_range(0..16),
                    BufferDecl::read("input", 1, DataType::U32).with_count(8),
                    BufferDecl::read_write("rw", 2, DataType::U32).with_count(8),
                    BufferDecl::read("counts", 3, DataType::U32).with_count(8),
                    BufferDecl::workgroup("scratch", 4, DataType::U32),
                ],
                [1, 1, 1],
                entry,
            )
        })
        .boxed()
}

// ------------------------------------------------------------------
// Regression test: new single-pass validator must emit exactly the
// same errors (+ warnings) as the old four-walk validator.
// ------------------------------------------------------------------
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 50,
        ..ProptestConfig::default()
    })]

    #[test]
    fn single_pass_validator_matches_legacy(program in arb_program()) {
        let legacy = validate_with_options_legacy(&program, ValidationOptions::default());
        let modern = validate_with_options(&program, ValidationOptions::default());

        // Deterministic ordering: sort both error sets by message.
        let mut legacy_errors = legacy.errors;
        let mut modern_errors = modern.errors;
        legacy_errors.sort_by(|a, b| a.message.cmp(&b.message));
        modern_errors.sort_by(|a, b| a.message.cmp(&b.message));

        prop_assert_eq!(
            legacy_errors, modern_errors,
            "error mismatch between legacy and single-pass validator"
        );

        let mut legacy_warnings = legacy.warnings;
        let mut modern_warnings = modern.warnings;
        legacy_warnings.sort_by(|a, b| a.message.cmp(&b.message));
        modern_warnings.sort_by(|a, b| a.message.cmp(&b.message));

        prop_assert_eq!(
            legacy_warnings, modern_warnings,
            "warning mismatch between legacy and single-pass validator"
        );
    }
}
