use std::sync::Arc;

use super::Program;
use crate::error::Error;
use crate::ir::{Expr, Ident, Node};
use crate::ir_inner::model::program::BufferDecl;
use crate::ir_inner::model::types::DataType;
use crate::transform::visit::collect_call_op_ids;

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

#[test]
fn canonical_fingerprint_normalizes_commutative_literal_order() {
    let left = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::u32(0),
            Expr::add(Expr::u32(7), Expr::var("x")),
        )],
    );
    let right = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::u32(0),
            Expr::add(Expr::var("x"), Expr::u32(7)),
        )],
    );

    assert_ne!(
        left.to_wire().expect("Fix: left fixture must encode"),
        right.to_wire().expect("Fix: right fixture must encode"),
        "Fix: this regression test must exercise distinct author wire forms."
    );
    assert_eq!(
        left.fingerprint(),
        right.fingerprint(),
        "Fix: canonical Program fingerprint must ignore commutative literal spelling."
    );
}

#[test]
fn canonical_fingerprint_normalizes_safe_commutative_nonliteral_order() {
    let left = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::u32(0),
            Expr::bitxor(Expr::var("a"), Expr::var("b")),
        )],
    );
    let right = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::u32(0),
            Expr::bitxor(Expr::var("b"), Expr::var("a")),
        )],
    );

    assert_eq!(
        left.fingerprint(),
        right.fingerprint(),
        "Fix: canonical Program fingerprint must sort safe commutative operands."
    );
}

#[test]
fn canonical_fingerprint_preserves_float_sensitive_nonliteral_order() {
    for (left_value, right_value) in [
        (
            Expr::add(Expr::var("a"), Expr::var("b")),
            Expr::add(Expr::var("b"), Expr::var("a")),
        ),
        (
            Expr::mul(Expr::var("a"), Expr::var("b")),
            Expr::mul(Expr::var("b"), Expr::var("a")),
        ),
        (
            Expr::min(Expr::var("a"), Expr::var("b")),
            Expr::min(Expr::var("b"), Expr::var("a")),
        ),
        (
            Expr::max(Expr::var("a"), Expr::var("b")),
            Expr::max(Expr::var("b"), Expr::var("a")),
        ),
    ] {
        let left = Program::wrapped(
            vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
            [1, 1, 1],
            vec![Node::store("out", Expr::u32(0), left_value)],
        );
        let right = Program::wrapped(
            vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
            [1, 1, 1],
            vec![Node::store("out", Expr::u32(0), right_value)],
        );

        assert_ne!(
            left.fingerprint(),
            right.fingerprint(),
            "Fix: canonical Program fingerprint must preserve order for float-sensitive ops."
        );
    }
}

#[test]
fn canonical_wire_hash_is_blake3_of_canonical_wire_bytes() {
    let program = Program::wrapped(
        vec![
            BufferDecl::read("input", 1, DataType::U32).with_count(1),
            BufferDecl::output("out", 0, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::u32(0),
            Expr::bitxor(Expr::var("b"), Expr::var("a")),
        )],
    );
    let canonical_wire = program
        .canonical_wire_bytes()
        .expect("Fix: canonical fixture must encode");
    let expected = *blake3::hash(&canonical_wire).as_bytes();

    assert_eq!(program.fingerprint(), expected);
    assert_eq!(
        *program
            .canonical_wire_hash()
            .expect("Fix: canonical fixture must hash")
            .as_bytes(),
        expected
    );
}

#[test]
fn canonical_wire_hash_normalizes_float_payload_noise() {
    let nan_a = Program::wrapped(
        Vec::new(),
        [1, 1, 1],
        vec![Node::let_bind("x", Expr::f32(f32::from_bits(0x7FC1_2345)))],
    );
    let nan_b = Program::wrapped(
        Vec::new(),
        [1, 1, 1],
        vec![Node::let_bind("x", Expr::f32(f32::from_bits(0x7FA0_0001)))],
    );
    let subnormal = Program::wrapped(
        Vec::new(),
        [1, 1, 1],
        vec![Node::let_bind("x", Expr::f32(f32::from_bits(1)))],
    );
    let zero = Program::wrapped(
        Vec::new(),
        [1, 1, 1],
        vec![Node::let_bind("x", Expr::f32(0.0))],
    );

    assert_eq!(nan_a.fingerprint(), nan_b.fingerprint());
    assert_eq!(subnormal.fingerprint(), zero.fingerprint());
}

#[test]
fn canonical_fingerprint_flattens_binding_free_nested_blocks() {
    let nested = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::block(vec![Node::block(vec![Node::store(
            "out",
            Expr::u32(0),
            Expr::u32(1),
        )])])],
    );
    let flat = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(1))],
    );

    assert_eq!(
        nested.fingerprint(),
        flat.fingerprint(),
        "Fix: canonical Program fingerprint must flatten binding-free Block wrappers."
    );
}

#[test]
fn canonical_fingerprint_preserves_binding_block_scope() {
    let scoped = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::block(vec![Node::let_bind("x", Expr::u32(1))])],
    );
    let leaked = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::let_bind("x", Expr::u32(1))],
    );

    assert_ne!(
        scoped.fingerprint(),
        leaked.fingerprint(),
        "Fix: canonicalization must not flatten Blocks that own local bindings."
    );
}

#[test]
fn validation_cache_is_bound_to_current_fingerprint() {
    let mut program = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(1))],
    );

    program.mark_validated_on("backend-a-test");
    assert!(program.is_validated_on("backend-a-test"));

    program.set_parallel_region_size([2, 1, 1]);
    assert!(
        !program.is_validated_on("backend-a-test"),
        "Fix: backend validation cache entries must be invalidated when Program fingerprint changes."
    );
}

#[test]
fn structural_validation_cache_is_cleared_by_parallel_region_mutation() {
    let mut program = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(1))],
    );

    program
        .validate()
        .expect("Fix: valid fixture must pass structural validation");
    assert!(program.is_structurally_validated());

    program.set_parallel_region_size([0, 1, 1]);
    assert!(
        !program.is_structurally_validated(),
        "Fix: set_parallel_region_size must clear structural validation state."
    );
    assert!(
        program.validate().is_err(),
        "Fix: validation must re-run after parallel region mutation and reject zero dimensions."
    );
}

#[test]
fn collect_call_op_ids_preserves_first_appearance_order() {
    let program = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![
            Node::let_bind("a", Expr::call("alpha.op", vec![Expr::u32(1)])),
            Node::let_bind("b", Expr::call("beta.op", vec![Expr::u32(2)])),
            Node::let_bind("c", Expr::call("gamma.op", vec![Expr::u32(3)])),
            Node::Return,
        ],
    );
    let ids: Vec<String> = collect_call_op_ids(&program)
        .into_iter()
        .map(|id| id.to_string())
        .collect();
    assert_eq!(
        ids,
        vec![
            "alpha.op".to_string(),
            "beta.op".to_string(),
            "gamma.op".to_string(),
        ]
    );
}

#[test]
fn collect_call_op_ids_shares_arc_for_duplicate_op_identifiers() {
    let shared = Ident::new(Arc::from("vyre.test.duplicate.call"));
    let program = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![
            Node::let_bind("a", Expr::call(shared.clone(), vec![Expr::u32(1)])),
            Node::let_bind("b", Expr::call(shared, vec![Expr::u32(2)])),
            Node::Return,
        ],
    );
    let ids = collect_call_op_ids(&program);
    assert_eq!(ids.len(), 2);
    assert!(Arc::ptr_eq(&ids[0], &ids[1]));
}

#[test]
fn fingerprint_matches_across_clone_when_canonical_wire_encode_rejects_workgroup() {
    let program = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [0, 0, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(1)), Node::Return],
    );
    assert!(
        program.canonical_wire_hash().is_err(),
        "Fixture must exercise canonical wire rejection before fallback hashing."
    );
    let clone = program.clone();
    assert_eq!(program.fingerprint(), clone.fingerprint());
}

#[test]
fn buffers_equal_ignoring_declaration_order_handles_permuted_buffers() {
    let buffers_a = [
        BufferDecl::output("out", 0, DataType::U32).with_count(1),
        BufferDecl::read("input", 1, DataType::U32).with_count(1),
    ];
    let buffers_b = [
        BufferDecl::read("input", 1, DataType::U32).with_count(1),
        BufferDecl::output("out", 0, DataType::U32).with_count(1),
    ];
    assert_ne!(buffers_a.as_slice(), buffers_b.as_slice());
    assert!(super::meta::buffers_equal_ignoring_declaration_order(
        &buffers_a, &buffers_b
    ));
}

#[test]
fn validate_joins_multiple_errors_with_semicolon_separator() {
    let program = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [0, 0, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(1)), Node::Return],
    );
    match program.validate() {
        Err(Error::WireFormatValidation { message }) => {
            assert!(
                message.contains("workgroup_size[0] is 0"),
                "missing axis-0 message: {message}"
            );
            assert!(
                message.contains("workgroup_size[1] is 0"),
                "missing axis-1 message: {message}"
            );
            assert!(
                message.contains("; "),
                "expected '; ' joiner between errors: {message}"
            );
        }
        other => panic!("expected WireFormatValidation error, got {other:?}"),
    }
}

#[test]
fn validation_skip_cache_hits_on_repeated_validate_calls() {
    // Call validate() twice on the same Program; the second call must
    // return immediately (is_structurally_validated flips to true after
    // the first successful call).
    let program = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(1))],
    );

    assert!(
        !program.is_structurally_validated(),
        "fresh program must not be pre-validated"
    );

    program
        .validate()
        .expect("Fix: valid program must pass validation");
    assert!(
        program.is_structurally_validated(),
        "program must be marked validated after first validate()"
    );

    // Second call must hit the cache (returns Ok immediately).
    program
        .validate()
        .expect("Fix: repeated validate must return Ok via cache");
    assert!(program.is_structurally_validated());
}

#[test]
fn validation_skip_cache_clears_after_with_rewritten_entry() {
    // The cache must invalidate when the Program shape changes.
    let program = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(1))],
    );

    program
        .validate()
        .expect("Fix: valid program must pass validation");
    assert!(program.is_structurally_validated());

    // Rewrite the entry to a different shape.
    let rewritten =
        program.with_rewritten_entry(vec![Node::store("out", Expr::u32(0), Expr::u32(42))]);
    assert!(
        !rewritten.is_structurally_validated(),
        "with_rewritten_entry must clear the validation cache"
    );
}

#[test]
fn mark_validated_on_distinguishes_backends() {
    let program = Program::wrapped(
        vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(1))],
    );

    program.mark_validated_on("backend-a");
    assert!(
        program.is_validated_on("backend-a"),
        "must be validated for backend-a after mark"
    );
    assert!(
        !program.is_validated_on("backend-b"),
        "mark_validated_on(\"backend-a\") must not satisfy is_validated_on(\"backend-b\")"
    );
}

#[test]
fn with_rewritten_entry_preserves_buffer_arc_identity() {
    let buffers: Vec<BufferDecl> = (0..20)
        .map(|i| BufferDecl::output(&format!("buf_{i}"), i, DataType::U32).with_count(1))
        .collect();
    let program = Program::wrapped(buffers, [64, 1, 1], vec![Node::Return]);
    let rewritten = program.with_rewritten_entry(vec![Node::let_bind("x", Expr::u32(42))]);

    assert!(
        Arc::ptr_eq(program.buffers_arc(), rewritten.buffers_arc()),
        "Fix: with_rewritten_entry must preserve the same Arc<[BufferDecl]> without deep cloning."
    );
}
