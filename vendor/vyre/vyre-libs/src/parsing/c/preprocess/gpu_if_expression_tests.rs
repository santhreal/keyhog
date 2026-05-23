use super::gpu_if_expression::*;

#[test]
fn op_id_is_canonical_and_stable() {
    assert_eq!(
        OP_ID,
        "vyre-libs::parsing::c::preprocess::gpu_if_expression"
    );
}

#[test]
fn binding_indices_are_canonical_and_stable() {
    assert_eq!(BINDING_TOK_STARTS, 0);
    assert_eq!(BINDING_TOK_LENS, 1);
    assert_eq!(BINDING_DIRECTIVE_KINDS, 2);
    assert_eq!(BINDING_SOURCE, 3);
    assert_eq!(BINDING_MACRO_NAMES_PACKED, 4);
    assert_eq!(BINDING_MACRO_OFFSETS, 5);
    assert_eq!(BINDING_MACRO_VALUES, 6);
    assert_eq!(BINDING_DIRECTIVE_VALUES, 7);
}

#[test]
fn build_program_returns_well_formed_program() {
    let p = gpu_if_expression(8, 64);
    assert_eq!(p.buffers().len(), 8);
    assert_eq!(p.workgroup_size(), [256, 1, 1]);
}
