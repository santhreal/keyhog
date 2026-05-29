//! Test: subgroup.
use super::*;

#[test]
fn subgroup_add_emits_collective_operation() {
    let desc = KernelDescriptor {
        id: "sub_add".into(),
        bindings: BindingLayout { slots: vec![] },
        dispatch: Dispatch::new(64, 1, 1),
        body: KernelBody {
            ops: vec![
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![0],
                    result: Some(0),
                },
                KernelOp {
                    kind: KernelOpKind::SubgroupAdd,
                    operands: vec![0],
                    result: Some(1),
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::U32(7)],
        },
    };
    let module = emit(&desc).unwrap();
    assert_eq!(module.entry_points.len(), 1);
    assert_eq!(module.entry_points[0].name, "main");
}

#[test]
fn subgroup_ballot_emits_ballot_statement() {
    let desc = KernelDescriptor {
        id: "ballot".into(),
        bindings: BindingLayout { slots: vec![] },
        dispatch: Dispatch::new(64, 1, 1),
        body: KernelBody {
            ops: vec![
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![0],
                    result: Some(0),
                },
                KernelOp {
                    kind: KernelOpKind::SubgroupBallot,
                    operands: vec![0],
                    result: Some(1),
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::Bool(true)],
        },
    };
    let module = emit(&desc).unwrap();
    assert_eq!(module.entry_points.len(), 1);
    assert_eq!(module.entry_points[0].name, "main");
}

#[test]
fn subgroup_scalar_builtins_are_emitted_only_when_used() {
    let mut desc = empty_desc();
    desc.body.ops.push(KernelOp {
        kind: KernelOpKind::SubgroupLocalId,
        operands: vec![],
        result: Some(0),
    });
    desc.body.ops.push(KernelOp {
        kind: KernelOpKind::SubgroupSize,
        operands: vec![],
        result: Some(1),
    });

    let module = emit(&desc).expect("descriptor subgroup scalar builtins must emit");
    let args = &module.entry_points[0].function.arguments;
    assert!(
        args.iter().any(|arg| matches!(
            arg.binding,
            Some(Binding::BuiltIn(BuiltIn::SubgroupInvocationId))
        )),
        "SubgroupLocalId must add the subgroup invocation builtin"
    );
    assert!(
        args.iter()
            .any(|arg| matches!(arg.binding, Some(Binding::BuiltIn(BuiltIn::SubgroupSize)))),
        "SubgroupSize must add the subgroup size builtin"
    );
}
