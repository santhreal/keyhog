use super::*;
use vyre_foundation::ir::MemoryOrdering;

fn barrier_kernel(ordering: MemoryOrdering) -> KernelDescriptor {
    KernelDescriptor {
        id: "barrier_scope".into(),
        bindings: BindingLayout { slots: vec![] },
        dispatch: Dispatch::new(1, 1, 1),
        body: KernelBody {
            ops: vec![KernelOp {
                kind: KernelOpKind::Barrier { ordering },
                operands: vec![],
                result: None,
            }],
            child_bodies: vec![],
            literals: vec![],
        },
    }
}

#[test]
fn workgroup_barrier_emits_cta_barrier() {
    let ptx = emit(&barrier_kernel(MemoryOrdering::SeqCst))
        .expect("Fix: workgroup-scope barriers must remain PTX-emittable.");

    assert!(
        ptx.contains("bar.sync 0;"),
        "Fix: workgroup-scope barrier lowering must emit a CTA barrier."
    );
}

#[test]
fn grid_sync_barrier_is_not_silently_downgraded_to_cta_barrier() {
    match emit(&barrier_kernel(MemoryOrdering::GridSync)) {
        Err(EmitError::InvalidDescriptor(message)) => {
            assert!(
                message.contains("GridSync") && message.contains("bar.sync 0"),
                "Fix: GridSync rejection must name the semantic scope loss; got: {message}"
            );
        }
        Ok(ptx) => panic!(
            "Fix: PTX emitter silently accepted GridSync; this would downgrade cross-grid synchronization to CTA scope. PTX:\n{ptx}"
        ),
        Err(other) => panic!(
            "Fix: GridSync PTX rejection must be an actionable InvalidDescriptor, not {other:?}."
        ),
    }
}
