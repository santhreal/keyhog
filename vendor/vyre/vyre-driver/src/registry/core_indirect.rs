//! `core.indirect_dispatch` op (C-B4).
//!
//! `core.indirect_dispatch(workgroup_count: GpuBufferHandle<[u32;3]>)`
//! lowers to `ComputePass::dispatch_workgroups_indirect(buffer, 0)`
//! on the wgpu backend. The workgroup count is read from GPU
//! memory at submission time — enabling patterns like:
//!
//! * Compact + dispatch: one kernel computes a list of work items
//!   and writes its size to a buffer; the next dispatch reads the
//!   size without a round-trip through the CPU.
//! * Variable-rate GPU pipelines where downstream dispatch size
//!   depends on upstream results.
//!
//! The op itself has Category C — there is no portable CPU
//! equivalent (dispatching is a backend concept). A Program that
//! uses `core.indirect_dispatch` on the CPU reference fails Law C
//! cleanly; a backend that supports indirect dispatch advertises
//! support via `supports_indirect_dispatch: true` in its
//! `AdapterCaps` (see `vyre_foundation::optimizer::ctx::AdapterCaps`).

use crate::OpDefRegistration;
use crate::{Category, OpDef, Signature, TypedParam};
use vyre_foundation::cpu_op::structured_intrinsic_cpu;

const OP_ID: &str = "core.indirect_dispatch";

const SIG: Signature = Signature {
    inputs: &[TypedParam {
        name: "workgroup_count",
        ty: "GpuBufferHandle<[u32;3]>",
    }],
    outputs: &[],
    attrs: &[],
    bytes_extraction: false,
};

inventory::submit! {
    OpDefRegistration::new(|| OpDef {
        id: OP_ID,
        dialect: "core",
        category: Category::Intrinsic,
        signature: SIG,
        lowerings: vyre_foundation::LoweringTable {
            cpu_ref: structured_intrinsic_cpu,
            ..vyre_foundation::LoweringTable::empty()
        },
        laws: &[],
        compose: None,
    })
}

/// Stable op id for `core.indirect_dispatch`.
pub const INDIRECT_DISPATCH_OP_ID: &str = OP_ID;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::DialectRegistry;

    #[test]
    fn indirect_dispatch_registers_in_core_dialect() {
        let reg = DialectRegistry::global();
        let id = reg.intern_op(OP_ID);
        let def = reg
            .lookup(id)
            .expect("Fix: core.indirect_dispatch must register via inventory::submit!; restore the OpDefRegistration block in this file.");
        assert_eq!(def.dialect, "core");
        assert_eq!(def.category, Category::Intrinsic);
    }

    #[test]
    fn indirect_dispatch_has_no_portable_lowering() {
        let reg = DialectRegistry::global();
        let id = reg.intern_op(OP_ID);
        let def = reg.lookup(id).unwrap();
        // Cat C op; the Wgsl/Spirv/Ptx/Metal lowerings are all None.
        assert!(def.lowerings.naga_wgsl.is_none());
        assert!(def.lowerings.naga_spv.is_none());
        assert!(def.lowerings.ptx.is_none());
        assert!(def.lowerings.metal.is_none());
    }

    #[test]
    fn op_id_is_stable() {
        assert_eq!(INDIRECT_DISPATCH_OP_ID, "core.indirect_dispatch");
    }
}
