//! Category C zero-copy I/O intrinsics.
//!
//! The `io` dialect declares ops that move bytes between persistent
//! storage and GPU memory without a CPU staging copy. These are
//! Category C — they have no portable lowering. A concrete backend
//! opts in by registering a `BackendRegistration` that supplies
//! `naga_wgsl` / `naga_spv` / `ptx` / `metal` builders.
//!
//! Today, no backend opts in. A program that uses these ops fails
//! the capability check with a clear message. The opt-in crate
//! (`vyre-dialect-io`, planned) will register io_uring + GPUDirect
//! Storage lowerings.
//!
//! The ops:
//!
//! * `io.dma_from_nvme(fd, offset, length)` — stream bytes directly
//!   from an NVMe block device into GPU memory.
//! * `io.write_back_to_nvme(handle, fd, offset)` — stream GPU bytes
//!   back to an NVMe block device.
//! * `mem.zerocopy_map(fd)` — map a file descriptor so that the GPU
//!   can read it as its own address space (GDS).
//! * `mem.unmap(handle)` — release a `mem.zerocopy_map` reservation.
//!
//! Even without lowerings, the ops are compositional in vyre IR:
//! frontends can write Programs against them today, and the Program
//! validates. Execution succeeds only when a backend that supports
//! the `io` dialect is registered.

use crate::OpDefRegistration;
use crate::{Category, OpDef, Signature, TypedParam};

const OP_DMA_FROM_NVME: &str = "io.dma_from_nvme";
const OP_WRITE_BACK_TO_NVME: &str = "io.write_back_to_nvme";
const OP_ZEROCOPY_MAP: &str = "mem.zerocopy_map";
const OP_UNMAP: &str = "mem.unmap";

const SIG_DMA_FROM_NVME: Signature = Signature {
    inputs: &[
        TypedParam {
            name: "fd",
            ty: "i32",
        },
        TypedParam {
            name: "offset",
            ty: "u64",
        },
        TypedParam {
            name: "length",
            ty: "u64",
        },
    ],
    outputs: &[TypedParam {
        name: "handle",
        ty: "GpuBufferHandle",
    }],
    attrs: &[],
    bytes_extraction: false,
};

const SIG_WRITE_BACK_TO_NVME: Signature = Signature {
    inputs: &[
        TypedParam {
            name: "handle",
            ty: "GpuBufferHandle",
        },
        TypedParam {
            name: "fd",
            ty: "i32",
        },
        TypedParam {
            name: "offset",
            ty: "u64",
        },
    ],
    outputs: &[],
    attrs: &[],
    bytes_extraction: false,
};

const SIG_ZEROCOPY_MAP: Signature = Signature {
    inputs: &[TypedParam {
        name: "fd",
        ty: "i32",
    }],
    outputs: &[TypedParam {
        name: "handle",
        ty: "GpuBufferHandle",
    }],
    attrs: &[],
    bytes_extraction: false,
};

const SIG_UNMAP: Signature = Signature {
    inputs: &[TypedParam {
        name: "handle",
        ty: "GpuBufferHandle",
    }],
    outputs: &[],
    attrs: &[],
    bytes_extraction: false,
};

/// Shared unsupported CPU entry for Category C io ops.
///
/// Cat C ops have no portable CPU reference: their entire purpose is to keep
/// payload movement on the zero-copy storage/GPU path. Capability negotiation
/// must reject these ops before reference dispatch reaches this function. A
/// direct call is therefore a routing failure; it clears the destination and
/// emits a structured error log instead of panicking inside the reference path.
fn unsupported_io_cpu_ref(input: &[u8], output: &mut Vec<u8>) {
    output.clear();
    tracing::error!(
        target: "vyre::io_cpu_ref",
        input_len = input.len(),
        "unsupported Category C io CPU reference dispatch. Category C io ops require \
         a backend with zero-copy NVMe/GDS capability and have no portable CPU/reference \
         lowering. Fix: select or register a backend that advertises the `io` dialect \
         lowering, or reject the program during capability negotiation before invoking \
         cpu_ref."
    );
}

inventory::submit! {
    OpDefRegistration::new(|| OpDef {
        id: OP_DMA_FROM_NVME,
        dialect: "io",
        category: Category::Intrinsic,
        signature: SIG_DMA_FROM_NVME,
        lowerings: crate::LoweringTable::new(unsupported_io_cpu_ref),
        laws: &[],
        compose: None,
    })
}

inventory::submit! {
    OpDefRegistration::new(|| OpDef {
        id: OP_WRITE_BACK_TO_NVME,
        dialect: "io",
        category: Category::Intrinsic,
        signature: SIG_WRITE_BACK_TO_NVME,
        lowerings: crate::LoweringTable::new(unsupported_io_cpu_ref),
        laws: &[],
        compose: None,
    })
}

inventory::submit! {
    OpDefRegistration::new(|| OpDef {
        id: OP_ZEROCOPY_MAP,
        dialect: "io",
        category: Category::Intrinsic,
        signature: SIG_ZEROCOPY_MAP,
        lowerings: crate::LoweringTable::new(unsupported_io_cpu_ref),
        laws: &[],
        compose: None,
    })
}

inventory::submit! {
    OpDefRegistration::new(|| OpDef {
        id: OP_UNMAP,
        dialect: "io",
        category: Category::Intrinsic,
        signature: SIG_UNMAP,
        lowerings: crate::LoweringTable::new(unsupported_io_cpu_ref),
        laws: &[],
        compose: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{DialectRegistry, Target};

    #[test]
    fn every_io_op_registers() -> Result<(), String> {
        let reg = DialectRegistry::global();
        for op in [
            OP_DMA_FROM_NVME,
            OP_WRITE_BACK_TO_NVME,
            OP_ZEROCOPY_MAP,
            OP_UNMAP,
        ] {
            let id = reg.intern_op(op);
            let def = reg
                .lookup(id)
                .ok_or_else(|| {
                    format!(
                        "Fix: op `{op}` must register via inventory::submit!(OpDefRegistration{{...}}); restore the registration in this dialect."
                    )
                })?;
            assert_eq!(def.id, op);
            assert_eq!(def.category, Category::Intrinsic);
        }
        Ok(())
    }

    #[test]
    fn io_ops_have_no_gpu_lowering() {
        let reg = DialectRegistry::global();
        for op in [
            OP_DMA_FROM_NVME,
            OP_WRITE_BACK_TO_NVME,
            OP_ZEROCOPY_MAP,
            OP_UNMAP,
        ] {
            let id = reg.intern_op(op);
            // No backend opts into io ops yet; wgsl/spv/ptx/metal
            // lowerings are all None. The capability-negotiation
            // layer surfaces a `BackendError::Unsupported` in this
            // case (see B-B5 backend trait split for the checked
            // path).
            assert!(
                reg.get_lowering(id, Target::Wgsl).is_none(),
                "{op} must not carry a wgsl lowering until a backend opts in"
            );
        }
    }

    #[test]
    fn io_ops_cpu_ref_clears_output_without_panicking_if_called_directly() {
        let reg = DialectRegistry::global();
        for op in [
            OP_DMA_FROM_NVME,
            OP_WRITE_BACK_TO_NVME,
            OP_ZEROCOPY_MAP,
            OP_UNMAP,
        ] {
            let id = reg.intern_op(op);
            let def = reg.lookup(id).unwrap();
            let mut out = vec![0xAA];
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                (def.lowerings.cpu_ref)(&[1, 2, 3], &mut out);
            }))
            .expect("Category C io cpu_ref must never panic inside reference dispatch");
            assert!(
                out.is_empty(),
                "{op} cpu_ref must clear output before failing so callers cannot consume stale bytes"
            );
        }
    }

    #[test]
    fn io_dialect_is_distinct_from_stdlib() {
        let reg = DialectRegistry::global();
        let id = reg.intern_op(OP_DMA_FROM_NVME);
        let def = reg.lookup(id).unwrap();
        assert_eq!(def.dialect, "io");
    }
}
