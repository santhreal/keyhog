//! CPU reference execution contract for operation types.

use crate::ir_inner::model::program::Program;

/// CPU reference implementation for an operation.
pub trait CpuOp {
    /// Execute one flat byte payload and append the byte output to `output`.
    fn cpu(input: &[u8], output: &mut Vec<u8>);
}

/// Marker trait for Category A operations with an executable IR program.
pub trait CategoryAOp {
    /// Build the canonical Category A IR program.
    fn program() -> Program;
}

/// Function pointer used by Category C descriptors.
pub type CpuFn = fn(input: &[u8], output: &mut Vec<u8>);

/// CPU adapter for intrinsics whose existing reference accepts structured buffers.
///
/// This is the fall-through adapter for Category C ops that have NOT yet
/// wired their typed CPU reference into a flat ABI. The function clears
/// the output buffer and emits a structured error. Consumers (conform
/// runner, backend parity checks) treat a non-empty invocation of this
/// function as a signal that a per-op flat-ABI adapter is still missing.
///
/// Migration target: each op registers its own CPU ref via
/// `vyre-reference`, and `DialectRegistry::get_lowering(ReferenceBackend)` dispatches
/// to it directly rather than going through this fallback. A-B3 residue
/// work (Phase 9 in the 0.5.0 plan) walks every
/// `structured_intrinsic_cpu` site and replaces it with a typed adapter.
pub fn structured_intrinsic_cpu(input: &[u8], output: &mut Vec<u8>) {
    output.clear();
    tracing::error!(
        target: "vyre::cpu_ref_fallback",
        input_len = input.len(),
        "structured intrinsic CPU adapter received flat bytes; no typed reference implementation is registered for this op. Fix: implement the op's typed reference in vyre-reference and dispatch via DialectRegistry::get_lowering(ReferenceBackend) instead of this fallback."
    );
}

/// True when [`structured_intrinsic_cpu`] is set as an op's CPU lowering —
/// used by the conform runner to flag ops still on the fallback so their
/// parity status is recorded accurately rather than silently passing.
#[must_use]
pub fn is_fallback_cpu_ref(f: CpuFn) -> bool {
    std::ptr::fn_addr_eq(f, structured_intrinsic_cpu as CpuFn)
}
