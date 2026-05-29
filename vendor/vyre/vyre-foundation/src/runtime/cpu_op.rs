//! CPU reference execution contract for operation types.

use crate::ir_inner::model::program::Program;
pub use vyre_spec::CpuFn;

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

/// Failing CPU adapter for intrinsics whose existing reference accepts structured buffers.
///
/// This is the explicit reference-oracle sentinel for Category C ops whose
/// typed CPU reference is intentionally not exposed through the flat ABI. The
/// function clears the output buffer and panics with an actionable diagnostic.
/// Returning normally would create a production-shaped host execution escape
/// hatch where callers could accidentally consume an empty byte vector as a
/// valid result.
///
/// Each op can register its own CPU ref via `vyre-reference`, and
/// `DialectRegistry::get_lowering(ReferenceBackend)` dispatches to it
/// directly rather than going through this sentinel.
///
/// AUDIT_2026-05-23: Deprecated - panicking CPU sentinel is a fallback hole.
/// Category C ops must implement typed GPU lowerings instead.
#[deprecated(
    note = "structured_intrinsic_cpu is a panicking fallback. Implement typed GPU lowering for the op."
)]
pub fn structured_intrinsic_cpu(input: &[u8], output: &mut Vec<u8>) {
    output.clear();
    panic!(
        "structured intrinsic CPU adapter received {} flat input bytes, but no typed reference implementation is registered for this op. Fix: implement the op's typed reference in vyre-reference and dispatch via DialectRegistry::get_lowering(ReferenceBackend); production execution must select a concrete GPU/backend lowering before launch.",
        input.len()
    );
}

/// True when [`structured_intrinsic_cpu`] is set as an op's CPU lowering.
///
/// Conformance tooling uses this to flag operations that still expose only the
/// structured-reference sentinel, so parity status is recorded explicitly
/// instead of pretending a flat CPU adapter exists.
#[must_use]
pub fn is_cpu_reference_sentinel(f: CpuFn) -> bool {
    #[allow(deprecated)]
    std::ptr::fn_addr_eq(f, structured_intrinsic_cpu as CpuFn)
}

/// Compatibility wrapper for older conformance tooling.
#[deprecated(
    note = "use is_cpu_reference_sentinel; CPU reference sentinels are explicit oracles, not runtime fallbacks"
)]
#[must_use]
pub fn is_fallback_cpu_ref(f: CpuFn) -> bool {
    is_cpu_reference_sentinel(f)
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn is_cpu_reference_sentinel_detects_structured_intrinsic() {
        assert!(is_cpu_reference_sentinel(structured_intrinsic_cpu));
    }

    #[test]
    fn is_cpu_reference_sentinel_rejects_other_fn() {
        #[allow(clippy::ptr_arg)] // Must match `CpuFn` (`&mut Vec<u8>`), not `&mut [u8]`.
        fn custom_cpu(_input: &[u8], _output: &mut Vec<u8>) {}
        assert!(!is_cpu_reference_sentinel(custom_cpu));
    }

    #[test]
    fn structured_intrinsic_clears_output_and_panics() {
        let mut output = vec![1, 2, 3];
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            structured_intrinsic_cpu(b"input", &mut output);
        }))
        .expect_err("structured intrinsic CPU sentinel must not return normally");

        assert!(output.is_empty());
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .expect("Fix: structured intrinsic CPU sentinel panic should carry a message");
        assert!(message.contains("no typed reference implementation is registered"));
        assert!(
            message.contains("production execution must select a concrete GPU/backend lowering")
        );
    }
}
