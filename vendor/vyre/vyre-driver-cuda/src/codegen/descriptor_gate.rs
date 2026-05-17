//! Descriptor-level validation and analysis before concrete CUDA PTX emission.

use vyre_foundation::ir::Program;

pub(crate) fn validate_and_analyze(
    program: &Program,
    target_sm: u32,
) -> Result<vyre_lower::KernelDescriptor, String> {
    let descriptor = lower_for_cuda_emit(program)?;
    if std::env::var_os("VYRE_CUDA_DESCRIPTOR_AUDIT").is_some() {
        let neutral = vyre_lower::audit::audit(&descriptor);
        let concrete =
            vyre_emit_ptx::patterns::audit_optimized(&descriptor, compute_capability(target_sm));
        tracing::trace!(
            target: "vyre_driver_cuda::descriptor",
            kernel = %descriptor.id,
            neutral = %neutral.format_short(),
            concrete = %concrete.format_short(),
            "descriptor analysis completed before CUDA PTX emission",
        );
    }
    Ok(descriptor)
}

fn lower_for_cuda_emit(program: &Program) -> Result<vyre_lower::KernelDescriptor, String> {
    if std::env::var_os("VYRE_CUDA_CANONICAL_PREEMIT").is_some() {
        return vyre_lower::lower_for_emit(program)
            .map(|lowered| lowered.descriptor)
            .map_err(|error| {
                format!(
                    "canonical pre-emit lowering failed before CUDA PTX emission: {error}. Fix: route Programs through vyre-lower::lower_for_emit and add missing neutral mappings there instead of concrete-driver lowering."
                )
            });
    }

    let trace = std::env::var_os("VYRE_CUDA_STAGE_TRACE").is_some();
    let start = std::time::Instant::now();
    let descriptor = vyre_lower::lower(program).map_err(|error| {
        format!(
            "CUDA fast descriptor lowering failed: {error}. Fix: add the missing neutral descriptor mapping before concrete PTX emission."
        )
    })?;
    if trace {
        eprintln!(
            "[cuda-codegen] +{}ms lower ops={} bindings={}",
            start.elapsed().as_millis(),
            descriptor.body.ops.len(),
            descriptor.bindings.slots.len()
        );
    }
    if std::env::var_os("VYRE_CUDA_DESCRIPTOR_REWRITES").is_none() {
        return Ok(descriptor);
    }
    let optimized = vyre_lower::rewrites::run_all(&descriptor);
    if trace {
        eprintln!(
            "[cuda-codegen] +{}ms descriptor_rewrites ops={} bindings={}",
            start.elapsed().as_millis(),
            optimized.body.ops.len(),
            optimized.bindings.slots.len()
        );
    }
    Ok(optimized)
}

pub(crate) fn compute_capability(target_sm: u32) -> vyre_emit_ptx::ComputeCapability {
    vyre_emit_ptx::ComputeCapability {
        major: target_sm / 10,
        minor: target_sm % 10,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Ident, Node, Program};

    #[test]
    fn validates_simple_store_program() {
        let buffer =
            BufferDecl::storage("out", 0, BufferAccess::ReadWrite, DataType::U32).with_count(16);
        let program = Program::wrapped(
            vec![buffer],
            [128, 1, 1],
            vec![Node::Store {
                buffer: Ident::from("out"),
                index: Expr::InvocationId { axis: 0 },
                value: Expr::LitU32(9),
            }],
        );

        let descriptor = validate_and_analyze(&program, 90).expect("descriptor gate must pass");

        assert_eq!(descriptor.dispatch.workgroup_size, [128, 1, 1]);
        assert_eq!(descriptor.bindings.slots.len(), 1);
        assert!(vyre_lower::verify::verify(&descriptor).is_ok());
    }

    #[test]
    fn rejects_descriptor_verification_failures() {
        let program = Program::wrapped(Vec::new(), [1, 0, 1], Vec::new());

        let error = validate_and_analyze(&program, 90).expect_err("zero dispatch must fail");

        assert!(error.contains("canonical pre-emit lowering failed"));
        assert!(error.contains("KernelDescriptor"));
        assert!(error.contains("Fix:"));
    }

    #[test]
    fn maps_sm_number_to_compute_capability() {
        let cc = compute_capability(89);
        assert_eq!(cc.major, 8);
        assert_eq!(cc.minor, 9);
    }
}
