//! Descriptor-level validation and analysis before concrete CUDA PTX emission.

use vyre_foundation::ir::Program;

pub(crate) fn validate_and_analyze(
    program: &Program,
    target_sm: u32,
) -> Result<vyre_lower::KernelDescriptor, String> {
    // Pre-lowering optimization is handled by the canonical
    // `prepare_program_for_emit` pipeline in `lower_for_cuda_emit`.
    // Calling the Program-level optimizer here would violate the
    // rewrite layer contract (emit/driver crates must not host
    // Program-IR optimizer passes).
    let descriptor = lower_for_cuda_emit(program)?;
    if let Err(errors) = vyre_lower::verify::verify(&descriptor) {
        return Err(format!(
            "canonical pre-emit lowering failed before CUDA PTX emission: descriptor verification failed for {:?}: {errors:?}. Fix: repair the source Program (workgroup_size axes must be > 0, binding slot ids must be unique, result ids must be unique within each body) before calling the CUDA driver.",
            descriptor
        ));
    }
    if crate::instrumentation::cuda_descriptor_audit_enabled() {
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
    if crate::instrumentation::cuda_canonical_preemit_enabled() {
        let prepared = vyre_lower::prepare_program_for_emit(program)
            .map_err(|error| {
                format!(
                    "canonical pre-emit Program preparation failed before CUDA PTX emission: {error}. Fix: repair call inlining or semantic Program optimization before concrete CUDA lowering."
                )
            })?;
        return vyre_lower::lower(&prepared).map_err(|error| {
            format!(
                "canonical pre-emit lowering failed before CUDA PTX emission: {error}. Fix: add the missing neutral descriptor mapping before concrete PTX emission."
            )
        });
    }

    let trace = crate::instrumentation::cuda_stage_trace_enabled();
    let start = std::time::Instant::now();
    let descriptor = vyre_lower::lower(program).map_err(|error| {
        format!(
            "CUDA fast descriptor lowering failed: {error}. Fix: add the missing neutral descriptor mapping before concrete PTX emission."
        )
    })?;
    if let Err(errors) = vyre_lower::verify::verify(&descriptor) {
        return Err(format!(
            "canonical pre-emit lowering failed before CUDA PTX emission: descriptor verification failed for {:?}: {errors:?}. Fix: repair the source Program (workgroup_size axes must be > 0, binding slot ids must be unique, result ids must be unique within each body) before calling the CUDA driver.",
            descriptor
        ));
    }
    if trace {
        tracing::debug!(
            "[cuda-codegen] +{}ms lower ops={} bindings={}",
            start.elapsed().as_millis(),
            descriptor.body.ops.len(),
            descriptor.bindings.slots.len()
        );
    }
    if !crate::instrumentation::cuda_descriptor_rewrites_enabled() {
        return Ok(descriptor);
    }
    let optimized = run_cuda_descriptor_rewrites(&descriptor)?;
    if trace {
        tracing::debug!(
            "[cuda-codegen] +{}ms descriptor_rewrites ops={} bindings={}",
            start.elapsed().as_millis(),
            optimized.body.ops.len(),
            optimized.bindings.slots.len()
        );
    }
    Ok(optimized)
}

fn run_cuda_descriptor_rewrites(
    descriptor: &vyre_lower::KernelDescriptor,
) -> Result<vyre_lower::KernelDescriptor, String> {
    let mut current = descriptor.clone();
    for _ in 0..vyre_lower::rewrites::RUN_ALL_MAX_ITERS {
        let mut changed = false;
        for pass in vyre_lower::rewrites::canonical_rewrite_passes() {
            if matches!(pass.name, "cmp_normalize" | "cmp_normalize_post_saturation") {
                continue;
            }
            let next = (pass.rewrite)(&current);
            if next != current {
                if let Err(errors) = vyre_lower::verify::verify(&next) {
                    return Err(format!(
                        "CUDA descriptor rewrite `{}` produced an invalid KernelDescriptor: {errors:?}. Fix: repair the rewrite pass or disable it explicitly only while debugging.",
                        pass.name
                    ));
                }
                current = next;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    Ok(current)
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

        let descriptor =
            validate_and_analyze(&program, 90).expect("Fix: descriptor gate must pass");

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

    #[test]
    fn descriptor_rewrites_are_release_default_not_opt_in() {
        let descriptor_source = include_str!("descriptor_gate.rs");
        let instrumentation_source = include_str!("../instrumentation.rs");

        assert!(
            instrumentation_source.contains("CUDA_DESCRIPTOR_REWRITES_ENV")
                && instrumentation_source.contains("\"VYRE_CUDA_DESCRIPTOR_REWRITES\"")
                && instrumentation_source.contains("cached_enabled_default_true")
                && instrumentation_source
                    .contains("matches!(value, \"0\" | \"false\" | \"FALSE\" | \"off\" | \"OFF\")")
                && descriptor_source.contains("cuda_descriptor_rewrites_enabled()"),
            "Fix: CUDA descriptor rewrites must be default-on with only an explicit debug disable."
        );
        assert!(
            !instrumentation_source.contains(concat!(
                "var_os(\"VYRE_CUDA_DESCRIPTOR_REWRITES\")",
                ".is_none()"
            )),
            "Fix: CUDA descriptor rewrites must not be opt-in on the release path."
        );
    }

    #[test]
    fn canonical_preemit_lowering_is_release_default_not_opt_in() {
        let descriptor_source = include_str!("descriptor_gate.rs");
        let instrumentation_source = include_str!("../instrumentation.rs");

        assert!(
            instrumentation_source.contains("CUDA_CANONICAL_PREEMIT_ENV")
                && instrumentation_source.contains("\"VYRE_CUDA_CANONICAL_PREEMIT\"")
                && instrumentation_source.contains("cached_enabled_default_true")
                && instrumentation_source.contains(
                    "matches!(value, \"0\" | \"false\" | \"FALSE\" | \"off\" | \"OFF\")"
                )
                && descriptor_source.contains("cuda_canonical_preemit_enabled()"),
            "Fix: CUDA canonical pre-emit lowering must be default-on with only an explicit debug disable."
        );
        assert!(
            !instrumentation_source.contains(concat!(
                "var_os(\"VYRE_CUDA_CANONICAL_PREEMIT\")",
                ".is_some()"
            )),
            "Fix: CUDA canonical pre-emit lowering must not be an opt-in release-path gate."
        );
    }

    #[test]
    fn cuda_descriptor_rewrites_preserve_comparison_opcode_direction() {
        let source = include_str!("descriptor_gate.rs");

        assert!(
            source.contains("\"cmp_normalize\" | \"cmp_normalize_post_saturation\""),
            "Fix: CUDA descriptor rewrites must skip comparison normalization so PTX preserves concrete comparison opcode direction."
        );
    }

    #[test]
    fn descriptor_rewrite_convergence_does_not_clone_whole_descriptor_each_iteration() {
        let source = include_str!("descriptor_gate.rs");

        assert!(
            source.contains("let mut changed = false;") && source.contains("if !changed"),
            "Fix: CUDA descriptor rewrite convergence must use a changed flag, not a full KernelDescriptor clone per iteration."
        );
        assert!(
            !source.contains(concat!("let before = current", ".clone()")),
            "Fix: descriptor rewrite convergence must not clone the whole descriptor before every pass sweep."
        );
    }
}
