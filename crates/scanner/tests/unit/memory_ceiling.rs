use crate::{
    enforce_cpu_scratch_ceiling, enforce_simd_scratch_ceiling, CPU_SCRATCH_CEILING_BYTES,
    SIMD_SCRATCH_CEILING_BYTES,
};

#[test]
fn cpu_scratch_allocation_ceiling_is_inclusive_and_overflow_safe() {
    assert!(enforce_cpu_scratch_ceiling(100 * 1024 * 1024).is_ok());
    assert!(enforce_cpu_scratch_ceiling(CPU_SCRATCH_CEILING_BYTES).is_ok());
    let err = enforce_cpu_scratch_ceiling(CPU_SCRATCH_CEILING_BYTES + 1).unwrap_err();
    assert!(err.to_string().contains("128MB ceiling"));
    assert!(enforce_cpu_scratch_ceiling(usize::MAX).is_err());
}

#[test]
fn simd_scratch_allocation_ceiling_is_inclusive_and_overflow_safe() {
    assert!(enforce_simd_scratch_ceiling(100 * 1024 * 1024).is_ok());
    assert!(enforce_simd_scratch_ceiling(SIMD_SCRATCH_CEILING_BYTES).is_ok());
    let err = enforce_simd_scratch_ceiling(SIMD_SCRATCH_CEILING_BYTES + 1).unwrap_err();
    assert!(err.to_string().contains("128MB ceiling"));
    assert!(enforce_simd_scratch_ceiling(usize::MAX).is_err());
}

/// Regression: a rejected scratch growth cannot reuse the prior chunk's active set.
#[test]
fn rejected_phase2_scratch_reset_clears_prior_generation() {
    use crate::engine::phase2::ActivePatternsScratch;

    let mut scratch = ActivePatternsScratch::new();
    scratch.begin(1).expect("initialize bounded scratch");
    scratch.mark(0);
    assert_eq!(scratch.active, vec![0]);

    let error = scratch
        .begin(usize::MAX)
        .expect_err("overflow-sized scratch must fail closed");
    assert!(error.to_string().contains("128MB ceiling"));
    assert!(scratch.active.is_empty());
    assert!(!scratch.is_active(0));
}
