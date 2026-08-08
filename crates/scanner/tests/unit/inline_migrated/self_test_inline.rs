//! Migrated from src/gpu/self_test.rs

use keyhog_scanner::gpu::verify_gpu_kernel_ownership_separation;

#[test]
fn test_gpu_kernel_ownership_separation_gate() {
    assert!(verify_gpu_kernel_ownership_separation().is_ok());
}
