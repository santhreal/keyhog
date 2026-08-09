//! Migrated from src/gpu/self_test.rs

use keyhog_scanner::gpu::{verify_gpu_kernel_ownership_separation, verify_gpu_kernel_symbols};

#[test]
fn test_gpu_kernel_ownership_separation_gate() {
    assert!(verify_gpu_kernel_ownership_separation().is_ok());
}

#[test]
fn test_gpu_kernel_symbols_allowed_vyre() {
    let allowed = ["vyre::scan::GpuLiteralSet", "vyre_driver_wgpu::WgpuBackend"];
    assert!(verify_gpu_kernel_symbols(&allowed).is_ok());
}

#[test]
fn test_gpu_kernel_symbols_rejects_forbidden_keyhog_symbol() {
    let forbidden = ["keyhog::gpu_kernel::custom_ptx"];
    let err = verify_gpu_kernel_symbols(&forbidden).unwrap_err();
    assert!(
        err.contains("KeyHog owns non-VYRE GPU dispatch symbol: keyhog::gpu_kernel::custom_ptx")
    );
}

#[test]
fn test_gpu_kernel_symbols_rejects_empty() {
    let empty: [&str; 0] = [];
    let err = verify_gpu_kernel_symbols(&empty).unwrap_err();
    assert_eq!(err, "No GPU dispatch symbols registered");
}
