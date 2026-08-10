//! Migrated from src/gpu/self_test.rs

use keyhog_scanner::gpu::{
    verify_gpu_kernel_ownership_separation, verify_gpu_kernel_ownership_separation_at_path,
};

#[test]
fn test_gpu_kernel_ownership_separation_gate() {
    assert!(verify_gpu_kernel_ownership_separation().is_ok());
}

#[test]
fn test_gpu_kernel_ownership_detects_prohibited_kernel_artifact() {
    let temp_dir = tempfile::tempdir().unwrap();
    let kernel_file = temp_dir.path().join("scan_kernel.wgsl");
    std::fs::write(&kernel_file, "// shader code").unwrap();

    let err = verify_gpu_kernel_ownership_separation_at_path(temp_dir.path()).unwrap_err();
    assert!(err.contains("KeyHog repository contains prohibited GPU kernel file"));
    assert!(err.contains("scan_kernel.wgsl"));
}

#[test]
fn source_artifact_enumerator_rejects_every_kernel_format_sibling() {
    for extension in ["wgsl", "ptx", "cu", "spv", "metal", "hlsl"] {
        let temp_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            temp_dir.path().join(format!("forbidden.{extension}")),
            "kernel",
        )
        .unwrap();
        assert!(
            verify_gpu_kernel_ownership_separation_at_path(temp_dir.path()).is_err(),
            "{extension} must be rejected"
        );
    }
}
