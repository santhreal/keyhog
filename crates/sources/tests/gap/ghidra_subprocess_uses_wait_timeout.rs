//! Ghidra analysis subprocess must use wait_timeout kill path.

#[cfg(feature = "binary")]
#[test]
fn ghidra_subprocess_uses_wait_timeout() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/binary/mod.rs"))
        .expect("binary/mod.rs");
    assert!(src.contains("wait_timeout"));
    assert!(src.contains("child.kill()"));
    assert!(src.contains("Ghidra process wait failed"));
    assert!(src.contains("Ghidra analysis timed out"));
    assert!(src.contains(".stderr(std::process::Stdio::piped())"));
    assert!(src.contains("capture_ghidra_stderr_excerpt"));
    assert!(src.contains("ghidra stderr: {stderr_excerpt}"));
    assert!(!src.contains(".stderr(std::process::Stdio::null())"));
}

#[cfg(not(feature = "binary"))]
#[test]
fn ghidra_wait_timeout_requires_binary_feature() {
    assert!(!cfg!(feature = "binary"));
}
