//! Ghidra analysis subprocess must use wait_timeout kill path.

#[cfg(feature = "binary")]
#[test]
fn ghidra_subprocess_uses_wait_timeout() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/binary/mod.rs"))
        .expect("binary/mod.rs");
    assert!(src.contains("wait_timeout"));
    assert!(src.contains("child.kill()"));
    assert!(src.contains("Ghidra analysis timed out"));
}

#[cfg(not(feature = "binary"))]
#[test]
fn ghidra_wait_timeout_requires_binary_feature() {
    assert!(!cfg!(feature = "binary"));
}
