//! Ghidra decompiled output must be capped before parsing.

#[cfg(feature = "binary")]
#[test]
fn binary_max_decompiled_cap_in_source() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/binary/mod.rs"))
        .expect("binary/mod.rs");
    assert!(
        !src.contains("MAX_DECOMPILED_SIZE"),
        "Ghidra output cap must be owned by SourceLimits"
    );
    assert!(src.contains("binary_decompiled_bytes"));
    let limits = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/limits.rs"))
        .expect("limits.rs");
    assert!(limits.contains("binary_decompiled_bytes: 50 * 1024 * 1024"));
}

#[cfg(not(feature = "binary"))]
#[test]
fn binary_decompiled_cap_requires_binary_feature() {
    assert!(!cfg!(feature = "binary"));
}
