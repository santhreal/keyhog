//! KH-GAP-010: Binary sources must not read unbounded file into RAM.

#[test]
fn binary_mod_uses_bounded_read_or_mmap() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/binary/mod.rs"
    ))
    .expect("binary/mod.rs");

    let has_mmap = src.contains("mmap") || src.contains("Mmap");
    let has_size_cap = src.contains("MAX_") || src.contains("max_bytes") || src.contains("limit");

    assert!(
        has_mmap || has_size_cap,
        "KH-GAP-010: binary source must document bounded read (mmap or explicit cap)"
    );

    // Current implementation loads full file — this gate fails until streaming lands.
    assert!(
        !src.contains("std::fs::read("),
        "KH-GAP-010: replace std::fs::read with bounded/mmap path for large binaries"
    );
}
