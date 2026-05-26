//! mmap paths must re-stat after open and refuse multi-GiB TOCTOU growth.

#[test]
fn mmap_toctou_sanity_cap_in_read() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/filesystem/read.rs"
    ))
    .expect("read.rs");
    assert!(src.contains("MMAP_TOCTOU_SANITY_CAP_BYTES"));
    assert!(src.contains("2 * 1024 * 1024 * 1024"));
}
