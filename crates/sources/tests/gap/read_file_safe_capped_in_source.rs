//! KH-GAP-013 (A5): `read_file_safe` must not use unbounded `read_to_end`.

#[test]
fn read_file_safe_capped_in_source() {
    // `read.rs` was split into the `read/` module dir; read_file_safe and
    // its MAX_BUFFERED_READ_BYTES cap now live in `read/raw.rs`.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/filesystem/read/raw.rs");
    let src = std::fs::read_to_string(path).expect("read read/raw.rs");
    assert!(
        src.contains("MAX_BUFFERED_READ_BYTES"),
        "read_file_safe must define a hard byte cap"
    );
    assert!(
        src.contains("crate::capped_read::read_to_cap")
            && src.contains("MAX_BUFFERED_READ_BYTES")
            && src.contains("read.truncated")
            && src.contains("\"filesystem buffered read exceeded stat-time {} byte cap\""),
        "read_file_safe must route all buffered reads through the shared capped-read owner and reject stat-time growth"
    );
    assert!(
        !src.contains("read_to_end(&mut file, &mut bytes)?"),
        "unbounded read_to_end must be replaced with capped read"
    );
    assert!(
        !src.contains("let mut bytes = vec![0u8; cap]"),
        "read_file_safe must not preallocate attacker-sized stat hints"
    );
}
