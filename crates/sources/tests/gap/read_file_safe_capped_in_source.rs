//! KH-GAP-013 (A5): `read_file_safe` must not use unbounded `read_to_end`.

#[test]
fn read_file_safe_capped_in_source() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/filesystem/read.rs");
    let src = std::fs::read_to_string(path).expect("read read.rs");
    assert!(
        src.contains("MAX_BUFFERED_READ_BYTES"),
        "read_file_safe must define a hard byte cap"
    );
    assert!(
        src.contains(".take(MAX_BUFFERED_READ_BYTES)"),
        "read_file_safe must bound the read with take()"
    );
    assert!(
        !src.contains("read_to_end(&mut file, &mut bytes)?"),
        "unbounded read_to_end must be replaced with capped read"
    );
}
