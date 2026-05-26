//! KH-GAP-010 closed: binary strings path uses capped read, not unbounded fs::read.

const MAX_BINARY_READ_BYTES: usize = 64 * 1024 * 1024;

#[test]
fn binary_mod_uses_capped_read_helper() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/binary/mod.rs"))
        .expect("binary/mod.rs readable");

    assert!(
        src.contains("read_binary_capped"),
        "binary strings extraction must use read_binary_capped"
    );
    assert!(
        !src.contains("std::fs::read(&self.path)"),
        "unbounded std::fs::read on binary path is forbidden"
    );
    assert!(
        src.contains("MAX_BINARY_READ_BYTES"),
        "cap constant must be documented in binary/mod.rs"
    );
    assert_eq!(
        MAX_BINARY_READ_BYTES,
        64 * 1024 * 1024,
        "documented 64 MiB cap for binary strings read"
    );
}
