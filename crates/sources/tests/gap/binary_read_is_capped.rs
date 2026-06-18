//! KH-GAP-010 closed: binary strings path uses capped read, not unbounded fs::read.

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
        !src.contains("MAX_BINARY_READ_BYTES"),
        "binary read cap must be owned by SourceLimits"
    );
    assert!(
        src.contains("binary_read_bytes") && src.contains("SourceTruncated"),
        "binary strings extraction must use resolved SourceLimits and surface capped partial reads"
    );
    let limits = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/limits.rs"))
        .expect("limits.rs readable");
    assert!(
        limits.contains("binary_read_bytes: 64 * 1024 * 1024"),
        "binary strings default cap must remain 64 MiB in SourceLimits"
    );
}
