//! Stdin source must cap piped input to prevent unbounded allocation.

#[test]
fn stdin_max_bytes_cap_in_source() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/stdin.rs"))
        .expect("stdin.rs");
    assert!(
        !src.contains("MAX_STDIN_BYTES"),
        "stdin cap must be owned by SourceLimits, not a private source constant"
    );
    assert!(
        src.contains("reader.take(max_bytes as u64 + 1)"),
        "stdin read must use take() before read_to_end"
    );
    assert!(
        src.contains("SourceLimits::default().stdin_bytes") && src.contains("with_limits"),
        "stdin source must accept resolved SourceLimits"
    );

    let limits = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/limits.rs"))
        .expect("limits.rs");
    assert!(
        limits.contains("stdin_bytes: 10 * 1024 * 1024"),
        "stdin default cap must remain 10 MiB in the shared SourceLimits owner"
    );
}
