//! Stdin source must cap piped input to prevent unbounded allocation.

#[test]
fn stdin_max_bytes_cap_in_source() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/stdin.rs"))
        .expect("stdin.rs");
    assert!(
        src.contains("MAX_STDIN_BYTES"),
        "stdin cap constant required"
    );
    assert!(
        src.contains("reader.take(max_bytes as u64 + 1)"),
        "stdin read must use take() before read_to_end"
    );
    assert!(
        src.contains("10 * 1024 * 1024"),
        "stdin cap must remain 10 MiB"
    );
}
