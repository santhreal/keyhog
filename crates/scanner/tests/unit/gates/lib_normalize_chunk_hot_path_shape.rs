//! Gate crate-root scan-text normalization against eager non-ASCII allocation.

#[test]
fn normalize_chunk_data_allocates_only_after_first_evasion_char() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs");
    let src = std::fs::read_to_string(path).expect("scanner lib source readable");
    let prod = src
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        prod.contains("let mut normalized: Option<String> = None;"),
        "normalize_chunk_data must stay lazy for clean non-ASCII text"
    );
    assert!(
        prod.contains("for (byte_pos, ch) in data.char_indices()"),
        "normalize_chunk_data must retain byte positions for safe borrowed-prefix rebuild"
    );
    assert!(
        prod.contains("out.push_str(&data[..byte_pos]);"),
        "normalize_chunk_data must copy only the already-proven-clean prefix when rebuilding"
    );
    assert!(
        !prod.contains("let mut normalized = String::with_capacity(data.len());"),
        "normalize_chunk_data must not allocate before proving an evasion char exists"
    );
    assert!(
        !prod.contains("let mut changed = false;"),
        "normalize_chunk_data must not scan clean non-ASCII text through an eager rebuild flag"
    );
}
