//! Gate `prefix_trie`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn prefix_trie_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/prefix_trie.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "prefix_trie: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "prefix_trie: todo!/unimplemented! forbidden in non-test source"
    );
}
