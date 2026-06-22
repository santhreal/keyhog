//! Gate `dedup`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn dedup_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/dedup.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "dedup: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "dedup: todo!/unimplemented! forbidden in non-test source"
    );
    assert!(
        !prod.contains("sha256_hash("),
        "dedup must reuse RawMatch::credential_hash; recomputing SHA-256 in the dedup hot path is forbidden"
    );
}
