//! Gate `entropy_avx512`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn entropy_avx512_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/entropy/avx512.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "entropy_avx512: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "entropy_avx512: todo!/unimplemented! forbidden in non-test source"
    );
}
