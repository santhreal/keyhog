//! Gate `checksum::npm`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn checksum_npm_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/checksum/npm.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "checksum::npm: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "checksum::npm: todo!/unimplemented! forbidden in non-test source"
    );
    assert!(
        prod.contains("fn decode_pypi_payload(")
            && !prod.contains(".or_else(|_|")
            && !prod.contains("URL_SAFE_NO_PAD, payload")
            && !prod.contains("STANDARD_NO_PAD, payload"),
        "checksum::npm must classify PyPI base64 alphabet/padding once instead of retrying every decoder"
    );
}
