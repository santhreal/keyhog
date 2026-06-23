//! Gate `finding`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn finding_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/finding.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "finding: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "finding: todo!/unimplemented! forbidden in non-test source"
    );
    assert!(
        prod.contains("Cow::<'de, str>::deserialize(deserializer)?")
            && prod.contains("hex::decode_to_slice(s.as_bytes(), &mut bytes)")
            && !prod.contains("let bytes = hex::decode(&s)")
            && !prod.contains("String::deserialize(deserializer).map(Arc::from)")
            && !prod.contains("Option::<String>::deserialize(deserializer)"),
        "finding: deserialization adapters must borrow input strings and decode credential_hash into a stack array"
    );
    assert!(
        src.contains("pub struct RawMatchDedupKey<'a>")
            && src.contains("pub(crate) fn deduplication_key(&self) -> RawMatchDedupKey<'_>")
            && src.contains("detector_id: &self.detector_id")
            && src.contains("credential: &self.credential")
            && !src.contains("pub(crate) fn deduplication_key(&self) -> (&str, &str)"),
        "finding: raw-match deduplication identity should be a named key, not an anonymous tuple"
    );
}
