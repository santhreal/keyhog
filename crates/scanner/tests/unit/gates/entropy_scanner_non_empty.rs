//! Gate `entropy::scanner`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn entropy_scanner_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/entropy/scanner.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "entropy::scanner: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "entropy::scanner: todo!/unimplemented! forbidden in non-test source"
    );
    for forbidden in [
        "!seen.insert(candidate.to_string())",
        "!seen.insert(candidate.clone())",
    ] {
        assert!(
            !prod.contains(forbidden),
            "entropy::scanner must borrow-check dedup before allocating: {forbidden}"
        );
    }
    for required in [
        "seen.contains(candidate)",
        "seen.contains(candidate.as_str())",
    ] {
        assert!(
            prod.contains(required),
            "entropy::scanner must keep borrow-first dedup check {required}"
        );
    }
}
