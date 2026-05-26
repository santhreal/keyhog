//! Gate `value_parsers`: no .unwrap( / .expect( in production source lines.

#[test]
fn value_parsers_no_unwrap_expect() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/value_parsers.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let mut offenders: Vec<(usize, &str)> = Vec::new();
    for (i, line) in src.lines().enumerate() {
        let t = line.trim();
        if t.starts_with("//") || t.contains("#[cfg(test)]") {
            continue;
        }
        if t.contains(".unwrap(") || t.contains(".expect(") {
            offenders.push((i + 1, line));
        }
    }
    assert!(
        offenders.is_empty(),
        "value_parsers: unwrap/expect in production source at {:?}",
        offenders.iter().take(5).collect::<Vec<_>>()
    );
}
