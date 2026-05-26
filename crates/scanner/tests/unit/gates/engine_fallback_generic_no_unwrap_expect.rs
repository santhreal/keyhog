//! Gate `engine::fallback_generic`: no .unwrap( / .expect( in production source lines.

#[test]
fn engine_fallback_generic_no_unwrap_expect() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/fallback_generic.rs"
    );
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
        "engine::fallback_generic: unwrap/expect in production source at {:?}",
        offenders.iter().take(5).collect::<Vec<_>>()
    );
}
