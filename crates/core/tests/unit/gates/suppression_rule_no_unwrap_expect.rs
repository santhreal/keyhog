//! Gate `suppression_rule`: no .unwrap( / .expect( in production source lines.

#[test]
fn suppression_rule_no_unwrap_expect() {
    for rel_path in &["src/suppression/mod.rs", "src/suppression/rule.rs"] {
        let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel_path);
        let src = std::fs::read_to_string(&path).expect("source readable");
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
            "{rel_path}: unwrap/expect in production source at {:?}",
            offenders.iter().take(5).collect::<Vec<_>>()
        );
    }
}
