//! Gate `orchestrator_config`: no .unwrap( / .expect( in production source lines.

#[test]
fn orchestrator_config_no_unwrap_expect() {
    for path in [
        concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator_config.rs"),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/orchestrator_config/detectors.rs"
        ),
    ] {
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
            "{path}: unwrap/expect in production source at {:?}",
            offenders.iter().take(5).collect::<Vec<_>>()
        );
    }
}
