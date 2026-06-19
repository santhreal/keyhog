//! Gate `orchestrator_config`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn orchestrator_config_non_empty() {
    for path in [
        concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator_config.rs"),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/orchestrator_config/detectors.rs"
        ),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/orchestrator_config/effective.rs"
        ),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/orchestrator_config/runtime.rs"
        ),
    ] {
        let src = std::fs::read_to_string(path).expect("source readable");
        assert!(
            src.trim().len() >= 20,
            "{path}: expected substantive source, got {} trimmed bytes",
            src.trim().len()
        );
        let prod = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
            "{path}: todo!/unimplemented! forbidden in non-test source"
        );
    }
}
