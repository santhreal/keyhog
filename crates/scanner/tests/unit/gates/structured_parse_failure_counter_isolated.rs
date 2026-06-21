//! Gate: exact structured parse-failure counter assertions must run isolated.

#[test]
fn structured_parse_failure_counter_isolated() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let standalone =
        std::fs::read_to_string(root.join("tests/regression_structured_parse_failure_counted.rs"))
            .expect("standalone structured parse-failure regression readable");
    let root_facade = std::fs::read_to_string(root.join("tests/unit/root_facade/mod.rs"))
        .expect("root_facade mod readable");

    assert!(
        standalone.contains("structured_parse_failure_count()")
            && standalone.contains("reset_for_scan()")
            && standalone.contains("scan_chunks_with_backend("),
        "structured parse-failure counter regression must assert exact public-scan telemetry"
    );
    assert!(
        !standalone.contains("testing::parse_")
            && !standalone.contains("parse_k8s_secret(")
            && !standalone.contains("parse_tfstate(")
            && !standalone.contains("parse_docker_compose(")
            && !standalone.contains("parse_jupyter("),
        "standalone regression must not depend on private parser facades"
    );
    assert!(
        !root_facade.contains("regression_structured_parse_failure_counted"),
        "exact process-global parse-failure counter test must not run inside the parallel root_facade aggregator"
    );
}
