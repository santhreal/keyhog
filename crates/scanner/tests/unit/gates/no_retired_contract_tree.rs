use std::path::Path;

#[test]
fn retired_contract_tree_stays_absent() {
    let tests_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let retired = tests_dir.join("contract_pending");

    assert!(
        !retired.exists(),
        "{} must not exist: detector coverage belongs in the live tests/contract module, tests/contracts corpus, or capability target-spec driver",
        retired.display()
    );
}

#[test]
fn live_contract_surfaces_exist() {
    let tests_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let capability_driver = tests_dir.join("capability_target_spec.rs");

    assert!(
        tests_dir.join("contract").join("mod.rs").is_file(),
        "tests/contract/mod.rs must own source-discovered contract modules"
    );
    assert!(
        tests_dir.join("contracts").is_dir(),
        "tests/contracts/ must own per-detector TOML fixture data"
    );
    assert!(
        capability_driver.is_file(),
        "tests/capability_target_spec.rs must wire target_spec capability contracts as a real Cargo target"
    );

    let driver = std::fs::read_to_string(&capability_driver)
        .unwrap_or_else(|e| panic!("read {}: {e}", capability_driver.display()));
    for module in [
        "capability_context_variants",
        "capability_decode_depth",
        "capability_unicode_evasion",
    ] {
        assert!(
            driver.contains(&format!("mod {module};")),
            "{} must wire target_spec/{module}.rs",
            capability_driver.display()
        );
    }
}
