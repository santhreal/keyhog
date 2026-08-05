#[test]
fn retired_per_rule_megakernel_modules_stay_out_of_production_engine() {
    let engine = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/engine");
    assert!(
        !engine.join("megakernel.rs").exists()
            && !engine.join("megakernel_triggers.rs").exists()
            && !engine.join("megakernel_wire.rs").exists(),
        "the production engine must not keep the retired per-rule megakernel catalog modules"
    );
}
