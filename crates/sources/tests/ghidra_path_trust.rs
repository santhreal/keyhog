#[test]
fn ghidra_discovery_does_not_use_env_or_path_which() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let ghidra =
        std::fs::read_to_string(root.join("src/binary/ghidra.rs")).expect("read ghidra source");

    assert!(
        ghidra.contains(r#"resolve_safe_bin("analyzeHeadless")"#),
        "custom Ghidra support dirs must flow through [system].trusted_bin_dirs"
    );
    assert!(
        !ghidra.contains(r#"std::env::var("GHIDRA_HOME")"#),
        "GHIDRA_HOME must not alter source extraction behavior"
    );
    assert!(
        !ghidra.contains(r#"resolve_safe_bin("which")"#)
            && !ghidra.contains(r#"Command::new(&which_bin)"#)
            && !ghidra.contains(r#".arg("analyzeHeadless")"#),
        "Ghidra discovery must not shell through which/PATH"
    );
}
