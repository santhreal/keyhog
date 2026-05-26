//! LR2-A8 harness integration: A3 gap gates present in gap/mod.rs

#[test]
fn gap_mod_lists_a3_bar_miss_gates() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/gap/mod.rs"),
    ).expect("gap/mod.rs");
    for m in [
        "no_inline_tests_in_a3_slice",
        "decode_pipeline_exceeds_modularity_cap",
        "pipeline_hot_path_allocs",
        "single_line_implicit_concat_not_appended",
        "pipeline_exceeds_modularity_cap",
    ] {
        assert!(src.contains(&format!("pub mod {m};")), "gap/mod.rs missing {m}");
    }
}
