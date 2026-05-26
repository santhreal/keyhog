use std::path::PathBuf;

#[test]
fn pipeline_directory_lists_lr2_modules() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/pipeline");
    assert!(dir.join("context_window.rs").is_file());
    assert!(dir.join("scan_loop.rs").is_file());
    assert!(dir.join("postprocess/mod.rs").is_file());
}
