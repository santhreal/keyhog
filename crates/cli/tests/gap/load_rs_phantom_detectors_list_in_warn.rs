//! KH-GAP-146: `load.rs` warn text cited phantom `keyhog detectors list`
//! (KH-GAP-108 oracle only checked scan stderr from empty detectors dir).

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

#[test]
fn load_rs_warn_text_does_not_cite_phantom_detectors_list_subcommand() {
    let src =
        std::fs::read_to_string(repo_root().join("crates/core/src/spec/load.rs")).expect("load.rs");
    assert!(
        !src.contains("detectors list"),
        "load.rs must not cite phantom `keyhog detectors list`; use `keyhog detectors`"
    );
}
