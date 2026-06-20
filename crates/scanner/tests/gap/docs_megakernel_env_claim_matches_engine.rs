//! KH-GAP-098: docs must not resurrect `KEYHOG_USE_MEGAKERNEL` routing claims.
//! The production GPU path is region-presence plus GPU regex-DFA admission, not
//! the retired per-rule megakernel catalog or an env-selected side route.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

#[test]
fn vyre_usage_must_not_claim_retired_keyhog_use_megakernel_routing() {
    let doc = std::fs::read_to_string(repo_root().join("docs/vyre-usage.md")).expect("doc");
    assert!(
        !doc.contains("KEYHOG_USE_MEGAKERNEL"),
        "docs/vyre-usage.md must not document retired KEYHOG_USE_MEGAKERNEL routing"
    );
}

#[test]
fn production_engine_must_not_read_retired_keyhog_use_megakernel_env() {
    let engine_dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine"));
    for entry in std::fs::read_dir(engine_dir).expect("engine dir readable") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("engine source readable");
        assert!(
            !src.contains("KEYHOG_USE_MEGAKERNEL"),
            "production engine source must not read retired KEYHOG_USE_MEGAKERNEL routing env: {}",
            path.display()
        );
    }
}
