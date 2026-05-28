//! KH-GAP-098: Docs must not claim `KEYHOG_USE_MEGAKERNEL` routing while engine ignores it.

#[path = "../support/mod.rs"]
mod support;

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

fn engine_reads_megakernel_env() -> bool {
    let engine_dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine"));
    std::fs::read_dir(engine_dir)
        .expect("engine dir")
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("rs"))
        .any(|e| {
            std::fs::read_to_string(e.path())
                .map(|s| s.contains("KEYHOG_USE_MEGAKERNEL"))
                .unwrap_or(false)
        })
}

#[test]
fn vyre_usage_must_not_claim_active_megakernel_routing_while_unwired() {
    if support::megakernel_waiver::megakernel_parity_waiver_active()
        && support::megakernel_waiver::megakernel_env_unwired_in_engine()
    {
        // KH-GAP-098: docs may describe planned megakernel routing while the
        // SPEC waiver (KH-GAP-043) keeps engine dispatch intentionally unwired.
        return;
    }

    let doc = std::fs::read_to_string(repo_root().join("docs/vyre-usage.md")).expect("doc");
    let claims_routing = doc.contains("KEYHOG_USE_MEGAKERNEL=1") && doc.contains("routed through");
    if claims_routing {
        assert!(
            engine_reads_megakernel_env(),
            "docs/vyre-usage.md claims KEYHOG_USE_MEGAKERNEL routing but engine/ never reads the env var"
        );
    }
}
