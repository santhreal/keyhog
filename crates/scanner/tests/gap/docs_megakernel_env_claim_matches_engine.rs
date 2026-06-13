//! KH-GAP-098: docs must not claim live `KEYHOG_USE_MEGAKERNEL` routing while
//! the engine ignores it. While the KH-GAP-043 SPEC waiver is active AND the
//! engine reads no such env var, `docs/vyre-usage.md` MAY describe the planned
//! megakernel routing (it is documented-as-planned, not documented-as-live).
//! Once the waiver lapses or the engine starts reading the env, any doc that
//! claims active routing must be backed by an engine that actually reads it —
//! otherwise the docs lie (COHERENCE vector / Law 10: no silently-stale claim).
//!
//! The waiver + env-unwired predicates live in the shared
//! `tests/support/megakernel_waiver.rs` helper (registered as KH-GAP-103);
//! pulled here directly via `#[path]` so this gap module needs only the helper,
//! not the whole `support` tree, inside the aggregated `all_tests` binary.

#[path = "../support/megakernel_waiver.rs"]
mod megakernel_waiver;

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

#[test]
fn vyre_usage_must_not_claim_active_megakernel_routing_while_unwired() {
    // Documented-as-planned is allowed while the waiver is active and the engine
    // genuinely reads no `KEYHOG_USE_MEGAKERNEL` env var.
    if megakernel_waiver::megakernel_parity_waiver_active()
        && megakernel_waiver::megakernel_env_unwired_in_engine()
    {
        return;
    }

    // Otherwise: if the doc claims active routing, the engine MUST read the env.
    let doc = std::fs::read_to_string(repo_root().join("docs/vyre-usage.md")).expect("doc");
    let claims_routing = doc.contains("KEYHOG_USE_MEGAKERNEL=1") && doc.contains("routed through");
    if claims_routing {
        assert!(
            !megakernel_waiver::megakernel_env_unwired_in_engine(),
            "docs/vyre-usage.md claims KEYHOG_USE_MEGAKERNEL routing but engine/ never reads the env var"
        );
    }
}
