//! Contract: `scripts/generate_contracts.py` pins the SAME detector count the
//! loader reports — single-sourced, no hardcoded literal.
//!
//! `generate_contracts.py` stamps `README_CLAIM` into every contract it
//! generates, so a stale count there silently poisons new contract TOMLs. The
//! count lives in exactly one place — `keyhog_core::load_detectors` (the same
//! path the CLI and README claim use). This gate derives that live count and
//! requires the script to advertise it, so adding a detector never leaves a
//! stale number in the generator (cf. the deleted `*_is_902` gates that baked
//! the count into their own filename and rotted).

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

/// `crates/scanner/../../detectors` — the on-disk Tier-B detector dir, computed
/// from `CARGO_MANIFEST_DIR` (same convention as the sibling contract gates).
fn detector_dir() -> PathBuf {
    repo_root().join("detectors")
}

#[test]
fn generate_contracts_script_claim_matches_loader() {
    let n = keyhog_core::load_detectors(&detector_dir())
        .expect("detectors/ must load")
        .len();

    let script = repo_root().join("scripts/generate_contracts.py");
    let text = std::fs::read_to_string(&script)
        .unwrap_or_else(|e| panic!("read {}: {e}", script.display()));

    let expected = format!("README_CLAIM = \"{n} service-specific detectors\"");
    assert!(
        text.contains(&expected),
        "generate_contracts.py must pin the live loader count: loader returned {n}, so \
         the script must contain {expected:?}. Bump scripts/generate_contracts.py's \
         README_CLAIM to {n} when the catalog changes — stale counts there poison every \
         newly generated contract TOML.",
    );
}
