//! The GitHub Marketplace requires the action metadata at the repository root
//! (`/action.yml`), but the canonical composite action historically lived at
//! `.github/actions/keyhog/action.yml` and still hosts `run-scan.sh`. Rather
//! than let two full copies drift, the root file is an EXACT mirror of the
//! inner file with only three path expressions rewritten for the shallower
//! root location. This test is the lock: it reconstructs the expected root
//! from the inner file and fails the moment either copy is edited without the
//! other, so a fix to the scan/resolution logic can never land in one and rot
//! in the other.
//!
//! The three deltas (and why):
//!  * `ACTION_SOURCE_ROOT` is `github.action_path` at the root (the checkout
//!    root itself) instead of `github.action_path/../../..` from three levels
//!    deep. Appears twice (version-resolve step, source-build step).
//!  * The scan step invokes `run-scan.sh`, which stays beside the inner action,
//!    so the root reaches it at `.github/actions/keyhog/run-scan.sh`.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <repo>/crates/cli
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/cli has a repo root two levels up")
        .to_path_buf()
}

const SOURCE_ROOT_FROM_INNER: &str = "${{ github.action_path }}/../../..";
const SOURCE_ROOT_AT_ROOT: &str = "${{ github.action_path }}";
const RUN_SCAN_FROM_INNER: &str = "${{ github.action_path }}/run-scan.sh";
const RUN_SCAN_AT_ROOT: &str = "${{ github.action_path }}/.github/actions/keyhog/run-scan.sh";

#[test]
fn root_action_is_the_locked_mirror_of_the_inner_action() {
    let root = repo_root();
    let inner_path = root.join(".github/actions/keyhog/action.yml");
    let root_path = root.join("action.yml");

    let inner = std::fs::read_to_string(&inner_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", inner_path.display()));
    let actual_root = std::fs::read_to_string(&root_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", root_path.display()));

    // The inner file must actually contain the expressions we rewrite, or the
    // mirror rule is stale.
    assert_eq!(
        inner.matches(SOURCE_ROOT_FROM_INNER).count(),
        2,
        "inner action.yml must set ACTION_SOURCE_ROOT via `{SOURCE_ROOT_FROM_INNER}` exactly twice; \
         the mirror rewrite rule is out of date"
    );
    assert_eq!(
        inner.matches(RUN_SCAN_FROM_INNER).count(),
        1,
        "inner action.yml must invoke `{RUN_SCAN_FROM_INNER}` exactly once; \
         the mirror rewrite rule is out of date"
    );

    let expected_root = inner
        .replace(SOURCE_ROOT_FROM_INNER, SOURCE_ROOT_AT_ROOT)
        .replace(RUN_SCAN_FROM_INNER, RUN_SCAN_AT_ROOT);

    assert_eq!(
        actual_root, expected_root,
        "root action.yml has drifted from the inner action.yml mirror. Edit \
         .github/actions/keyhog/action.yml (the canonical source), then \
         regenerate the root by rewriting only the three path expressions this \
         test documents. Do not hand-edit one copy alone."
    );
}
