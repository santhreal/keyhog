//! The "is this the newest stable release" predicate that decides whether a
//! release advances the floating pointers (`latest` image, `v<major>` tag) has
//! exactly one owner: `scripts/is-newest-stable-tag.sh`. It was previously a
//! byte-identical inline block copied into two release jobs; a drift between
//! the copies would move one pointer but not the other. This test fails if the
//! inline predicate reappears or if either job stops routing through the script.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <repo>/crates/cli
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/cli has a repo root two levels up")
        .to_path_buf()
}

#[test]
fn floating_tag_predicate_has_a_single_shell_owner() {
    let root = repo_root();

    let script = root.join("scripts/is-newest-stable-tag.sh");
    assert!(
        script.is_file(),
        "the single owner scripts/is-newest-stable-tag.sh must exist"
    );

    let release = std::fs::read_to_string(root.join(".github/workflows/release.yml"))
        .expect("read .github/workflows/release.yml");

    // Both advance-deciding steps route through the one script.
    assert_eq!(
        release.matches("bash scripts/is-newest-stable-tag.sh").count(),
        2,
        "both release jobs (latest-image + major-tag) must call the single \
         newest-stable helper; found a different count"
    );

    // The old inline predicate must not come back in any form. `advance=false`
    // and the hand-rolled `sort -V | tail` selection were the two tells of the
    // duplicated block; neither should appear in release.yml anymore.
    assert!(
        !release.contains("advance=false"),
        "the inline `advance=false` predicate reappeared in release.yml; \
         call scripts/is-newest-stable-tag.sh instead of re-inlining it"
    );
    assert!(
        !release.contains("sort -V | tail"),
        "the inline newest-tag selection (`sort -V | tail`) reappeared in \
         release.yml; it belongs only in scripts/is-newest-stable-tag.sh"
    );
}
