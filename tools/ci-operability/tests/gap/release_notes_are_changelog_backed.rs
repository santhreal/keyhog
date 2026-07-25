//! Release and prerelease entry points must consume one validated changelog section.

use super::support::{read_workflow, repo_root};
use std::process::Command;

/// Locks out publishing a placeholder body or allowing a tag through prerelease
/// checks when its exact changelog section has no substantive release notes.
#[test]
fn release_entrypoints_require_exact_changelog_backed_notes() {
    let workflow = read_workflow("release.yml");
    let prerelease = std::fs::read_to_string(repo_root().join("scripts/prerelease.sh"))
        .expect("read scripts/prerelease.sh");

    assert!(
        workflow.contains("scripts/release_notes.py")
            && workflow.contains("--tag \"$tag\"")
            && workflow.contains("--changelog \"$GITHUB_WORKSPACE/CHANGELOG.md\"")
            && workflow.contains("--output \"$workdir/release-notes.md\"")
            && workflow.contains("--notes-file \"$workdir/release-notes.md\"")
            && workflow.contains("--commit \"${{ steps.source.outputs.commit }}\""),
        "release.yml must render the exact tagged changelog section and pass that file to the immutable-ID publisher"
    );
    assert!(
        prerelease.contains("RELEASE_VERSION=\"${BUMP:-$CUR}\"")
            && prerelease.contains("python3 -B scripts/release_notes.py")
            && prerelease.contains("--tag \"v$RELEASE_VERSION\"")
            && prerelease.contains("--changelog CHANGELOG.md")
            && prerelease.contains("--output /dev/null"),
        "prerelease.sh must reject missing or placeholder notes for the actual current or bumped release version"
    );
}

/// Exercise changelog extraction and exact-ID publication through local files
/// and an in-process fake GitHub API, including tag drift and rollback failures.
#[test]
fn release_notes_and_asset_publication_are_behaviorally_fail_closed() {
    let output = Command::new("python3")
        .args([
            "-B",
            "-m",
            "unittest",
            "scripts.tests.test_release_notes",
            "scripts.tests.test_publish_release_assets",
        ])
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .current_dir(repo_root())
        .output()
        .expect("run behavioral release publication suites");
    assert!(
        output.status.success(),
        "behavioral release publication suites failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
