//! Release publication must update crates.io from the same immutable versioned source.

use super::support::{read_workflow, repo_root};
use std::{fs, process::Command};

/// Locks out releases that publish binaries but leave crates.io stale, allow an
/// automatic release-event bypass, publish from a branch checkout, skip an internal
/// crate, or accept bytes not verified against the exact packaged archive.
#[test]
fn published_release_updates_every_crate_from_the_exact_tag() {
    let workflow = read_workflow("publish-crates.yml");
    let release_workflow = read_workflow("release.yml");

    assert!(
        !workflow.contains("release:\n")
            && workflow.contains("workflow_call:")
            && workflow.contains("workflow_dispatch:")
            && workflow.contains("KEYHOG_MANUAL_TAG: ${{ inputs.tag }}")
            && !workflow.contains("github.event.release"),
        "crates publication must have no standalone release-event bypass and permit only reusable or explicit exact-tag recovery entry"
    );
    assert!(
        workflow.contains("workflow_call:")
            && release_workflow.contains("uses: ./.github/workflows/publish-crates.yml")
            && release_workflow.contains("needs: publish")
            && release_workflow.contains("tag: ${{ needs.publish.outputs.tag }}")
            && release_workflow
                .contains("CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}"),
        "only the final verified public release may call the reusable crate publisher because GITHUB_TOKEN publication does not emit another workflow run"
    );
    assert!(
        workflow.contains("group: keyhog-crates-io")
            && workflow.contains("cancel-in-progress: false"),
        "irreversible crate uploads must be globally serialized and never cancelled in progress"
    );
    let credential = "CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}";
    assert!(
        workflow.matches(credential).count() == 2
            && workflow.contains(
                "Require crates.io credential\n        shell: bash\n        env:\n          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}",
            )
            && workflow.contains(
                "Publish and verify every workspace crate\n        shell: bash\n        env:\n          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}",
            )
            && workflow.contains("-z \"${CARGO_REGISTRY_TOKEN:-}\""),
        "the credential must be required but scoped away from checkout, setup, gates, packaging, and tagged build scripts"
    );
    assert!(
        workflow.matches("CRATES_IO_POLL_INITIAL_SECONDS:").count() == 1
            && workflow.matches("CRATES_IO_POLL_MAX_SECONDS:").count() == 1
            && workflow.matches("CRATES_IO_POLL_TIMEOUT_SECONDS:").count() == 1
            && !workflow.contains("WAIT_BETWEEN_PUBLISH"),
        "the publisher must use one bounded exact-version polling configuration and no fixed post-publication wait"
    );
    let verdict = workflow
        .find("Require immutable published release verdict")
        .expect("public release verdict step");
    let credential_step = workflow
        .find("Require crates.io credential")
        .expect("credential step");
    assert!(
        verdict < credential_step
            && workflow.contains("automation/scripts/verify_published_release.py")
            && workflow.contains("--expected-commit \"$KEYHOG_EXPECTED_COMMIT\"")
            && workflow.contains("--expected-tag-object \"$KEYHOG_EXPECTED_TAG_OBJECT\"")
            && !workflow.contains("KEYHOG_PUBLISHED_RELEASE_ID")
            && workflow.contains("cargo install rsign2 --version 0.6.6 --locked"),
        "reusable/manual recovery must prove the immutable public release ID, tag object, commit, checksums, and signatures before a crates.io credential enters scope"
    );
    let verifier = fs::read_to_string(repo_root().join("scripts/verify_published_release.py"))
        .expect("read published-release verifier");
    assert!(
        verifier.contains("/releases/tags/{escaped_tag}")
            && verifier.contains("/releases/{release_id}")
            && verifier.contains("release has no published_at verdict")
            && verifier.contains("value.get(\"draft\") is not False")
            && verifier.contains("value.get(\"immutable\") is not True")
            && verifier.contains("exact signed asset manifest is incomplete")
            && verifier.contains("[rsign, \"verify\", \"-q\""),
        "the release verdict must fail closed on missing/mutable/draft/unpublished/incomplete releases and cryptographically verify every exact checksum manifest"
    );
    assert!(
        workflow.contains("git/ref/tags/$KEYHOG_RELEASE_TAG")
            && workflow.contains("git/tags/$tag_object")
            && workflow.contains("automation/scripts/verify_release_tag.py")
            && workflow.contains("KEYHOG_EVENT_ACTOR_ID: ${{ github.actor_id }}")
            && workflow.contains("\"$KEYHOG_EVENT_ACTOR_ID\" != \"64453045\"")
            && workflow.contains("--actor-id \"$KEYHOG_EVENT_ACTOR_ID\"")
            && workflow.contains("git/ref/heads/main")
            && workflow.contains("compare/$commit...$main_sha")
            && workflow.contains("--main-ref-json \"$KEYHOG_MAIN_REF_JSON\"")
            && workflow.contains("--compare-json \"$KEYHOG_COMPARE_JSON\"")
            && workflow.contains("--authorized-key \"$GITHUB_WORKSPACE/automation/.github/release-signing-key.asc\"")
            && workflow.contains("id: source")
            && workflow.contains("KEYHOG_EXPECTED_COMMIT: ${{ steps.source.outputs.commit }}")
            && workflow.contains("KEYHOG_EXPECTED_OBJECT: ${{ steps.source.outputs.object }}")
            && workflow.contains("ref: ${{ steps.source.outputs.commit }}")
            && workflow.contains("git -C source rev-list -n 1 \"$KEYHOG_RELEASE_TAG\"")
            && workflow.contains("git -C source rev-parse HEAD")
            && workflow.contains("git -C source rev-parse \"$KEYHOG_RELEASE_TAG\"")
            && workflow.contains("workspace_version")
            && workflow.contains("KEYHOG_RELEASE_VERSION"),
        "the job must bind the stable owner actor, exact signed tag payload, pinned trusted-main ancestry, peeled commit, exact checkout, and workspace version before credentials"
    );
    assert!(
        workflow.contains("ref: ${{ github.workflow_sha }}")
            && workflow.contains("path: automation")
            && workflow.contains("path: source")
            && workflow.contains(
                "tag=\"$(bash automation/scripts/release-version.sh \"$KEYHOG_RELEASE_TAG\")\"",
            )
            && workflow.contains("' source/Cargo.toml)")
            && workflow.contains(
                "run: bash automation/scripts/publish.sh --source-root \"$GITHUB_WORKSPACE/source\"",
            )
            && !workflow.contains("run: bash scripts/publish.sh"),
        "manual and future-tag runs must execute hardened automation from the immutable workflow revision while packaging only the separate tagged source checkout"
    );
}

/// Runs the publisher and immutable-public-release verifier with local doubles.
/// The suites reject order/checksum drift, rerun uploads, incomplete inventories,
/// credential disclosure, draft/missing releases, and incomplete or forged manifests.
#[test]
fn crate_publisher_is_behaviorally_ordered_exact_and_rerunnable() {
    let output = Command::new("python3")
        .args([
            "-B",
            "-m",
            "unittest",
            "scripts.tests.test_publish",
            "scripts.tests.test_verify_published_release",
        ])
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .current_dir(repo_root())
        .output()
        .expect("run behavioral crate publication suite");
    assert!(
        output.status.success(),
        "behavioral crate publication suite failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
