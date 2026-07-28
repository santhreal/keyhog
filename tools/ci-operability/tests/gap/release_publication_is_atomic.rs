//! Release mutation is globally serialized and stays private until every signed
//! asset, product smoke, and GHCR publication proof succeeds.

use super::support::{read_workflow, repo_root};

fn job<'a>(workflow: &'a str, name: &str, next: &str) -> &'a str {
    workflow
        .split(&format!("\n  {name}:\n"))
        .nth(1)
        .and_then(|rest| rest.split(&format!("\n  {next}:\n")).next())
        .unwrap_or_else(|| panic!("release.yml must contain {name} before {next}"))
}

/// Locks out cancellation or per-tag concurrency that permits irreversible
/// publication mutations from two releases to overlap.
#[test]
fn duplicate_tag_runs_serialize_without_cancelling_active_publication() {
    let workflow = read_workflow("release.yml");

    assert_eq!(workflow.matches("\nconcurrency:\n").count(), 1);
    assert_eq!(workflow.matches("cancel-in-progress: false").count(), 1);
    assert!(
        workflow.contains("group: release-${{ github.repository }}")
            && !workflow.contains("group: release-${{ github.repository }}-"),
        "all release tags must share one non-cancelling publication lock",
    );
}

/// Locks out detached workflow-run provenance and CI verdicts for another
/// ref or commit from authorizing an exact-tag release.
#[test]
fn tag_push_preserves_attestation_ref_and_waits_for_exact_ci_verdict() {
    let workflow = read_workflow("release.yml");
    let gate = job(&workflow, "ci-verdict", "build");

    assert!(
        workflow.contains("push:\n    tags:\n      - 'v*'")
            && !workflow.contains("workflow_run:")
            && gate.contains("KEYHOG_EVENT_REF: ${{ github.ref }}")
            && gate.contains("KEYHOG_EVENT_SHA: ${{ github.sha }}")
            && gate.contains("for _attempt in $(seq 1 360)")
            && gate.contains(
                "actions/workflows/ci.yml/runs?head_sha=$tag_commit&event=push&per_page=100",
            )
            && gate.contains(".name == \"CI verdict\"")
            && gate.contains(".conclusion == \"success\""),
        "tag push provenance must remain ambient while the read-only gate waits for exact-tag CI",
    );
}

/// Locks out stale global `latest` rollback while allowing an already-attested
/// exact version digest to be reused without overwriting its immutable tag.
#[test]
fn older_release_cannot_roll_latest_backward_after_newer_tag_appears() {
    let workflow = read_workflow("release.yml");
    let docker = job(&workflow, "docker", "publish");
    let version_push = docker
        .find("Build and push new multi-arch version image")
        .expect("conditional version image push");
    let attestation = docker
        .find("Attest new published image digest")
        .expect("digest attestation");
    let revalidate = docker
        .find("Revalidate newest stable immediately before latest mutation")
        .expect("fresh newest-tag decision");
    let latest = docker
        .find("Advance latest image for the newest stable release")
        .expect("latest mutation");

    assert!(
        workflow.contains("group: release-${{ github.repository }}")
            && version_push < attestation
            && attestation < revalidate
            && revalidate < latest
            && docker.matches("is-newest-stable-tag.sh").count() == 1,
        "global serialization and a post-build tag refresh must prevent stale latest rollback",
    );
}

/// Locks out the recovery failure where a manual dispatch named an immutable
/// tag but the workflow compared its `main` event ref and SHA to that tag.
/// Dispatch recovery must build the exact tag while loading hardened release
/// automation from the workflow commit.
#[test]
fn manual_dispatch_binds_products_to_the_input_tag() {
    let workflow = read_workflow("release.yml");
    let gate = job(&workflow, "ci-verdict", "build");
    let build = job(&workflow, "build", "installers");
    let sign = job(&workflow, "sign", "smoke");
    let publish = job(&workflow, "publish", "major-tag");

    assert!(
        gate.contains("tag=\"$KEYHOG_MANUAL_TAG\"")
            && gate.contains("commit=\"$KEYHOG_MANUAL_SHA\"")
            && gate.contains("\"$KEYHOG_EVENT_REF\" != \"refs/tags/$tag\"")
            && gate.contains("\"$KEYHOG_EVENT_SHA\" != \"$tag_commit\"")
            && build.contains("ref: ${{ needs.ci-verdict.outputs.commit }}")
            && build.contains("KEYHOG_RELEASE_TAG_OBJECT: ${{ needs.ci-verdict.outputs.tag_object }}"),
        "manual recovery must bind ambient ref/SHA and every product to the authenticated signed tag",
    );
    assert!(
        sign.contains("ref: ${{ github.workflow_sha }}")
            && sign.contains("$GITHUB_WORKSPACE/automation/scripts/publish_release_assets.py"),
        "signing must use hardened automation while products remain bound to the signed tag",
    );
    assert!(
        publish.contains("ref: ${{ needs.ci-verdict.outputs.commit }}")
            && publish.contains("\"$commit\" != \"$(git rev-parse HEAD)\"")
            && publish.contains("\"$tag_object\" != \"$KEYHOG_RELEASE_TAG_OBJECT\""),
        "publication must recheck the signed receipt, commit, and tag object during recovery",
    );
}

/// Locks out public binary exposure when the required GHCR digest publication
/// or provenance verification fails downstream.
#[test]
fn container_failure_leaves_the_immutable_release_private() {
    let workflow = read_workflow("release.yml");
    let sign = job(&workflow, "sign", "smoke");
    let docker = job(&workflow, "docker", "publish");
    let publish = job(&workflow, "publish", "major-tag");

    assert!(
        sign.contains("automation/scripts/publish_release_assets.py\" prepare")
            && sign.contains("release-publication.json.minisig")
            && !sign.contains("automation/scripts/publish_release_assets.py\" publish"),
        "sign must only prepare an immutable-ID draft and signed cross-job proof",
    );
    assert!(
        docker.contains("push: true")
            && docker.contains("Verify published multi-arch manifest")
            && docker.contains("Attest new published image digest"),
        "docker must push, read back, and attest GHCR before succeeding",
    );
    assert!(
        publish.contains("needs: [ci-verdict, sign, docker, smoke]")
            && publish.contains("ref: ${{ github.workflow_sha }}")
            && publish.contains("automation/scripts/publish_release_assets.py\" publish"),
        "a failed docker dependency must prevent the only public transition job",
    );
}

/// Locks out the regression where Docker depended only on signing, allowing
/// irreversible versioned and `latest` GHCR tag mutations before the signed
/// candidate smoke failed. Product smoke must gate both public mutations first.
#[test]
fn failed_candidate_smoke_leaves_the_release_private() {
    let workflow = read_workflow("release.yml");
    let smoke = job(&workflow, "smoke", "crates");
    let docker = job(&workflow, "docker", "publish");
    let publish = job(&workflow, "publish", "major-tag");

    assert!(
        smoke.contains("name: signed-linux-candidate")
            && smoke.contains("sha256sum -c \"$payload.sha256\"")
            && smoke.contains("minisign -Vm \"$payload\"")
            && smoke.contains("--from-file=\"$candidate/keyhog-linux-x86_64\"")
            && smoke.contains("--no-calibrate")
            && smoke.contains("\"$installed\" doctor")
            && smoke.contains("--backend \"$KEYHOG_EXPECTED_SCAN_BACKEND\"")
            && smoke.contains("scan_status")
            && smoke.contains("length == 1")
            && smoke.contains("stripe-secret-key"),
        "smoke must verify and install staged proofs, assert doctor backend state, and exercise exact product scan semantics",
    );
    assert!(
        docker.contains("needs: [ci-verdict, smoke]")
            && docker
                .contains("ghcr.io/${{ github.repository }}:${{ steps.tag.outputs.version }}",)
            && docker.contains("--tag \"ghcr.io/${{ github.repository }}:latest\""),
        "docker must depend on smoke because versioned and latest GHCR tag writes are irreversible public mutations",
    );
    assert!(
        publish.contains("needs: [ci-verdict, sign, docker, smoke]"),
        "a failed candidate smoke must prevent the only public transition job",
    );
}

/// Locks out overwriting a version tag on recovery and publishing an image
/// whose exact digest has never executed the real CLI runtime path.
#[test]
fn success_orders_signed_assets_and_attested_multiarch_image_before_publication() {
    let workflow = read_workflow("release.yml");
    let docker = job(&workflow, "docker", "publish");
    let publish = job(&workflow, "publish", "major-tag");

    assert!(
        docker.contains("platforms: linux/amd64,linux/arm64")
            && docker.contains("KEYHOG_IMAGE_DIGEST: ${{ steps.image.outputs.digest }}")
            && docker.contains("subject-digest: ${{ steps.image.outputs.digest }}")
            && docker.contains("push-to-registry: true")
            && docker.contains("if: steps.existing-image.outputs.exists != 'true'")
            && docker.contains("gh attestation verify \"oci://$KEYHOG_IMAGE@$digest\"")
            && docker.contains("Smoke exact digest-addressed container runtime")
            && docker.contains("--backend simd"),
        "GHCR success must reuse only provenance-verified versions or publish a new attested digest, then smoke the exact amd64 runtime",
    );
    let verify = publish
        .find("minisign -Vm \"$receipt\"")
        .expect("final job verifies signed receipt");
    let transition = publish
        .find("automation/scripts/publish_release_assets.py\" publish")
        .expect("final job performs public transition");
    assert!(
        publish.contains("needs: [ci-verdict, sign, docker, smoke]") && verify < transition,
        "the signed immutable-ID receipt and every dependency must pass before publication",
    );
}

/// Locks out a serialized recovery run mutating an already-complete public
/// release instead of verifying and reusing its immutable state.
#[test]
fn serialized_rerun_reuses_public_release_without_mutation() {
    let publisher = std::fs::read_to_string(repo_root().join("scripts/publish_release_assets.py"))
        .expect("read release publisher");
    let finalizer = publisher
        .split("def publish_prepared_release(")
        .nth(1)
        .expect("publisher has a separate final phase");
    let public_rerun = finalizer
        .find("current.get(\"draft\") is False")
        .expect("finalizer detects a completed rerun");
    let idempotent_return = finalizer
        .find("return receipt.release_id")
        .expect("completed rerun returns the immutable release ID");
    let public_patch = finalizer
        .find("payload={\"draft\": False}")
        .expect("fresh finalization has one public transition");

    assert!(
        public_rerun < idempotent_return && idempotent_return < public_patch,
        "an exact already-public rerun must return before any release mutation",
    );
}
