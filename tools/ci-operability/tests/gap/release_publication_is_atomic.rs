//! Release mutation is serialized per immutable tag and stays private until every
//! signed asset, product smoke, and GHCR publication proof succeeds.

use super::support::{read_workflow, repo_root};

fn job<'a>(workflow: &'a str, name: &str, next: &str) -> &'a str {
    workflow
        .split(&format!("\n  {name}:\n"))
        .nth(1)
        .and_then(|rest| rest.split(&format!("\n  {next}:\n")).next())
        .unwrap_or_else(|| panic!("release.yml must contain {name} before {next}"))
}

#[test]
fn duplicate_tag_runs_serialize_without_cancelling_active_publication() {
    let workflow = read_workflow("release.yml");

    assert_eq!(workflow.matches("\nconcurrency:\n").count(), 1);
    assert_eq!(workflow.matches("cancel-in-progress: false").count(), 1);
    assert!(
        workflow.contains(
            "group: release-${{ github.repository }}-${{ inputs.tag || github.ref_name }}",
        ),
        "release workflow concurrency must key both push and dispatch runs by exact tag",
    );
}

/// Locks out the recovery failure where a manual dispatch named an immutable
/// tag but the workflow compared its `main` event ref and SHA to that tag.
/// Dispatch recovery must build the exact tag while loading hardened release
/// automation from the workflow commit.
#[test]
fn manual_dispatch_binds_products_to_the_input_tag() {
    let workflow = read_workflow("release.yml");
    let build = job(&workflow, "build", "installers");
    let sign = job(&workflow, "sign", "smoke");
    let publish = job(&workflow, "publish", "major-tag");
    let exact_dispatch_ref =
        "ref: ${{ inputs.tag && format('refs/tags/{0}', inputs.tag) || github.ref }}";

    assert!(
        build.contains(exact_dispatch_ref)
            && build.contains(
                "if [[ -z \"${KEYHOG_RELEASE_INPUT_TAG:-}\" && \"$KEYHOG_RELEASE_EVENT_REF\" != \"refs/tags/$tag\" ]]",
            )
            && build.contains(
                "if [[ -z \"${KEYHOG_RELEASE_INPUT_TAG:-}\" && \"$actual\" != \"$KEYHOG_RELEASE_EVENT_SHA\" ]]",
            ),
        "manual dispatch must check out the exact input tag without comparing it to the workflow branch ref or SHA",
    );
    assert!(
        sign.contains("ref: ${{ github.workflow_sha }}")
            && sign.contains("$GITHUB_WORKSPACE/automation/scripts/publish_release_assets.py"),
        "signing must use hardened automation from the workflow commit while products remain bound to the immutable tag",
    );
    assert!(
        publish.contains(exact_dispatch_ref)
            && publish.contains("\"$commit\" != \"$(git rev-parse HEAD)\""),
        "publication must verify the signed receipt against the exact tag checkout during recovery dispatch",
    );
}

#[test]
fn container_failure_leaves_the_immutable_release_private() {
    let workflow = read_workflow("release.yml");
    let sign = job(&workflow, "sign", "smoke");
    let docker = job(&workflow, "docker", "publish");
    let publish = job(&workflow, "publish", "major-tag");

    assert!(
        sign.contains("publish_release_assets.py\" prepare")
            && sign.contains("release-publication.json.minisig")
            && !sign.contains("publish_release_assets.py publish"),
        "sign must only prepare an immutable-ID draft and signed cross-job proof",
    );
    assert!(
        docker.contains("push: true")
            && docker.contains("Verify published multi-arch manifest")
            && docker.contains("Attest published image digest"),
        "docker must push, read back, and attest GHCR before succeeding",
    );
    assert!(
        publish.contains("needs: [sign, docker, smoke]")
            && publish.contains("publish_release_assets.py publish"),
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
        docker.contains("needs: smoke")
            && docker.contains(
                "ghcr.io/${{ github.repository }}:${{ steps.tag.outputs.version }}",
            )
            && docker.contains("--tag \"ghcr.io/${{ github.repository }}:latest\""),
        "docker must depend on smoke because versioned and latest GHCR tag writes are irreversible public mutations",
    );
    assert!(
        publish.contains("needs: [sign, docker, smoke]"),
        "a failed candidate smoke must prevent the only public transition job",
    );
}

#[test]
fn success_orders_signed_assets_and_attested_multiarch_image_before_publication() {
    let workflow = read_workflow("release.yml");
    let docker = job(&workflow, "docker", "publish");
    let publish = job(&workflow, "publish", "major-tag");

    assert!(
        docker.contains("platforms: linux/amd64,linux/arm64")
            && docker.contains("KEYHOG_IMAGE_DIGEST: ${{ steps.image.outputs.digest }}")
            && docker.contains("subject-digest: ${{ steps.image.outputs.digest }}")
            && docker.contains("push-to-registry: true"),
        "GHCR success must mean a verified, digest-attested amd64+arm64 manifest",
    );
    let verify = publish
        .find("minisign -Vm \"$receipt\"")
        .expect("final job verifies signed receipt");
    let transition = publish
        .find("publish_release_assets.py publish")
        .expect("final job performs public transition");
    assert!(
        publish.contains("needs: [sign, docker, smoke]") && verify < transition,
        "the signed immutable-ID receipt and every dependency must pass before publication",
    );
}

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
