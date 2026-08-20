//! Release trust-boundary contracts for the crates.io-only release workflow.

use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn release_workflow() -> String {
    fs::read_to_string(root().join(".github/workflows/release.yml")).expect("read release workflow")
}

/// A release must originate from a successful push to `main`, bind the checked
/// out commit to that CI run, and push the release commit and tag atomically.
#[test]
fn automatic_release_is_bound_to_the_successful_main_ci_identity() {
    let workflow = release_workflow();
    for contract in [
        "workflows: [CI]",
        "github.event.workflow_run.conclusion == 'success'",
        "github.event.workflow_run.event == 'push'",
        "github.event.workflow_run.head_branch == 'main'",
        "CI_HEAD_SHA: ${{ github.event.workflow_run.head_sha }}",
        "ref: main",
        "if [[ \"$current\" == \"$CI_HEAD_SHA\" ]]",
        "summary=\"$(git show -s --format=%s \"$CI_HEAD_SHA\")\"",
        "python3 -B scripts/auto_release.py --summary \"$summary\" --apply",
        "git push --atomic origin HEAD:main \"refs/tags/v${version}\"",
    ] {
        assert!(
            workflow.contains(contract),
            "automatic release identity contract is missing {contract}"
        );
    }
}

/// Trusted publishing must use GitHub OIDC, generate the commit-bound integrity
/// receipt first, and pass only the exchanged short-lived token to publish.sh.
#[test]
fn crates_publish_uses_oidc_after_the_integrity_receipt() {
    let workflow = release_workflow();
    for contract in [
        "id-token: write",
        "python3 -B scripts/release_integrity_receipt.py",
        "--commit \"$(git rev-parse HEAD)\"",
        "--version \"${{ steps.tag.outputs.version }}\"",
        "--output release-integrity.json",
        "rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18 # v1.0.5",
        "run: bash scripts/publish.sh",
        "CARGO_REGISTRY_TOKEN: ${{ steps.crates-io-auth.outputs.token }}",
        "path: release-integrity.json",
    ] {
        assert!(
            workflow.contains(contract),
            "trusted crates.io release contract is missing {contract}"
        );
    }

    let receipt = workflow
        .find("- name: Generate release integrity receipt")
        .expect("integrity receipt step");
    let authenticate = workflow
        .find("- name: Authenticate to crates.io")
        .expect("OIDC authentication step");
    let publish = workflow
        .find("- name: Publish crates.io packages")
        .expect("publish step");
    let upload = workflow
        .find("- name: Upload release integrity receipt")
        .expect("receipt upload step");
    assert!(
        receipt < authenticate && authenticate < publish && publish < upload,
        "release order must be receipt, OIDC exchange, publish, then receipt upload"
    );
}

/// Installation documentation and automation must agree that releases are six
/// crates.io packages, not unsigned or unattested binary installer assets.
#[test]
fn install_docs_match_the_crates_only_release_surface() {
    let workflow = release_workflow();
    let docs = fs::read_to_string(root().join("docs/src/install.md")).expect("read install docs");

    // The pinned-install example is derived, never spelled out. `keyhog` takes
    // `version.workspace = true`, so `CARGO_PKG_VERSION` is the workspace
    // version at compile time. Hardcoding it drifted: the literal said 0.5.50
    // while `prepare_release` had advanced the doc to 0.5.68, so this contract
    // could not be satisfied and the gate failed on a tree whose docs were
    // correct. A release gate that goes red because the release happened is
    // worse than no gate, because the next person deletes it.
    let pinned_install = format!(
        "cargo install --locked --version '={}' keyhog",
        env!("CARGO_PKG_VERSION")
    );
    for contract in [
        "cargo install --locked keyhog",
        pinned_install.as_str(),
        "Every successful `main` CI run publishes the next patch version.",
        "does\nnot publish binary release assets or installer bundles.",
    ] {
        assert!(
            docs.contains(contract),
            "installation guide is missing crates-only contract {contract}"
        );
    }
    for retired in [
        "releases/download/",
        "minisign -Vm install.sh",
        "KEYHOG_VERSION=",
        "unsigned-installers",
        "actions/attest@",
    ] {
        assert!(
            !docs.contains(retired) && !workflow.contains(retired),
            "crates-only release surfaces must not retain retired binary asset contract {retired}"
        );
    }
}
