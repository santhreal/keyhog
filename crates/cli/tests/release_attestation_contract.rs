//! Release trust-boundary contract for GitHub build provenance.

use std::fs;
use std::path::Path;

#[test]
fn every_matrix_payload_is_attested_before_private_staging() {
    let workflow_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/release.yml");
    let workflow = fs::read_to_string(&workflow_path).expect("read release workflow");
    let build = workflow
        .split("\n  build:")
        .nth(1)
        .and_then(|tail| tail.split("\n  sign:").next())
        .expect("release build job");

    assert!(
        build.contains("id-token: write") && build.contains("attestations: write"),
        "the matrix build needs the two least-privilege attestation permissions"
    );
    assert!(
        build.contains("KEYHOG_RELEASE_EVENT_REF: ${{ github.ref }}")
            && build.contains("refs/tags/$tag")
            && build.contains("KEYHOG_RELEASE_EVENT_SHA: ${{ github.sha }}")
            && build.contains("git rev-parse HEAD")
            && build.contains("actual\" != \"$KEYHOG_RELEASE_EVENT_SHA"),
        "manual and tag-push builds must bind the checkout to the event identity attested by GitHub"
    );
    assert!(
        build.contains("uses: actions/attest@a1948c3f048ba23858d222213b7c278aabede763 # v4.1.1"),
        "release provenance must use the reviewed immutable action revision"
    );

    let attest = build
        .find("- name: Attest release payload provenance")
        .expect("attestation step");
    let upload = build
        .find("- name: Stage unsigned release bundle")
        .expect("private artifact staging step");
    assert!(
        attest < upload,
        "payloads must be attested before private staging"
    );

    let attestation_step = &build[attest..upload];
    assert!(
        !attestation_step.contains("\n        if:"),
        "every release matrix payload must be attested without a skip condition"
    );
    for subject in [
        "${{ matrix.asset }}",
        "${{ matrix.asset }}.gpu-literals.tar.gz",
    ] {
        assert!(
            attestation_step.contains(subject),
            "attestation is missing release payload {subject}"
        );
    }

    let install_doc =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/src/install.md"))
            .expect("read install documentation");
    for policy in [
        "--signer-workflow github.com/santhreal/keyhog/.github/workflows/release.yml",
        "--source-ref \"refs/tags/$TAG\"",
        "--deny-self-hosted-runners",
    ] {
        assert!(
            install_doc.contains(policy),
            "documented attestation verification is missing policy constraint {policy}"
        );
    }
}
