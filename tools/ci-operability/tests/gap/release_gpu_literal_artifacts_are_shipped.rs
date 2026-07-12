//! AX10: release assets must ship compiled GPU literal artifacts, not just a
//! dead helper binary.

use super::support::read_workflow;

#[test]
fn release_workflow_builds_uploads_and_signs_gpu_literal_artifacts() {
    let text = read_workflow("release.yml");
    let ci = read_workflow("ci.yml");

    assert!(
        text.contains("--bin keyhog-scanner-artifacts")
            && text.contains("--out-dir \"$bundle_dir\"")
            && text.contains("artifact_features: 'ml,entropy,decode,multiline,simdsieve,simd'")
            && text.contains("--features \"${{ matrix.artifact_features }}\"")
            && text.contains(".gpu-literals.tar.gz"),
        "release.yml must build a GPU literal artifact bundle through the real scanner artifact writer"
    );
    assert!(
        text.contains("\"$asset.gpu-literals.tar.gz\"")
            && text.contains("\"$asset.gpu-literals.tar.gz.sha256\"")
            && text.contains("gh release upload \"$tag\""),
        "release.yml must upload the GPU literal sidecar and checksum beside each binary"
    );

    let sign_job = text
        .split("\n  sign:\n")
        .nth(1)
        .and_then(|rest| rest.split("\n  docker:\n").next())
        .expect("release.yml must keep the sign job");
    assert!(
        sign_job.contains("gh release download \"$tag\"")
            && sign_job.contains("--pattern 'keyhog-*'")
            && sign_job.contains("rsign sign")
            && sign_job.contains("*.sha256|*.minisig) continue ;;")
            && !sign_job.contains("*.tar.gz"),
        "release signing must sign uploaded GPU literal sidecars instead of excluding tarballs"
    );
    assert!(
        ci.contains("--test gpu_literal_artifact_writer")
            && ci.contains("--bin keyhog-scanner-artifacts")
            && ci.contains("--features ml,entropy,decode,multiline,simdsieve,simd")
            && ci.contains("--out-dir \"$RUNNER_TEMP/keyhog-gpu-literals\""),
        "ci.yml must run the artifact writer integration test and the release-style writer command"
    );
}
