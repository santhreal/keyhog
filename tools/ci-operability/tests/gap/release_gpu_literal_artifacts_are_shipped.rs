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
        text.contains("${{ matrix.asset }}.gpu-literals.tar.gz")
            && text.contains("${{ matrix.asset }}.gpu-literals.tar.gz.sha256")
            && text.contains("name: unsigned-${{ matrix.asset }}")
            && text.contains("cp -a \"$GITHUB_WORKSPACE/dist/.\" \"$workdir/\"")
            && text.contains("final+=(\"$payload.minisig\")")
            && text.contains("releases/$release_id/assets?name=$asset")
            && text.contains("\"repos/$GITHUB_REPOSITORY/releases/$release_id\"")
            && text.contains("-F draft=false")
            && text
                .contains("published release manifest does not equal the signed expected manifest"),
        "release.yml must stage the GPU literal bundle privately, then publish it only through the exact signed manifest"
    );

    let sign_job = text
        .split("\n  sign:\n")
        .nth(1)
        .and_then(|rest| rest.split("\n  docker:\n").next())
        .expect("release.yml must keep the sign job");
    assert!(
        sign_job.contains("payloads+=(\"$base\" \"$base.gpu-literals.tar.gz\")")
            && sign_job.contains("rsign sign")
            && sign_job.contains("for f in \"${payloads[@]}\"")
            && !sign_job.contains("gh release download \"$tag\""),
        "release signing must sign the privately staged binary and GPU literal payloads without using a public release as staging transport"
    );
    assert!(
        ci.contains("--test gpu_literal_artifact_writer")
            && ci.contains("--bin keyhog-scanner-artifacts")
            && ci.contains("--features ml,entropy,decode,multiline,simdsieve,simd")
            && ci.contains("--out-dir \"$RUNNER_TEMP/keyhog-gpu-literals\""),
        "ci.yml must run the artifact writer integration test and the release-style writer command"
    );
}
