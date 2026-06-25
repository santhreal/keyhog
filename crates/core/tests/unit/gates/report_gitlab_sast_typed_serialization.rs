//! Gate GitLab SAST reporter serialization: typed structs, no dynamic json! objects.

#[test]
fn report_gitlab_sast_uses_typed_serialization() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/report/gitlab_sast.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let prod = src
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    for required in [
        "struct GitlabScan",
        "struct GitlabTool",
        "struct GitlabVulnerability",
        "struct GitlabDetails",
        "fn vulnerability_object(finding: &VerifiedFinding) -> Result<GitlabVulnerability<'_>, ReportError>",
    ] {
        assert!(
            prod.contains(required),
            "missing typed GitLab SAST owner: {required}"
        );
    }
    assert!(
        !prod.contains("serde_json::json!") && !prod.contains("serde_json::Value"),
        "GitLab SAST reporter must serialize typed structs instead of dynamic serde_json values"
    );
}
