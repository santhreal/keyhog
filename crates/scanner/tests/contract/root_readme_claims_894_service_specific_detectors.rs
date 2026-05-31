//! Contract: root README claims 894 service-specific detectors.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

#[test]
fn root_readme_claims_891_service_specific_detectors() {
    let readme = std::fs::read_to_string(repo_root().join("README.md"))
        .expect("root README.md readable");

    assert!(
        readme.contains("894 service-specific"),
        "README must claim 894 service-specific detectors - front-page count drift breaks catalog trust"
    );
}
