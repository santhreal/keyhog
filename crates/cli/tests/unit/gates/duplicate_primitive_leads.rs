use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|error| {
        panic!("read {rel}: {error}");
    })
}

#[test]
fn d_lead_1_removes_dead_duplicate_shims() {
    let spec = read("crates/core/src/spec.rs");
    assert!(
        !spec.contains("fn to_severity(&self) -> Self"),
        "core::Severity must not grow an identity to_severity shim; CLI SeverityFilter owns the filter-to-core conversion"
    );

    let core_testing = read("crates/core/src/testing.rs");
    assert!(
        !core_testing.contains("severity_to_severity"),
        "core testing facade must not re-export the removed identity severity shim"
    );

    let scanner_lib = read("crates/scanner/src/lib.rs");
    assert!(
        !scanner_lib.contains("crate::jwt::finding_metadata(credential)"),
        "scanner testing facade must not duplicate the public jwt::finding_metadata bridge"
    );
}
