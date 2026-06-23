//! Gate daemon trust ancestor validation: one walker, policy wrappers only.

#[test]
fn daemon_trust_ancestor_validation_has_single_walker() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/daemon/trust.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let prod = src
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        prod.contains("enum MissingAncestorPolicy")
            && prod.contains("enum AncestorUse")
            && prod.contains("fn validate_ancestors_no_symlink("),
        "daemon trust ancestor validation must be one shared helper with explicit policies"
    );
    assert_eq!(
        prod.matches("for ancestor in path.ancestors()").count(),
        1,
        "daemon trust must not duplicate ancestor traversal for existing-vs-all path checks"
    );
    assert!(
        prod.contains(
            "validate_ancestors_no_symlink(path, MissingAncestorPolicy::Error, AncestorUse::TrustSocket)"
        ) && prod.contains("MissingAncestorPolicy::Tolerate")
            && prod.contains("AncestorUse::CreateSocketDir"),
        "daemon trust wrappers must express missing-component and symlink-error policy at the call site"
    );
}
