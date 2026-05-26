//! Git sources must canonicalize repo paths and require .git/HEAD.

#[cfg(feature = "git")]
#[test]
fn git_validate_repo_path_canonicalizes() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/git/mod.rs"
    ))
    .expect("git/mod.rs");
    assert!(src.contains("canonicalize(repo_path)"));
    assert!(src.contains("looks_like_repo"));
    assert!(src.contains("is not a git repository"));
}

#[cfg(not(feature = "git"))]
#[test]
fn git_validate_repo_requires_git_feature() {
    assert!(!cfg!(feature = "git"));
}
