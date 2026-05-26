//! LR1-A8 replacement gate: `git/mod.rs` non-repo still reports git name.

#[cfg(feature = "git")]
use keyhog_core::Source;
#[cfg(feature = "git")]
use keyhog_sources::GitSource;

#[cfg(feature = "git")]
#[test]
fn git_source_on_non_repo_keeps_git_name() {
    let source = GitSource::new(std::path::PathBuf::from("/nonexistent/repo"));
    assert_eq!(source.name(), "git");
}

#[cfg(not(feature = "git"))]
#[test]
fn git_mod_gate_skipped_without_feature() {
    // git feature disabled in default test build.
}
