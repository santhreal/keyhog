//! Tier-B skip-dir policy parse/merge/validate, relocated out of
//! `crate::skip_dirs` (the `no_inline_tests_in_src` gate forbids inline
//! `#[cfg(test)]`). Reached through the `crate::testing` facade.

use keyhog::testing::{CliTestApi as _, API};

#[test]
fn bundled_policy_contains_consumer_specific_components() {
    let policy = API
        .skip_dir_policy_from_bundled()
        .expect("bundled skip-dir policy loads");

    assert!(policy.is_watch_component(".GIT"));
    assert!(policy.is_watch_component("NODE_MODULES"));
    assert!(policy.is_watch_component(".cache"));
    assert!(policy.is_watch_component("vendor"));
    assert!(policy.is_watch_component(".nuxt"));
    assert!(policy.is_git_discovery_component("node_modules"));
    assert!(policy.is_git_discovery_component(".cache"));
    assert!(policy.is_git_discovery_component("vendor"));
    assert!(policy.is_git_discovery_component(".nuxt"));
    assert!(policy.is_git_discovery_component("system volume information"));
    assert!(!policy.is_git_discovery_component(".git"));
}

#[test]
fn policy_validation_rejects_path_components_with_separators() {
    let raw = r#"
        [skip_dirs]
        base = ["node_modules/inner"]
        watch_extra = [".git"]
        git_discovery_extra = ["Library"]
    "#;

    let error = API
        .skip_dir_policy_from_toml(raw)
        .expect_err("separator must be rejected");
    assert!(
        error.contains("single path component"),
        "unexpected validation error: {error}"
    );
}

#[test]
fn empty_user_policy_parses_as_noop_section() {
    let (base, watch_extra, git_discovery_extra) = API
        .skip_dir_section_counts("")
        .expect("empty user TOML is a no-op policy section");

    assert_eq!(base, 0);
    assert_eq!(watch_extra, 0);
    assert_eq!(git_discovery_extra, 0);
}

#[test]
fn policy_merge_tolerates_source_default_duplicates() {
    let raw = r#"
        [skip_dirs]
        base = ["node_modules", ".cargo"]
        watch_extra = [".git", ".turbo"]
        git_discovery_extra = ["System Volume Information"]
    "#;

    let policy = API
        .skip_dir_policy_from_toml(raw)
        .expect("source-default duplicates are benign");

    assert!(policy.is_watch_component("node_modules"));
    assert!(policy.is_watch_component(".git"));
    assert!(policy.is_watch_component(".cargo"));
    assert!(policy.is_git_discovery_component("node_modules"));
    assert!(policy.is_git_discovery_component(".cargo"));
    assert!(!policy.is_git_discovery_component(".git"));
}

#[test]
fn user_policy_merge_tolerates_bundled_duplicates() {
    let user = r#"
        [skip_dirs]
        base = [".cargo", "node_modules"]
        watch_extra = [".svn", ".git"]
        git_discovery_extra = ["System Volume Information"]
    "#;

    let policy = API
        .skip_dir_policy_from_bundled_plus_user(user)
        .expect("overlap with bundled/source dirs is benign");

    assert!(policy.is_watch_component(".cargo"));
    assert!(policy.is_watch_component("node_modules"));
    assert!(policy.is_watch_component(".svn"));
    assert!(policy.is_git_discovery_component("system volume information"));
    assert!(!policy.is_git_discovery_component(".git"));
}

#[test]
fn user_policy_merge_rejects_internal_duplicates() {
    let user = r#"
        [skip_dirs]
        base = ["custom", "CUSTOM"]
    "#;

    let error = API
        .skip_dir_policy_from_bundled_plus_user(user)
        .expect_err("duplicates inside a user list must stay invalid");
    assert!(
        error.contains("duplicate component"),
        "unexpected validation error: {error}"
    );
}
