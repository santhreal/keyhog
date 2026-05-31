#[test]
fn compiler_alt_basic() {
    assert_eq!(keyhog_scanner::testing::rewrite_alternation_prefix("(?:ghp_|github_pat_)[a-zA-Z0-9_]{36}", "ghp_", "[gɡ]hp_").as_deref(), Some("[gɡ]hp_[a-zA-Z0-9_]{36}"));
}
