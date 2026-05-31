#[test]
fn compiler_alt_inline_flag() {
    assert_eq!(keyhog_scanner::testing::rewrite_alternation_prefix("(?i)(?:ghp_|github_pat_)[a-zA-Z0-9_]{36}", "ghp_", "[gɡ]hp_").as_deref(), Some("(?i)[gɡ]hp_[a-zA-Z0-9_]{36}"));
}
