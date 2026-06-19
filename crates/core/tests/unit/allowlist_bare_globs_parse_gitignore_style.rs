//! Bare path globs (no `path:` prefix) register as gitignore-style entries.

use keyhog_core::Allowlist;

#[test]
fn allowlist_bare_globs_parse_gitignore_style() {
    let content = "*.log
node_modules/
vendor/**/*.json
";
    let al = keyhog_core::testing::CoreTestApi::allowlist_parse(&keyhog_core::testing::TestApi, content);
    assert_eq!(al.ignored_paths.len(), 3, "got {:?}", al.ignored_paths);
    assert!(al.is_path_ignored("server.log"));
    assert!(al.is_path_ignored("node_modules/left-pad/index.js"));
    assert!(al.is_path_ignored("vendor/aws/sdk.json"));
}
