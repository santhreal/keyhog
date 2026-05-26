//! Mixed prefixed and bare entries in one file must all load.

use keyhog_core::Allowlist;

#[test]
fn allowlist_mixed_prefixed_and_bare_entries_all_load() {
    let content = "detector:asana-pat
hash:9d6060e21ef8d5daec9cfe4a44b1b1bc9792246bfad28210edaaa1782a8a676a
path:tests/**/*.fixture
*.log
node_modules/
9d6060e21ef8d5daec9cfe4a44b1b1bc9792246bfad28210edaaa1782a8a675f
";
    let al = Allowlist::parse(content);
    assert!(al.ignored_detectors.contains("asana-pat"));
    assert_eq!(al.credential_hashes.len(), 2);
    assert!(al.ignored_paths.iter().any(|p| p == "tests/**/*.fixture"));
    assert!(al.ignored_paths.iter().any(|p| p == "*.log"));
    assert!(al.ignored_paths.iter().any(|p| p == "node_modules/"));
}
