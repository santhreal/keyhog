//! Git subprocess must refuse $PATH lookup for git binary in git/mod.rs.

#[test]
fn git_uses_resolve_safe_bin() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/git/mod.rs"))
        .expect("git/mod.rs");
    assert!(
        src.contains(r#"resolve_safe_bin("git")"#),
        "git_bin must use resolve_safe_bin"
    );
    assert!(
        src.contains("Command::new(&git_bin()?)"),
        "git subprocess must invoke resolved git_bin path"
    );
    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with('*') {
            continue;
        }
        assert!(
            !trimmed.contains(r#"Command::new("git")"#),
            "bare PATH git invocation in code line: {trimmed}"
        );
    }
}
