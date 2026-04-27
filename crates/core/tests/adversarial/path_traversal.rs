use keyhog_core::Allowlist;

#[test]
fn allowlist_path_traversal_attack() {
    let mut al = Allowlist::empty();
    al.ignored_paths.push("safe/**".into());

    // Attacker tries to use traversal to match a safe rule
    assert!(
        !al.is_path_ignored("safe/../../etc/passwd"),
        "Path traversal should not bypass safety"
    );
    assert!(!al.is_path_ignored("../etc/passwd"));
    assert!(!al.is_path_ignored("/etc/passwd"));
}

#[test]
fn allowlist_null_byte_attack() {
    let mut al = Allowlist::empty();
    al.ignored_paths.push("safe/*".into());

    // Null bytes should be handled like any other character and NOT bypass the rule.
    // "safe/file\0.txt" matches "safe/*"
    assert!(
        al.is_path_ignored("safe/file\0.txt"),
        "Null bytes should be matched by '*' and not cause bypass"
    );
}
