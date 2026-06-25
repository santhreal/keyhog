use keyhog_core::Allowlist;
use std::path::PathBuf;

fn temp_allowlist_path(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "keyhog_allowlist_{label}_{}_{}.keyhogignore",
        std::process::id(),
        nanos
    ))
}

fn load_error(content: &str) -> String {
    let path = temp_allowlist_path("typo");
    std::fs::write(&path, content).expect("write allowlist");
    let err = Allowlist::load_with_metadata_policy(&path, false, false, None)
        .expect_err("allowlist should fail closed");
    let _ = std::fs::remove_file(&path);
    err.to_string()
}

#[test]
fn typoed_prefixed_allowlist_entry_fails_closed() {
    let hash = "a".repeat(64);
    let err = load_error(&format!("hsah:{hash}\n"));

    assert!(
        err.contains("violates allowlist governance")
            && err.contains("valid prefix")
            && err.contains("refusing to scan"),
        "typoed allowlist prefix must be an operator-visible load error, got: {err}"
    );
}

#[test]
fn hex_like_bare_hash_typo_fails_closed() {
    let err = load_error(&format!("{}\n", "a".repeat(63)));

    assert!(
        err.contains("hex-like bare entry")
            && err.contains("64-character SHA-256")
            && err.contains("refusing to scan"),
        "hex-like bare hash typo must not become a path glob, got: {err}"
    );
}

#[test]
fn bare_64_byte_non_hex_entry_fails_closed() {
    let err = load_error(&format!("{}g\n", "a".repeat(63)));

    assert!(
        err.contains("bare 64-byte entry")
            && err.contains("SHA-256 hex digest")
            && err.contains("refusing to scan"),
        "bare 64-byte hash typo must not become a path glob, got: {err}"
    );
}

#[test]
fn explicit_path_prefix_allows_ambiguous_path_globs() {
    let path = temp_allowlist_path("path_prefix");
    let hex_like_path = "a".repeat(63);
    std::fs::write(&path, format!("path:foo:bar\npath:{hex_like_path}\n"))
        .expect("write allowlist");

    let allowlist = Allowlist::load_with_metadata_policy(&path, false, false, None)
        .expect("explicit path entries should load");
    let _ = std::fs::remove_file(&path);

    assert!(allowlist.ignored_paths.iter().any(|path| path == "foo:bar"));
    assert!(
        allowlist
            .ignored_paths
            .iter()
            .any(|path| path == &hex_like_path)
    );
}
