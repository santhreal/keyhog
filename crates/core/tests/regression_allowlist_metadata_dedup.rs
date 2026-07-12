//! Inline-metadata governance: a repeated `reason`/`expires`/`approved_by`
//! key must not silently override (Law 10) - it fails the load closed - and a
//! backslash-escaped quote inside a quoted value must parse cleanly, matching
//! the tokenizer's escape handling.

use keyhog_core::testing::{CoreTestApi, TestApi};
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
    let path = temp_allowlist_path("metadedup");
    std::fs::write(&path, content).expect("write allowlist");
    let err = Allowlist::load_with_metadata_policy(&path, false, false, None)
        .expect_err("duplicate metadata key must fail closed");
    let _ = std::fs::remove_file(&path);
    err.to_string()
}

fn load_ok(content: &str) -> Allowlist {
    let path = temp_allowlist_path("metaok");
    std::fs::write(&path, content).expect("write allowlist");
    let al = Allowlist::load_with_metadata_policy(&path, false, false, None)
        .expect("clean metadata must load");
    let _ = std::fs::remove_file(&path);
    al
}

#[test]
fn duplicate_reason_key_fails_closed_not_silently_overridden() {
    let err = load_error("detector:foo ; reason=\"first\" ; reason=\"second\"\n");
    assert!(
        err.contains("duplicate metadata key `reason`") && err.contains("refusing to scan"),
        "duplicate reason must be an operator-visible load error, got: {err}"
    );
}

#[test]
fn duplicate_expires_key_fails_closed() {
    let err = load_error("detector:foo ; expires=2099-01-01 ; expires=2098-01-01\n");
    assert!(
        err.contains("duplicate metadata key `expires`") && err.contains("refusing to scan"),
        "duplicate expires must fail closed, got: {err}"
    );
}

#[test]
fn duplicate_approved_by_key_fails_closed() {
    let err = load_error("detector:foo ; approved_by=\"a\" ; approved_by=\"b\"\n");
    assert!(
        err.contains("duplicate metadata key `approved_by`"),
        "duplicate approved_by must fail closed, got: {err}"
    );
}

#[test]
fn escaped_quote_inside_value_loads_and_preserves_entry() {
    // `reason="a\"b"` is one token to the metadata splitter; it must not be
    // flagged as an unterminated quote and the entry must survive.
    let al = load_ok("detector:bar ; reason=\"a\\\"b\"\n");
    assert!(
        al.ignored_detectors.contains("bar"),
        "entry with an escaped-quote reason must be retained"
    );
}

#[test]
fn parse_preserves_entry_on_duplicate_key() {
    // Parse-only recovery mirrors the unknown-key contract: the suppression is
    // still recovered even though the load path rejects it.
    let al = CoreTestApi::allowlist_parse(&TestApi, "detector:bar ; reason=a ; reason=b");
    assert!(al.ignored_detectors.contains("bar"));
}
