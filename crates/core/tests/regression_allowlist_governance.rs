//! Regression coverage for `.keyhogignore` metadata governance.

use keyhog_core::Allowlist;
use tempfile::TempDir;

fn write_allowlist(contents: &str) -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join(".keyhogignore");
    std::fs::write(&path, contents).expect("write allowlist");
    (dir, path)
}

#[test]
fn load_with_metadata_policy_rejects_missing_reason_and_approval() {
    let (_dir, path) = write_allowlist("detector:aws-access-key ; expires=2999-01-01\n");
    let err = Allowlist::load_with_metadata_policy(&path, true, true, None)
        .expect_err("missing governance metadata must fail closed");

    let msg = err.to_string();
    assert!(
        msg.contains("allowlist governance")
            && msg.contains("line 1")
            && msg.contains("reason")
            && msg.contains("approved_by")
            && msg.contains("refusing to scan with unapproved suppressions"),
        "governance error must name the missing fields and fix; got: {msg}"
    );
}

#[test]
fn load_with_metadata_policy_rejects_missing_expiry_when_max_days_is_set() {
    let (_dir, path) = write_allowlist(
        "detector:aws-access-key ; reason=\"noise\" ; approved_by=\"sec@example.com\"\n",
    );
    let err = Allowlist::load_with_metadata_policy(&path, false, false, Some(90))
        .expect_err("max_expires_days requires dated suppressions");

    let msg = err.to_string();
    assert!(
        msg.contains("expires")
            && msg.contains("max_expires_days")
            && msg.contains("line 1")
            && msg.contains("refusing to scan with unapproved suppressions"),
        "expiry policy error must be actionable; got: {msg}"
    );
}

#[test]
fn load_with_metadata_policy_rejects_expiry_beyond_max_days() {
    let (_dir, path) = write_allowlist(
        "detector:aws-access-key ; reason=\"noise\" ; approved_by=\"sec@example.com\" ; expires=2999-01-01\n",
    );
    let err = Allowlist::load_with_metadata_policy(&path, false, false, Some(90))
        .expect_err("overlong suppressions must fail closed");

    let msg = err.to_string();
    assert!(
        msg.contains("expires=2999-01-01")
            && msg.contains("more than 90 days")
            && msg.contains("line 1"),
        "overlong expiry error must name the configured limit; got: {msg}"
    );
}

#[test]
fn load_with_metadata_policy_rejects_unknown_metadata_keys() {
    let (_dir, path) =
        write_allowlist("detector:aws-access-key ; reasno=\"typo\" ; reason=\"noise\"\n");
    let err = Allowlist::load_with_metadata_policy(&path, false, false, None)
        .expect_err("unknown governance metadata keys must fail closed");

    let msg = err.to_string();
    assert!(
        msg.contains("allowlist governance")
            && msg.contains("line 1")
            && msg.contains("unknown key `reasno`")
            && msg.contains("supported keys are reason, expires, approved_by")
            && msg.contains("refusing to scan with unapproved suppressions"),
        "unknown metadata key error must name the typo and supported fields; got: {msg}"
    );
}

#[test]
fn load_with_metadata_policy_rejects_metadata_tokens_missing_equals() {
    let (_dir, path) =
        write_allowlist("detector:aws-access-key ; reason=\"noise\" ; expires 2099-01-01\n");
    let err = Allowlist::load_with_metadata_policy(&path, false, false, None)
        .expect_err("metadata tokens without equals must fail closed");

    let msg = err.to_string();
    assert!(
        msg.contains("allowlist governance")
            && msg.contains("line 1")
            && msg.contains("metadata token `expires 2099-01-01` is missing `=`")
            && msg.contains("refusing to scan with unapproved suppressions"),
        "missing equals error must name the malformed token; got: {msg}"
    );
}

#[test]
fn load_with_metadata_policy_rejects_unterminated_metadata_quotes() {
    let (_dir, path) =
        write_allowlist("detector:aws-access-key ; reason=\"unclosed ; expires=2099-01-01\n");
    let err = Allowlist::load_with_metadata_policy(&path, false, false, None)
        .expect_err("unterminated metadata quotes must fail closed");

    let msg = err.to_string();
    assert!(
        msg.contains("allowlist governance")
            && msg.contains("line 1")
            && msg.contains("unterminated")
            && msg.contains("quote")
            && msg.contains("refusing to scan with unapproved suppressions"),
        "unterminated quote error must name the syntax problem; got: {msg}"
    );
}

#[test]
fn load_with_metadata_policy_rejects_metadata_only_lines() {
    let (_dir, path) = write_allowlist("; reason=\"temporary suppression\"\n");
    let err = Allowlist::load_with_metadata_policy(&path, false, false, None)
        .expect_err("metadata-only allowlist lines must fail closed");

    let msg = err.to_string();
    assert!(
        msg.contains("allowlist governance")
            && msg.contains("line 1")
            && msg.contains("empty allowlist entry before metadata")
            && msg.contains("refusing to scan with unapproved suppressions"),
        "metadata-only line error must name the missing suppression entry; got: {msg}"
    );
}

#[test]
fn load_with_metadata_policy_rejects_malformed_explicit_entries() {
    for (entry, field, detail) in [
        (
            "hash:not-a-sha256\n",
            "hash",
            "must be a 64-character SHA-256 hex digest",
        ),
        ("detector:\n", "detector", "detector id must not be empty"),
        ("path:\n", "path", "path glob must not be empty"),
    ] {
        let (_dir, path) = write_allowlist(entry);
        let err = Allowlist::load_with_metadata_policy(&path, false, false, None)
            .expect_err("malformed explicit allowlist entries must fail closed");

        let msg = err.to_string();
        assert!(
            msg.contains("allowlist governance")
                && msg.contains("line 1")
                && msg.contains(field)
                && msg.contains(detail)
                && msg.contains("refusing to scan with unapproved suppressions"),
            "malformed {field} entry must be actionable; got: {msg}"
        );
    }
}

#[test]
fn load_with_metadata_policy_accepts_complete_metadata() {
    let (_dir, path) = write_allowlist(
        "detector:aws-access-key ; reason=\"known generated fixture\" ; approved_by=\"sec@example.com\" ; expires=2099-01-01\n",
    );
    let allowlist = Allowlist::load_with_metadata_policy(&path, true, true, Some(50_000))
        .expect("complete governance metadata must load");

    assert!(allowlist.ignored_detectors.contains("aws-access-key"));
}
