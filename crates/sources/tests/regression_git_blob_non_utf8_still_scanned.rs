//! Regression (audit C4): the git blob source must scan files that contain a
//! single non-UTF-8 byte, not silently drop the whole blob.
//!
//! Before the fix, `stream_git_blobs` decoded blobs with
//! `std::str::from_utf8(&data).ok()?` - any non-UTF-8 byte made the closure
//! return `None`, so a credential sitting next to a stray high byte (latin-1
//! config, a `.env` with a smart quote, a key beside binary data) was found by
//! `keyhog scan <dir>` (filesystem, lossy decode) but MISSED by
//! `keyhog scan --git` on the exact same content. The fix mirrors the
//! filesystem decode contract: lossy UTF-8 after a binary-density check, so a
//! single bad byte no longer discards the blob.
//!
//! Exercised through the public `Source` streaming API (`GitSource::chunks`).

#![cfg(feature = "git")]

use std::path::Path;
use std::process::Command;

use keyhog_core::Source;
use keyhog_sources::GitSource;

fn git(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .unwrap_or_else(|e| panic!("git {args:?} failed to spawn: {e}"));
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn git_source_scans_blob_with_non_utf8_byte() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path();

    git(repo, &["init", "-b", "main"]);
    git(repo, &["config", "user.email", "c4@test.example"]);
    git(repo, &["config", "user.name", "C4 Regression"]);

    // A config blob that is valid text except for one non-UTF-8 byte (0x92,
    // a Windows-1252 "smart quote") in a comment, alongside a real AWS key.
    // 0x92 is a lone continuation-style byte that is NOT valid UTF-8, so the
    // old strict `from_utf8` decode would have dropped this entire blob.
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"# don\x92t lose this file\n");
    bytes.extend_from_slice(b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n");
    assert!(
        std::str::from_utf8(&bytes).is_err(),
        "fixture must be non-UTF-8 to exercise the decode fallback"
    );

    std::fs::write(repo.join("config.ini"), &bytes).expect("write fixture");
    git(repo, &["add", "config.ini"]);
    git(repo, &["commit", "-m", "add config with stray high byte"]);

    let bodies: Vec<String> = GitSource::new(repo.to_path_buf())
        .with_max_commits(1)
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();

    assert!(
        bodies.iter().any(|b| b.contains("AKIAIOSFODNN7EXAMPLE")),
        "git source must still surface a credential from a blob containing a \
         non-UTF-8 byte (lossy decode contract); got {bodies:?}"
    );
    // The stray byte should have been replaced (lossy), not have aborted the
    // blob: the surrounding text is preserved and scannable.
    assert!(
        bodies.iter().any(|b| b.contains("lose this file")),
        "lossy decode must preserve the surrounding text; got {bodies:?}"
    );
}
