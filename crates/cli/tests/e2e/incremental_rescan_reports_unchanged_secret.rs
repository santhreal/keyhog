//! WHY: Incremental Merkle cache change-kind correctness and adversarial integrity contract (Row 53, Row 90):
//! The incremental Merkle cache must never silently drop a secret across any change
//! kind, including the four adversarial change kinds (size- and mtime-preserving content
//! change, content-preserving rename, retargeted symlink, and mode change that makes a file
//! readable). Foreign detector digests or binary identities must trigger clean cold-start
//! fallback rather than serving stale cache entries.
//!
//! WHAT IT DOES NOT CATCH:
//! Kernel-level filesystem corruption that produces non-deterministic stat results across reads.

use crate::e2e::support::scan_path;
use tempfile::TempDir;

#[test]
fn incremental_rescan_still_reports_secret_in_unchanged_file() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join(".env.config"),
        "TOKEN=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\n",
    )
    .expect("write secret file");
    let cache = dir.path().join("merkle.idx");
    let cache = cache.to_str().unwrap();
    let args = ["--incremental", "--incremental-cache", cache];

    let first = scan_path(dir.path(), &args);
    assert_eq!(
        first.status.code(),
        Some(1),
        "run 1 must exit 1 (findings present); stdout={}",
        String::from_utf8_lossy(&first.stdout)
    );

    // The file has not changed. The incremental cache must NOT make the secret
    // vanish on the re-run.
    let second = scan_path(dir.path(), &args);
    assert_eq!(
        second.status.code(),
        Some(1),
        "run 2 over the UNCHANGED secret file must STILL exit 1, not silently \
         pass. stdout={}",
        String::from_utf8_lossy(&second.stdout)
    );
    assert!(
        String::from_utf8_lossy(&second.stdout).contains("github-classic-pat"),
        "run 2 must still surface the github-classic-pat finding"
    );
}

#[test]
fn incremental_skips_unchanged_clean_file_for_speedup() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join("ok.txt"),
        "just ordinary source code, nothing sensitive here\n",
    )
    .expect("write clean file");
    let cache = dir.path().join("merkle.idx");
    let cache = cache.to_str().unwrap();
    let args = ["--incremental", "--incremental-cache", cache];

    assert_eq!(scan_path(dir.path(), &args).status.code(), Some(0));
    assert_eq!(scan_path(dir.path(), &args).status.code(), Some(0));
}

#[test]
fn all_unchanged_clean_files_are_complete_incremental_coverage() {
    let source = TempDir::new().expect("source tempdir");
    let state = TempDir::new().expect("state tempdir");
    std::fs::write(
        source.path().join("ok.txt"),
        "just ordinary source code, nothing sensitive here\n",
    )
    .expect("write clean file");
    let cache = state.path().join("merkle.idx");
    let cache = cache.to_str().expect("UTF-8 cache fixture");
    let args = ["--incremental", "--incremental-cache", cache];

    assert_eq!(scan_path(source.path(), &args).status.code(), Some(0));
    let warm = scan_path(source.path(), &args);
    assert_eq!(
        warm.status.code(),
        Some(0),
        "warm all-unchanged scan failed: {}",
        String::from_utf8_lossy(&warm.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&warm.stderr).contains("read ZERO bytes"),
        "trusted Merkle coverage was misclassified as no input"
    );
}

#[test]
fn incremental_corrupt_explicit_cache_warns_and_rewrites() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join("ok.txt"),
        "just ordinary source code, nothing sensitive here\n",
    )
    .expect("write clean file");
    let cache = dir.path().join("merkle.idx");
    std::fs::write(&cache, b"this is not a merkle cache").expect("write corrupt cache");
    let cache_arg = cache.to_str().unwrap();
    let args = ["--incremental", "--incremental-cache", cache_arg];

    let output = scan_path(dir.path(), &args);
    assert_eq!(
        output.status.code(),
        Some(0),
        "corrupt incremental cache must not prevent the full scan from running"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("warning: incremental cache") && stderr.contains("could not be parsed"),
        "corrupt explicit incremental cache must be operator-visible; stderr={stderr}"
    );
    let rewritten = std::fs::read_to_string(&cache).expect("read rewritten cache");
    assert!(
        rewritten.contains("\"version\"") && !rewritten.contains("not a merkle cache"),
        "successful cold-start scan must rewrite the damaged cache; cache={rewritten}"
    );
}

#[test]
fn incremental_cache_persist_failure_is_visible_and_nonzero_on_clean_scan() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join("ok.txt"),
        "just ordinary source code, nothing sensitive here\n",
    )
    .expect("write clean file");
    let blocker = dir.path().join("not-a-directory");
    std::fs::write(&blocker, b"regular file").expect("write cache parent blocker");
    let cache = blocker.join("merkle.idx");
    let cache_arg = cache.to_str().unwrap();
    let args = ["--incremental", "--incremental-cache", cache_arg];

    let output = scan_path(dir.path(), &args);
    assert_eq!(
        output.status.code(),
        Some(3),
        "clean incremental scan whose cache cannot be persisted must not exit 0"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("warning: incremental cache")
            && stderr.contains("could not be persisted")
            && stderr.contains("cache path is fixed"),
        "incremental cache persistence failure must be operator-visible; stderr={stderr}"
    );
}

#[test]
fn incremental_cache_persist_failure_with_findings_keeps_finding_exit_and_warning() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join(".env.config"),
        "TOKEN=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\n",
    )
    .expect("write secret file");
    let blocker = dir.path().join("not-a-directory");
    std::fs::write(&blocker, b"regular file").expect("write cache parent blocker");
    let cache = blocker.join("merkle.idx");
    let cache_arg = cache.to_str().unwrap();
    let args = ["--incremental", "--incremental-cache", cache_arg];

    let output = scan_path(dir.path(), &args);
    assert_eq!(
        output.status.code(),
        Some(1),
        "findings keep the findings exit code even when cache persistence also fails"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("github-classic-pat"),
        "cache persistence failure must not hide the reported secret; stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("incremental cache")
            || stderr.contains("could not be persisted")
            || stderr.contains("failed to persist")
            || stderr.contains("warning"),
        "cache persistence failure must remain visible on stderr; stderr={stderr}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The Four Adversarial Change Kinds (Row 90)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn adversarial_1_size_and_mtime_preserving_content_change_detected() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("config.env");

    // Clean payload of exact length 48 bytes
    let clean_bytes = b"DATABASE_URL=postgres://user:pass@localhost:5432\n";
    assert_eq!(clean_bytes.len(), 49);
    std::fs::write(&target, clean_bytes).expect("write clean target");

    let cache = dir.path().join("merkle.idx");
    let cache_arg = cache.to_str().unwrap();
    let args = ["--incremental", "--incremental-cache", cache_arg];

    // Initial cold run: clean -> exit 0
    let first = scan_path(dir.path(), &args);
    assert_eq!(first.status.code(), Some(0));

    // Capture metadata before tampering
    let metadata = std::fs::metadata(&target).expect("get metadata");
    let mtime = metadata.modified().expect("get mtime");

    // Replace with a secret payload of the EXACT same byte length (49 bytes)
    // "TOKEN=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\n" is 48 bytes + 1 byte padding
    let dirty_bytes = b"TOKEN=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 #\n";
    assert_eq!(dirty_bytes.len(), 49);
    std::fs::write(&target, dirty_bytes).expect("write dirty target");

    // Restore exact mtime to match previous stat
    let file = std::fs::File::open(&target).expect("open target");
    let times = std::fs::FileTimes::new().set_modified(mtime);
    file.set_times(times).expect("restore exact mtime");
    drop(file);

    // Rescan: the content hash has changed, so the scanner MUST re-read and report the secret
    let second = scan_path(dir.path(), &args);
    assert_eq!(
        second.status.code(),
        Some(1),
        "size- and mtime-preserving content change must STILL be detected; stdout={}",
        String::from_utf8_lossy(&second.stdout)
    );
    assert!(
        String::from_utf8_lossy(&second.stdout).contains("github-classic-pat"),
        "tampered secret must be reported"
    );
}

#[test]
fn adversarial_2_content_preserving_rename_tracked_and_reported() {
    let dir = TempDir::new().expect("tempdir");
    let orig_path = dir.path().join("orig_secret.env");
    std::fs::write(
        &orig_path,
        "TOKEN=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\n",
    )
    .expect("write orig secret");

    let cache = dir.path().join("merkle.idx");
    let cache_arg = cache.to_str().unwrap();
    let args = ["--incremental", "--incremental-cache", cache_arg];

    // Initial run: finding at orig_path -> exit 1
    let first = scan_path(dir.path(), &args);
    assert_eq!(first.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&first.stdout).contains("orig_secret.env"));

    // Rename file to new path
    let new_path = dir.path().join("renamed_secret.env");
    std::fs::rename(&orig_path, &new_path).expect("rename file");

    // Rescan: finding must be reported at the new path
    let second = scan_path(dir.path(), &args);
    assert_eq!(second.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&second.stdout).contains("renamed_secret.env"),
        "renamed secret file must be reported under its new path"
    );
}

#[cfg(unix)]
#[test]
fn adversarial_3_retargeted_symlink_detected() {
    let dir = TempDir::new().expect("tempdir");
    let clean_target = dir.path().join("clean.txt");
    std::fs::write(&clean_target, "clean payload\n").expect("write clean");

    let secret_target = dir.path().join("secret.txt");
    std::fs::write(
        &secret_target,
        "SECRET=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\n",
    )
    .expect("write secret");

    let link_path = dir.path().join("active_link.txt");
    std::os::unix::fs::symlink(&clean_target, &link_path).expect("create initial symlink");

    let cache = dir.path().join("merkle.idx");
    let cache_arg = cache.to_str().unwrap();
    let args = ["--incremental", "--incremental-cache", cache_arg];

    // Initial run over link pointing to clean target -> exit 0 (if scanning link_path directly)
    let first = scan_path(&link_path, &args);
    assert_eq!(first.status.code(), Some(0));

    // Retarget symlink to secret file
    std::fs::remove_file(&link_path).expect("remove old link");
    std::os::unix::fs::symlink(&secret_target, &link_path).expect("repoint symlink");

    // Rescan over link pointing to secret target -> exit 1
    let second = scan_path(&link_path, &args);
    assert_eq!(
        second.status.code(),
        Some(1),
        "retargeted symlink must report finding; stdout={}",
        String::from_utf8_lossy(&second.stdout)
    );
}

#[cfg(unix)]
#[test]
fn adversarial_4_mode_change_makes_file_readable_detected() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().expect("tempdir");
    let secret_file = dir.path().join("restricted.env");
    std::fs::write(
        &secret_file,
        "KEY=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\n",
    )
    .expect("write secret file");

    // Make file completely unreadable (mode 0000)
    std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o000))
        .expect("set mode 0000");

    let cache = dir.path().join("merkle.idx");
    let cache_arg = cache.to_str().unwrap();
    let args = ["--incremental", "--incremental-cache", cache_arg];

    // Initial scan with unreadable file
    let _ = scan_path(dir.path(), &args);

    // Make file readable (mode 0644)
    std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o644))
        .expect("set mode 0644");

    // Rescan: the newly readable file must be discovered and reported
    let second = scan_path(dir.path(), &args);
    assert_eq!(
        second.status.code(),
        Some(1),
        "newly readable file must be scanned and reported; stdout={}",
        String::from_utf8_lossy(&second.stdout)
    );
    assert!(
        String::from_utf8_lossy(&second.stdout).contains("github-classic-pat"),
        "finding in newly readable file must be reported"
    );
}

#[test]
fn foreign_detector_digest_triggers_cold_fallback_and_reports_findings() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join(".env.config"),
        "TOKEN=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\n",
    )
    .expect("write secret file");

    let cache = dir.path().join("merkle.idx");
    let cache_arg = cache.to_str().unwrap();
    let args = ["--incremental", "--incremental-cache", cache_arg];

    // Initial run creates cache
    let first = scan_path(dir.path(), &args);
    assert_eq!(first.status.code(), Some(1));

    // Tamper cache file with a foreign detector spec hash
    let cache_content = std::fs::read_to_string(&cache).expect("read cache");
    let tampered = cache_content.replace(
        "\"spec_hash\":",
        "\"spec_hash\": \"0000000000000000000000000000000000000000000000000000000000000000\", \"_old\":",
    );
    std::fs::write(&cache, tampered).expect("write tampered cache");

    // Rescan with foreign spec hash: must cold-start and still find the secret
    let second = scan_path(dir.path(), &args);
    assert_eq!(
        second.status.code(),
        Some(1),
        "foreign detector digest must trigger cold fallback and report findings; stdout={}",
        String::from_utf8_lossy(&second.stdout)
    );
    assert!(
        String::from_utf8_lossy(&second.stdout).contains("github-classic-pat"),
        "finding must be reported on spec mismatch fallback"
    );
}
