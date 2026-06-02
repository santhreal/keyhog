//! E2E regression: `--incremental` must NEVER silently drop a secret that
//! lives in an unchanged file.
//!
//! The merkle cache skips files whose content hash is unchanged for a big
//! speedup, but a secret in an unchanged file is still a leak. Before the fix,
//! the second `--incremental` run skipped the secret-bearing file and exited 0,
//! so a monorepo whose secret had been committed earlier (file now unchanged)
//! would report CLEAN and the leak would ship. The fix never caches a file that
//! produced a finding, so secret-bearing files are always re-scanned and
//! re-reported while clean files stay cached.

use crate::e2e::support::scan_path;
use tempfile::TempDir;

#[test]
fn incremental_rescan_still_reports_secret_in_unchanged_file() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join("config.env"),
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
        "run 1 must flag the secret (exit 1)"
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
    // The other half of the contract: a CLEAN file IS cached and skipped, so
    // the speedup the flag promises is preserved. Both runs exit 0.
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
