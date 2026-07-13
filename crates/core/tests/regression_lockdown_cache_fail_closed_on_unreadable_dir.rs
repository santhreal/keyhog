//! Regression: `lockdown_disk_cache_violations` must FAIL CLOSED when the
//! keyhog cache directory exists but cannot be inspected.
//!
//! The previous implementation ended the cache scan with `.unwrap_or(false)`,
//! so a `read_dir` error (e.g. an EACCES permission denial on a directory that
//! DOES exist and may hold a past-findings cache) was read as "clean" and
//! `--lockdown` would happily start with an unaudited artifact present, a
//! fail-OPEN security gate (Law 10). The fix distinguishes `NotFound`
//! (genuinely clean) from every other error (fail closed, surfaced loudly,
//! reported as a violation).
//!
//! Goes red if the gate regresses to fail-open on an unreadable cache dir.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

#[test]
fn unreadable_cache_dir_is_a_lockdown_violation_not_silently_clean() {
    // Running as root bypasses Unix permission bits, so the dir would be
    // readable regardless and the EACCES path is untestable. Skip there rather
    // than assert a false negative, but surface that we skipped, loudly, so a
    // root CI run does not silently lose this coverage.
    // SAFETY: libc::geteuid is a pure read of the effective uid.
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        eprintln!(
            "regression_lockdown_cache_fail_closed: skipped, running as root \
             (uid 0) bypasses directory permission bits; EACCES path untestable here"
        );
        return;
    }

    let cache_home = TempDir::new().expect("cache tempdir");
    // `dirs::cache_dir()` honors XDG_CACHE_HOME on Linux; on macOS it uses
    // ~/Library/Caches and ignores XDG, so restrict the asserting body to Linux.
    // SAFETY: single-threaded test setup; no other thread reads the env here.
    unsafe { std::env::set_var("XDG_CACHE_HOME", cache_home.path()) };

    let keyhog_cache = cache_home.path().join("keyhog");
    std::fs::create_dir_all(&keyhog_cache).expect("create keyhog cache dir");
    // Drop it with a past-findings artifact, then make the directory itself
    // unreadable/unsearchable so `read_dir` returns EACCES.
    std::fs::write(keyhog_cache.join("findings.json"), b"[]\n").expect("seed cache content");
    std::fs::set_permissions(&keyhog_cache, std::fs::Permissions::from_mode(0o000))
        .expect("chmod 000 the cache dir");

    let violations = keyhog_core::testing::CoreTestApi::lockdown_disk_cache_violations(
        &keyhog_core::testing::TestApi,
    );

    // Restore permissions so the TempDir can clean itself up.
    let _ = std::fs::set_permissions(&keyhog_cache, std::fs::Permissions::from_mode(0o700));

    #[cfg(target_os = "linux")]
    assert_eq!(
        violations,
        vec![keyhog_cache],
        "an unreadable keyhog cache dir must be reported as a lockdown violation \
         (fail closed), never silently treated as clean"
    );

    // On non-Linux unix the XDG override does not steer dirs::cache_dir(), so we
    // cannot assert the exact path; only require we did not panic and the fix
    // compiled. The Linux assertion above is the load-bearing oracle.
    #[cfg(not(target_os = "linux"))]
    let _ = violations;
}
