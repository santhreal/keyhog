//! Regression: `keyhog uninstall` must NAME the on-disk cache it leaves behind.
//!
//! Dogfood origin: a real `keyhog uninstall --yes` removed the binary and
//! printed a "manual cleanup" list (PATH export, completions, pre-commit hook)
//! but said NOTHING about `~/.cache/keyhog`: the compiled GPU rule catalogs +
//! detector/merkle cache, which can be ~GB. That silently orphaned real disk.
//! The fix surfaces the cache's real, current path when it exists so the user
//! can reclaim it (it is deliberately not auto-deleted, a reinstall reuses it
//! to skip the multi-second catalog recompile).
//!
//! This drives the actual binary with `XDG_CACHE_HOME` pointed at a temp dir
//! holding a `keyhog/` cache, runs the dry-run uninstall (no `--yes`, so the
//! binary is never touched), and asserts the cleanup hints name that path.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn uninstall_dry_run_names_the_cache_directory_when_present() {
    let cache_home = TempDir::new().expect("tempdir");
    // keyhog's cache root is `dirs::cache_dir()/keyhog`; on Linux dirs honors
    // XDG_CACHE_HOME, so plant the cache there to make the path deterministic.
    let keyhog_cache = cache_home.path().join("keyhog");
    std::fs::create_dir_all(keyhog_cache.join("programs")).expect("create cache");
    std::fs::write(keyhog_cache.join("programs").join("blob.bin"), b"x").expect("seed cache");

    let output = Command::new(binary())
        .arg("uninstall") // dry run: no --yes, so nothing is removed
        .env("XDG_CACHE_HOME", cache_home.path())
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn keyhog uninstall");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The dry-run must not have removed anything.
    assert!(
        keyhog_cache.is_dir(),
        "dry-run uninstall must not delete the cache"
    );
    // The cleanup hints must name the real cache path so it isn't orphaned.
    let cache_str = keyhog_cache.display().to_string();
    assert!(
        stdout.contains(&cache_str),
        "uninstall cleanup hints must name the cache dir {cache_str}; got:\n{stdout}"
    );
    // And it must label it as the keyhog cache (not just print a bare path).
    assert!(
        stdout.contains("cache"),
        "the cache hint must describe what the path is; got:\n{stdout}"
    );
}

#[test]
fn uninstall_dry_run_omits_cache_hint_when_absent() {
    // XDG_CACHE_HOME points at an EMPTY dir (no keyhog/ subdir), so the hint
    // must not fabricate a path that isn't there (no scary "remove ~/.cache/..."
    // for a cache the user never created).
    let cache_home = TempDir::new().expect("tempdir");

    let output = Command::new(binary())
        .arg("uninstall")
        .env("XDG_CACHE_HOME", cache_home.path())
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn keyhog uninstall");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let phantom = cache_home.path().join("keyhog").display().to_string();
    assert!(
        !stdout.contains(&phantom),
        "uninstall must not name a cache dir that does not exist; got:\n{stdout}"
    );
}
