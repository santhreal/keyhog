//! Migrated from `src/safe_bin.rs` inline tests.
use keyhog_core::safe_bin::resolve_safe_bin;
#[test]
#[cfg(unix)]
fn resolves_sh_to_known_path() {
    // `/bin/sh` exists on every Unix variant we ship to.
    let resolved = resolve_safe_bin("sh").expect("sh should resolve");
    assert!(resolved.is_absolute());
    assert!(resolved.ends_with("sh"));
}
