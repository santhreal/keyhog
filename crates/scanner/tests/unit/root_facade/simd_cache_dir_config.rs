//! Regression coverage for explicit Hyperscan cache-dir configuration.

#![cfg(feature = "simd")]

use keyhog_scanner::testing::{set_hyperscan_cache_dir, HsScanner};
use std::ffi::OsString;

struct CacheEnvGuard {
    original: Option<OsString>,
}

impl CacheEnvGuard {
    fn poison_legacy_env() -> Self {
        let original = std::env::var_os("KEYHOG_CACHE_DIR");
        let poison = std::env::temp_dir().join("keyhog-cache-dir-must-be-ignored");
        std::env::set_var("KEYHOG_CACHE_DIR", poison);
        Self { original }
    }
}

impl Drop for CacheEnvGuard {
    fn drop(&mut self) {
        set_hyperscan_cache_dir(None);
        match self.original.take() {
            Some(value) => std::env::set_var("KEYHOG_CACHE_DIR", value),
            None => std::env::remove_var("KEYHOG_CACHE_DIR"),
        }
    }
}

#[test]
fn explicit_cache_dir_wins_and_legacy_env_is_ignored() {
    let _guard = CacheEnvGuard::poison_legacy_env();
    let home = dirs::home_dir().expect("home directory required for cache-dir allowlist");
    let root = tempfile::TempDir::new_in(home).expect("home tempdir");
    let cache_dir = root.path().join("hs-cache");
    set_hyperscan_cache_dir(Some(cache_dir.clone()));

    let (_scanner, unsupported) = HsScanner::compile(&[(0, 0, "khcache_[A-Z0-9]{8}", false)])
        .expect("explicit cache dir must compile despite poisoned legacy env");
    assert!(unsupported.is_empty(), "simple pattern should compile");

    let entries: Vec<_> = std::fs::read_dir(&cache_dir)
        .expect("explicit cache dir exists")
        .map(|entry| entry.expect("cache entry").path())
        .collect();
    assert!(
        entries.iter().any(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("hs-") && name.ends_with(".db"))
        }),
        "expected a Hyperscan cache database under {}; entries={entries:?}",
        cache_dir.display()
    );
}
