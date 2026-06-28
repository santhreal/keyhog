//! Regression coverage for explicit Hyperscan cache-dir configuration.

#![cfg(feature = "simd")]

use keyhog_scanner::testing::{set_hyperscan_cache_dir, HsScanner};
use rusty_fork::rusty_fork_test;
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

rusty_fork_test! {
    #![rusty_fork(timeout_ms = 5000)]

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

    // The warm half of the ship-time precompile contract: a second compile of the
    // SAME patterns into the SAME cache dir must LOAD the persisted shard databases
    // rather than recompile them. This is what makes install-time calibration pay
    // off — the first real scan reuses the shards the installer warmed.
    //
    // Oracle: `persist_cached_shard` writes via a temp file + atomic rename, so a
    // re-persist REPLACES the shard file and gives it a new inode. A warm load never
    // calls persist, so the inode is untouched. An unchanged inode set therefore
    // proves the database was served from cache, not recompiled — a behavioral fact,
    // independent of filesystem mtime resolution.
    #[cfg(unix)]
    #[test]
    fn warm_cache_is_reused_in_place_on_recompile() {
        use std::os::unix::fs::MetadataExt;

        let _guard = CacheEnvGuard::poison_legacy_env();
        let home = dirs::home_dir().expect("home directory required for cache-dir allowlist");
        let root = tempfile::TempDir::new_in(home).expect("home tempdir");
        let cache_dir = root.path().join("hs-cache");
        set_hyperscan_cache_dir(Some(cache_dir.clone()));

        let patterns: &[(usize, usize, &str, bool)] = &[(0, 0, "khreuse_[A-Z0-9]{8}", false)];

        let shard_inodes = |dir: &std::path::Path| -> Vec<(std::path::PathBuf, u64)> {
            let mut found: Vec<(std::path::PathBuf, u64)> = match std::fs::read_dir(dir) {
                Ok(read_dir) => read_dir
                    .filter_map(|entry| {
                        let path = entry.expect("cache entry").path();
                        let is_shard = path
                            .file_name()
                            .and_then(|name| name.to_str())
                            .is_some_and(|name| name.starts_with("hs-") && name.ends_with(".db"));
                        is_shard.then(|| {
                            let inode = std::fs::metadata(&path).expect("stat shard").ino();
                            (path, inode)
                        })
                    })
                    .collect(),
                Err(_) => Vec::new(),
            };
            found.sort();
            found
        };

        // Cold compile: a cache miss compiles from patterns and atomically persists
        // the shard database(s) under the cache dir.
        let (_cold, cold_unsupported) =
            HsScanner::compile(patterns).expect("cold compile must succeed");
        assert!(cold_unsupported.is_empty(), "simple pattern should compile");
        let after_cold = shard_inodes(&cache_dir);
        assert!(
            !after_cold.is_empty(),
            "cold compile must persist at least one hs-*.db shard under {}",
            cache_dir.display()
        );

        // Warm compile of the SAME patterns into the SAME cache dir must serve the
        // persisted shard(s) without re-persisting them.
        let (_warm, warm_unsupported) =
            HsScanner::compile(patterns).expect("warm compile must succeed");
        assert_eq!(
            warm_unsupported, cold_unsupported,
            "warm compile must classify the same patterns as the cold compile"
        );
        let after_warm = shard_inodes(&cache_dir);
        assert_eq!(
            after_cold, after_warm,
            "warm recompile must reuse the persisted shard(s) in place (identical paths + inodes); \
             a changed inode means the shard was recompiled and re-persisted instead of loaded from cache"
        );
    }
}
