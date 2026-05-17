//! E4 + E5 substrate: cross-process persistent CUDA JIT cache wiring.
//!
//! The CUDA driver ships its own JIT cache that persists compiled
//! modules to disk and reuses them across processes. This module
//! configures it once at backend startup so vyre dispatches benefit
//! without per-process re-JIT cost.
//!
//! NVIDIA controls the cache through three environment variables:
//!   - `CUDA_CACHE_DISABLE` — set to `0` to force-enable.
//!   - `CUDA_CACHE_PATH` — directory for cached cuBIN artifacts.
//!   - `CUDA_CACHE_MAXSIZE` — soft byte ceiling (defaults to 256 MB).
//!
//! We pick a vyre-namespaced path under the user's XDG cache so the
//! cache is shared by every process that links `vyre-driver-cuda` on
//! the same host (E5: cross-process), and the artifacts persist across
//! reboots (E4: persistent across runs). Configuration is idempotent —
//! callers that have already set any of the three vars keep their
//! choice. Configuration happens once via a `Once` so multi-threaded
//! backend bring-up does not race.

use std::path::PathBuf;
use std::sync::Once;

const CUDA_CACHE_DISABLE: &str = "CUDA_CACHE_DISABLE";
const CUDA_CACHE_PATH: &str = "CUDA_CACHE_PATH";
const CUDA_CACHE_MAXSIZE: &str = "CUDA_CACHE_MAXSIZE";

/// Default cache size: 1 GiB. The CUDA driver's built-in default of
/// 256 MiB evicts faster than we want on workloads with many distinct
/// kernel shapes (autotune sweeps, large matmul tilings).
const DEFAULT_MAX_BYTES: u64 = 1 * 1024 * 1024 * 1024;

static CONFIGURED: Once = Once::new();

/// Configure the CUDA driver JIT cache for this process. Call once at
/// CUDA backend bring-up; subsequent calls are no-ops. The function is
/// thread-safe.
pub fn configure_jit_cache_default() {
    CONFIGURED.call_once(|| {
        configure_jit_cache(default_cache_root(), DEFAULT_MAX_BYTES);
    });
}

/// Plumb the JIT cache to an explicit directory. Mostly for tests; in
/// production the `_default()` entry point picks an XDG path.
pub fn configure_jit_cache(cache_dir: PathBuf, max_bytes: u64) {
    // Honour caller overrides — if the operator already set any of the
    // three vars, leave their decision alone. This means a sandboxed
    // environment or CI runner can opt out by setting
    // `CUDA_CACHE_DISABLE=1` in the parent process.
    if std::env::var_os(CUDA_CACHE_DISABLE).is_none() {
        // SAFETY: env-var mutation requires unsafe in Rust 2024 because
        // it is process-global state shared with C-string getenv readers.
        // We restrict mutation to the `Once` callsite (configure_jit_cache_default)
        // so backend bring-up is the only writer; everything past
        // bring-up is read-only.
        unsafe {
            std::env::set_var(CUDA_CACHE_DISABLE, "0");
        }
    }
    if std::env::var_os(CUDA_CACHE_PATH).is_none() {
        // Make sure the directory exists; the CUDA driver will not
        // create it for us. If creation fails, leave CUDA_CACHE_PATH
        // unset and surface the configuration bug instead of pointing
        // the driver at a path known to be unusable.
        match std::fs::create_dir_all(&cache_dir) {
            Ok(()) => unsafe {
                std::env::set_var(CUDA_CACHE_PATH, &cache_dir);
            },
            Err(error) => eprintln!(
                "Fix: failed to create CUDA JIT cache directory `{}`: {error}. Set CUDA_CACHE_PATH to a writable directory before dispatch.",
                cache_dir.display()
            ),
        }
    }
    if std::env::var_os(CUDA_CACHE_MAXSIZE).is_none() {
        unsafe {
            std::env::set_var(CUDA_CACHE_MAXSIZE, max_bytes.to_string());
        }
    }
}

/// Choose the default cache root: `$XDG_CACHE_HOME/vyre/cuda-jit` when
/// XDG is set, else `$HOME/.cache/vyre/cuda-jit`, else `/tmp/vyre/cuda-jit`.
fn default_cache_root() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(xdg).join("vyre").join("cuda-jit");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".cache")
            .join("vyre")
            .join("cuda-jit");
    }
    PathBuf::from("/tmp/vyre/cuda-jit")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All four scenarios live in one test because they mutate
    /// process-global env state and `cargo test` runs tests in
    /// parallel; splitting them would race on the shared CUDA_CACHE_*
    /// vars and produce non-deterministic results. Sequenced inside
    /// one function with explicit reset between scenarios.
    fn reset_env() {
        // SAFETY: tests are the only env writers outside backend
        // bring-up; sequential mutation is safe inside one test.
        unsafe {
            std::env::remove_var(CUDA_CACHE_DISABLE);
            std::env::remove_var(CUDA_CACHE_PATH);
            std::env::remove_var(CUDA_CACHE_MAXSIZE);
        }
    }

    #[test]
    fn jit_cache_env_contract() {
        // Scenario 1: all three vars get set when the operator hasn't
        // pre-configured anything. Cache directory is created.
        reset_env();
        let dir = std::env::temp_dir().join("vyre-jit-cache-test-1");
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!(
                "Fix: failed to remove stale CUDA JIT cache test directory `{}`: {error}",
                dir.display()
            ),
        }
        configure_jit_cache(dir.clone(), 12_345);
        assert_eq!(std::env::var(CUDA_CACHE_DISABLE).unwrap(), "0");
        assert_eq!(
            std::env::var(CUDA_CACHE_PATH).unwrap(),
            dir.to_string_lossy()
        );
        assert_eq!(std::env::var(CUDA_CACHE_MAXSIZE).unwrap(), "12345");
        assert!(dir.is_dir(), "cache directory must be created");

        // Scenario 2: existing CUDA_CACHE_DISABLE=1 is preserved
        // (operator opt-out).
        reset_env();
        unsafe {
            std::env::set_var(CUDA_CACHE_DISABLE, "1");
        }
        let dir2 = std::env::temp_dir().join("vyre-jit-cache-test-2");
        configure_jit_cache(dir2, 1024);
        assert_eq!(
            std::env::var(CUDA_CACHE_DISABLE).unwrap(),
            "1",
            "operator opt-out must be preserved"
        );

        // Scenario 3: existing CUDA_CACHE_PATH is preserved.
        reset_env();
        let custom = PathBuf::from("/tmp/operator-chosen-jit-path");
        unsafe {
            std::env::set_var(CUDA_CACHE_PATH, &custom);
        }
        let other = std::env::temp_dir().join("vyre-jit-cache-test-3");
        configure_jit_cache(other, 1024);
        assert_eq!(
            std::env::var(CUDA_CACHE_PATH).unwrap(),
            custom.to_string_lossy()
        );

        // Scenario 4: default_cache_root() routes through XDG when set.
        let xdg_before = std::env::var_os("XDG_CACHE_HOME");
        unsafe {
            std::env::set_var("XDG_CACHE_HOME", "/tmp/my-xdg-cache");
        }
        let root = default_cache_root();
        assert_eq!(root, PathBuf::from("/tmp/my-xdg-cache/vyre/cuda-jit"));
        unsafe {
            match xdg_before {
                Some(v) => std::env::set_var("XDG_CACHE_HOME", v),
                None => std::env::remove_var("XDG_CACHE_HOME"),
            }
        }

        // Final cleanup so other tests in the crate see a clean env.
        reset_env();
    }
}
