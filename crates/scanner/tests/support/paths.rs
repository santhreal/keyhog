//! Shared filesystem path helpers for scanner integration tests.

use std::path::{Path, PathBuf};

/// Returns the absolute path to `crates/scanner/../detectors` (the on-disk Tier-B
/// detector TOML directory), computed from `CARGO_MANIFEST_DIR` so tests stay
/// stable across `cargo test`, `cargo nextest`, and remote runners that move cwd.
pub fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

/// Returns the absolute path to the on-disk `benchmarks/corpora/mirror/corpus`
/// tree (real-world source files used as representative scan input), computed
/// from `CARGO_MANIFEST_DIR` so measurement tests stay stable regardless of cwd.
/// Returns `None` if the tree is absent (e.g. a checkout without benchmark
/// corpora) so callers can fall back to a synthetic payload instead of failing.
pub fn corpus_dir() -> Option<PathBuf> {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("benchmarks");
    d.push("corpora");
    d.push("mirror");
    d.push("corpus");
    d.is_dir().then_some(d)
}

/// Read a deterministic, bounded slice of the mirror corpus.
///
/// A present-but-partially-unreadable corpus is a broken measurement input, not
/// an excuse to time or compare a silently smaller dataset.
pub fn corpus_files(root: &Path, limit: usize) -> Vec<Vec<u8>> {
    corpus_files_with_paths(root, limit)
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect()
}

/// Read a deterministic, bounded slice of the mirror corpus, preserving labels
/// for per-file diagnostics.
pub fn corpus_files_with_paths(root: &Path, limit: usize) -> Vec<(String, Vec<u8>)> {
    if limit == 0 {
        return Vec::new();
    }

    corpus_paths(root)
        .into_iter()
        .take(limit)
        .map(|path| {
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|e| panic!("read mirror corpus file {}: {e}", path.display()));
            (path.to_string_lossy().into_owned(), bytes)
        })
        .collect()
}

/// Concatenate corpus files until `limit_bytes` is reached.
pub fn corpus_bytes(root: &Path, limit_bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(limit_bytes);
    for path in corpus_paths(root) {
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("read mirror corpus file {}: {e}", path.display()));
        out.extend_from_slice(&bytes);
        out.push(b'\n');
        if out.len() >= limit_bytes {
            out.truncate(limit_bytes);
            return out;
        }
    }
    out
}

fn corpus_paths(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries = Vec::new();
        let iter = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read mirror corpus dir {}: {e}", dir.display()));
        for entry in iter {
            let entry = entry
                .unwrap_or_else(|e| panic!("read mirror corpus dir entry {}: {e}", dir.display()));
            entries.push(entry.path());
        }
        entries.sort();

        for path in entries {
            let meta = std::fs::metadata(&path)
                .unwrap_or_else(|e| panic!("stat mirror corpus entry {}: {e}", path.display()));
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                paths.push(path);
            } else {
                panic!(
                    "unsupported mirror corpus entry type {}: expected file or directory",
                    path.display()
                );
            }
        }
    }
    paths.sort();
    paths
}
