use codewalk::WalkConfig;
use std::collections::HashSet;
use std::path::Path;

use super::skip_lists::{SKIP_DIRS, SKIP_EXTENSIONS};

/// Check if a path matches the built-in default exclusion patterns.
pub(super) fn is_default_excluded(path: &str) -> bool {
    let bytes = path.as_bytes();
    let ends_ci = |suffix: &[u8]| -> bool {
        bytes.len() >= suffix.len()
            && bytes[bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    };

    const SUFFIXES: &[&[u8]] = &[
        b".min.js",
        b".min.css",
        b".bak",
        b".swp",
        b".tmp",
        b".map",
        b".cache",
    ];
    if SUFFIXES.iter().any(|s| ends_ci(s)) {
        return true;
    }

    const SKIP_SEGMENTS: &[&[u8]] = &[
        b"node_modules",
        b".git",
        b"__pycache__",
        b"vendor",
        b"dist",
        b"build",
        b"out",
    ];
    let mut filename: &[u8] = bytes;
    for segment in path.split(['/', '\\']) {
        let seg_bytes = segment.as_bytes();
        if SKIP_SEGMENTS
            .iter()
            .any(|skip| seg_bytes.eq_ignore_ascii_case(skip))
        {
            return true;
        }
        if !seg_bytes.is_empty() {
            filename = seg_bytes;
        }
    }

    const FILENAMES: &[&[u8]] = &[
        b"package-lock.json",
        b"yarn.lock",
        b"pnpm-lock.yaml",
        b"cache.json",
        b"cargo.lock",
        b"go.sum",
        b"gemfile.lock",
        b"angular.json",
    ];
    if FILENAMES
        .iter()
        .any(|name| filename.eq_ignore_ascii_case(name))
    {
        return true;
    }

    let tsc = b"tsconfig";
    let json = b".json";
    if filename.len() >= tsc.len() + json.len()
        && filename[..tsc.len()].eq_ignore_ascii_case(tsc)
        && filename[filename.len() - json.len()..].eq_ignore_ascii_case(json)
    {
        return true;
    }

    false
}

pub(super) fn file_mtime_ns(path: &Path) -> Option<u64> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let dur = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    let nanos = dur.as_secs() as u128 * 1_000_000_000 + dur.subsec_nanos() as u128;
    Some(u64::try_from(nanos).unwrap_or(u64::MAX))
}

pub(super) fn walker_config(max_file_size: u64, ignore_paths: &[String]) -> WalkConfig {
    let mut exclude_extensions = HashSet::new();
    exclude_extensions.extend(SKIP_EXTENSIONS.iter().map(|ext| (*ext).to_string()));

    let mut exclude_dirs = HashSet::new();
    exclude_dirs.extend(SKIP_DIRS.iter().map(|dir| (*dir).to_string()));

    let ignore_overrides = ignore_paths
        .iter()
        .map(|pattern| {
            if pattern.starts_with('!') {
                pattern.clone()
            } else {
                format!("!{pattern}")
            }
        })
        .collect();

    let _ = max_file_size;

    WalkConfig::default()
        .max_file_size(0)
        .follow_symlinks(false)
        .respect_gitignore(true)
        .skip_hidden(false)
        .skip_binary(false)
        .exclude_extensions(exclude_extensions)
        .exclude_dirs(exclude_dirs)
        .ignore_files(vec![".keyhogignore".to_string()])
        .ignore_patterns(ignore_overrides)
}
