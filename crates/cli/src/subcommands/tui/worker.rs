//! Filesystem walker + scanner driver for `keyhog tui`.
//!
//! Spawned as a background `std::thread` from `mod.rs::run`. Walks the
//! target tree, scans each file directly against `CompiledScanner`,
//! and streams findings to the UI over an `mpsc::Sender`. Atomics in
//! the shared `Counters` struct drive the stats panel; the
//! `current_file` RwLock surfaces walker progress in the banner line.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use keyhog_core::{dedup_cross_detector, dedup_matches, Chunk, ChunkMetadata, DedupScope};
use keyhog_scanner::engine::CompiledScanner;

use super::{Counters, FindingEvent};

pub(super) fn scan_worker(
    target: PathBuf,
    scanner: Arc<CompiledScanner>,
    counters: Arc<Counters>,
    cancel: Arc<AtomicBool>,
    sender: std::sync::mpsc::Sender<FindingEvent>,
    max_files: usize,
    throttle_ms: u64,
) {
    // Surface the pre-walk in the banner so a `keyhog tui ~/code`
    // on a 50k-file tree doesn't look frozen for the second or two
    // we spend enumerating. The banner shows "discovering files in
    // <target>..." until walk_files returns; once we have a real
    // entries list, the per-file loop below overwrites this with
    // each path as it scans.
    if let Ok(mut slot) = counters.current_file.write() {
        *slot = format!("discovering files in {} ...", target.display());
    }
    let entries: Vec<PathBuf> = walk_files(&target, max_files);
    counters.files_total.store(entries.len(), Ordering::Relaxed);
    if let Ok(mut slot) = counters.current_file.write() {
        slot.clear();
    }

    let throttle = if throttle_ms == 0 {
        None
    } else {
        Some(Duration::from_millis(throttle_ms))
    };

    for path in &entries {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        // Surface the current file in the banner so the viewer sees
        // the walker actually moving through the tree. Truncated to a
        // sensible display width by the renderer.
        if let Ok(mut slot) = counters.current_file.write() {
            *slot = path.display().to_string();
        }
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                // Walker promised this file existed, so a read failure here
                // is interesting (permissions, mid-scan deletion, raced
                // tmpfile). Surface it at debug level so a `--verbose`
                // run sees the cause, and skip without inflating the
                // bytes counter; the TUI then accurately reports
                // "N of M files done" with N < M when files are
                // unreadable.
                tracing::debug!(
                    path = %path.display(),
                    error = %e,
                    "tui: skipping unreadable file"
                );
                counters.files_done.fetch_add(1, Ordering::Relaxed);
                if let Some(d) = throttle {
                    std::thread::sleep(d);
                }
                continue;
            }
        };
        let len_u64 = bytes.len() as u64;
        let Ok(data) = String::from_utf8(bytes) else {
            counters.files_done.fetch_add(1, Ordering::Relaxed);
            counters.bytes_done.fetch_add(len_u64, Ordering::Relaxed);
            if let Some(d) = throttle {
                std::thread::sleep(d);
            }
            continue;
        };
        let chunk = Chunk {
            data: data.into(),
            metadata: ChunkMetadata {
                source_type: "filesystem".into(),
                path: Some(path.display().to_string()),
                ..Default::default()
            },
        };
        // Dedup to the SAME findings `keyhog scan` reports rather than streaming
        // raw per-chunk hits: `dedup_matches` (credential scope — the scan
        // default) collapses the same credential found by multiple paths, and
        // `dedup_cross_detector` collapses overlay detectors firing on one line
        // (e.g. entropy-token / generic-secret on a `ghp_`/`sk_live_` line).
        // Without this the live feed over-surfaces — 11 rows where `keyhog scan`
        // reports 4 — and the stats `findings` count disagrees with the scan
        // reporter. Dedup is per-file (the streaming feed can't buffer the whole
        // tree for cross-file credential dedup), which matches how each file's
        // findings appear as it is scanned.
        let mut matches = scanner.scan(&chunk);
        matches.sort_by_key(|m| std::cmp::Reverse(m.severity));
        let deduped =
            dedup_cross_detector(dedup_matches(matches, &DedupScope::Credential));
        counters
            .findings_total
            .fetch_add(deduped.len(), Ordering::Relaxed);
        for m in &deduped {
            let _ = sender.send(FindingEvent::from(m));
        }
        counters.files_done.fetch_add(1, Ordering::Relaxed);
        counters.bytes_done.fetch_add(len_u64, Ordering::Relaxed);
        if let Some(d) = throttle {
            std::thread::sleep(d);
        }
    }
    counters.done.store(true, Ordering::Relaxed);
    if let Ok(mut slot) = counters.current_file.write() {
        slot.clear();
    }
    drop(sender);
}

fn walk_files(root: &Path, max_files: usize) -> Vec<PathBuf> {
    // Single-file target shortcut. `read_dir` on a file path returns
    // NotADirectory, which the loop's `let Ok(rd) = ... else continue`
    // would silently swallow, leaving `out` empty and the TUI showing
    // "0 / 0 files scanned" forever. Callers passing a single file
    // (very common for `keyhog tui` invoked from an IDE picker)
    // expect that one file to be scanned.
    if root.is_file() {
        return vec![root.to_path_buf()];
    }

    let mut out: Vec<PathBuf> = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('.') && (name == ".git" || name == ".cache" || name == ".idea") {
                continue;
            }
            // Use the dir-entry's own file type, which does NOT follow symlinks,
            // and skip symlinks entirely. `path.is_dir()` calls metadata() and
            // follows links, so a directory symlink pointing at an ancestor
            // (`proj/link -> ..`) made this manual DFS descend forever — re-pushing
            // the same subtree onto `stack` and growing `out` without bound.
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                if name == "target" || name == "node_modules" || name == "vendor" {
                    continue;
                }
                stack.push(path);
            } else if file_type.is_file() {
                if let Ok(meta) = path.metadata() {
                    if meta.len() <= 4 * 1024 * 1024 {
                        out.push(path);
                        if max_files > 0 && out.len() >= max_files {
                            return out;
                        }
                    }
                }
            }
        }
    }
    out
}
