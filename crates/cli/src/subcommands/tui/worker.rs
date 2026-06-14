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

use keyhog_core::{
    dedup_cross_detector, dedup_matches, Chunk, ChunkMetadata, DedupScope, DedupedMatch,
};
use keyhog_scanner::engine::CompiledScanner;
use rayon::prelude::*;

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
    let entries: Vec<PathBuf> = walk_files(&target, max_files, &counters);
    counters.files_total.store(entries.len(), Ordering::Relaxed);
    if let Ok(mut slot) = counters.current_file.write() {
        slot.clear();
    }

    let throttle = if throttle_ms == 0 {
        None
    } else {
        Some(Duration::from_millis(throttle_ms))
    };

    // Scan every file on the GLOBAL rayon pool — the SAME parallelism the
    // `keyhog scan` orchestrator uses — instead of the prior single-threaded
    // `for path in &entries` loop, which pinned the whole TUI scan to ONE core
    // (a 16-core box ran the live dashboard at 1/16th throughput, so findings
    // trickled in for "an insane amount of time"). `for_each_with` hands each
    // worker thread its own `Sender` clone (mpsc `Sender` is `Send` but not
    // `Sync`); the shared `counters`/`scanner`/`cancel` are all `Sync` (atomics
    // + an `Arc<CompiledScanner>`, exactly as the orchestrator shares them). The
    // channel closes when the last clone drops at the end of the parallel
    // for-each, which — together with the `done` flag — signals the UI.
    entries
        .par_iter()
        .for_each_with(sender, |sender, path| {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            // Best-effort banner update. `try_write` (not `write`) so a worker
            // never BLOCKS on the display lock under 16-way contention — the
            // banner is cosmetic, the scan must not serialize on it.
            if let Ok(mut slot) = counters.current_file.try_write() {
                *slot = path.display().to_string();
            }
            let bytes = match std::fs::read(path) {
                Ok(b) => b,
                Err(e) => {
                    // Walker promised this file existed, so a read failure here
                    // is interesting (permissions, mid-scan deletion, raced
                    // tmpfile). Surface it at debug level so a `--verbose` run
                    // sees the cause, and skip without inflating the bytes
                    // counter; the TUI then accurately reports "N of M files
                    // done" with N < M when files are unreadable.
                    tracing::debug!(
                        path = %path.display(),
                        error = %e,
                        "tui: skipping unreadable file"
                    );
                    counters.files_done.fetch_add(1, Ordering::Relaxed);
                    if let Some(d) = throttle {
                        std::thread::sleep(d);
                    }
                    return;
                }
            };
            let len_u64 = bytes.len() as u64;
            let Ok(data) = String::from_utf8(bytes) else {
                counters.files_done.fetch_add(1, Ordering::Relaxed);
                counters.bytes_done.fetch_add(len_u64, Ordering::Relaxed);
                if let Some(d) = throttle {
                    std::thread::sleep(d);
                }
                return;
            };
            let chunk = Chunk {
                data: data.into(),
                metadata: ChunkMetadata {
                    source_type: "filesystem".into(),
                    path: Some(path.display().to_string()),
                    ..Default::default()
                },
            };
            let deduped = dedup_file_findings(&scanner, &chunk);
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
        });
    counters.done.store(true, Ordering::Relaxed);
    if let Ok(mut slot) = counters.current_file.write() {
        slot.clear();
    }
}

/// Per-file dedup pipeline shared by the live TUI worker and its contract test.
///
/// Runs the SAME collapse `keyhog scan` applies before the reporter prints:
/// sort by severity descending, then `dedup_matches` (credential scope — the
/// scan default) to fold one credential surfaced by several paths, then
/// `dedup_cross_detector` to fold overlay detectors (entropy-token /
/// generic-secret) that fire on the same `ghp_` / `sk_live_` line. Without it
/// the live feed streams raw per-chunk hits and over-surfaces — the stats
/// `findings` count and the feed rows disagree with the `keyhog scan` reporter
/// (e.g. one `ghp_…` line shown three times by three detectors).
///
/// Scope is deliberately per-file: the streaming feed cannot buffer the whole
/// tree for cross-file credential dedup, which matches how each file's findings
/// appear as it is scanned. Two files holding the same literal secret therefore
/// surface once each, exactly as the live walk reaches them.
pub fn dedup_file_findings(scanner: &CompiledScanner, chunk: &Chunk) -> Vec<DedupedMatch> {
    let mut matches = scanner.scan(chunk);
    matches.sort_by_key(|m| std::cmp::Reverse(m.severity));
    dedup_cross_detector(dedup_matches(matches, &DedupScope::Credential))
}

fn walk_files(root: &Path, max_files: usize, counters: &Counters) -> Vec<PathBuf> {
    // Single-file target shortcut. `read_dir` on a file path returns
    // NotADirectory, which the loop's read below would count as an unreadable
    // directory, leaving `out` empty and the TUI showing "0 / 0 files scanned"
    // forever. Callers passing a single file (very common for `keyhog tui`
    // invoked from an IDE picker) expect that one file to be scanned.
    if root.is_file() {
        return vec![root.to_path_buf()];
    }

    let mut out: Vec<PathBuf> = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(error) => {
                // Law 10: a directory we cannot read drops its WHOLE subtree from
                // the scan. That recall loss must be visible, so count it (the
                // stats panel surfaces "N dirs unreadable") rather than silently
                // continuing. tracing is unavailable here — the alt-screen TUI
                // owns the terminal — so the counter IS the operator surface.
                let _ = error;
                counters.walk_skipped_dirs.fetch_add(1, Ordering::Relaxed);
                continue;
            }
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
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => {
                    // Can't tell file/dir/symlink: drop the entry but COUNT it so
                    // the operator sees the enumeration was incomplete (Law 10).
                    counters.walk_skipped_files.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
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
                match path.metadata() {
                    Ok(meta) => {
                        // Files over 4 MiB are an INTENTIONAL policy skip (the TUI
                        // targets source trees, not blobs), not a failure — no skip
                        // counter for those.
                        if meta.len() <= 4 * 1024 * 1024 {
                            out.push(path);
                            if max_files > 0 && out.len() >= max_files {
                                return out;
                            }
                        }
                    }
                    Err(_) => {
                        // metadata() failed (permission denied, TOCTOU race): we
                        // cannot size-check, so the file is dropped — but counted,
                        // never silently omitted from the denominator (Law 10).
                        counters.walk_skipped_files.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }
    out
}
