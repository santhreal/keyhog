//! `keyhog watch <path>` - daemon mode.
//!
//! Tier-B moat innovation #7 from docs/EXECUTION_PLAN.md: compile-once,
//! scan-many. The detector corpus + Hyperscan database are built ONCE at
//! startup; subsequent scans on a saved file run in O(file_size) without
//! the ~50-100 ms compile overhead a fresh `keyhog scan` invocation pays.
//!
//! Architecture:
//!   1. Compile a `CompiledScanner` once.
//!   2. Walk the path with `notify::recommended_watcher` (inotify on Linux,
//!      FSEvents on macOS, ReadDirectoryChangesW on Windows).
//!   3. On `Modify` or `Create` events: read the file, build a Chunk, select
//!      the persisted calibrated backend, scan, and print findings to stdout.
//!   4. Block on the channel forever; Ctrl-C exits cleanly.
//!
//! No batching, no orchestrator: a single saved file is the natural scan
//! unit for an editor workflow. If the user wants a directory-wide rescan
//! they can always invoke `keyhog scan` separately.

use crate::args::WatchArgs;
use crate::orchestrator::{DefaultScanRuntime, setup_default_scan_runtime};
use crate::skip_dirs::SkipDirPolicy;
use crate::style;
use anyhow::{Context, Result};
use keyhog_core::{Chunk, ChunkMetadata};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::time::{Duration, Instant};

/// Within this window, a repeat event for the *same path and same content*
/// (e.g. the Create+Modify burst notify emits for a single new-file write,
/// KH-GAP-109) is suppressed so we print one finding set per real change,
/// not one per inotify event. A genuine later edit (different content) is
/// always re-scanned because the content hash changes.
const DEDUP_WINDOW: Duration = Duration::from_millis(750);
const DEDUP_PRUNE_INTERVAL: usize = 128;

#[derive(Default)]
struct WatchDedupeState {
    entries: HashMap<PathBuf, (Instant, u64)>,
    scans_since_prune: usize,
}

pub(crate) fn run(args: WatchArgs) -> Result<()> {
    let watch_root = std::fs::canonicalize(&args.path)
        .with_context(|| format!("canonicalize {}", args.path.display()))?;
    if !watch_root.is_dir() {
        anyhow::bail!(
            "watch path '{}' is not a directory. \
             Fix: pass a directory to monitor, or run `keyhog scan {}` for a one-shot file scan.",
            watch_root.display(),
            watch_root.display()
        );
    }

    let scan_runtime = setup_default_scan_runtime(
        &args.detectors,
        args.cache_dir.clone(),
        None,
        "keyhog watch",
        false,
    )?;
    let detector_count = scan_runtime.detector_count();

    if !args.quiet {
        eprintln!(
            "\u{1F441}  keyhog watch (\u{2630} {} detectors compiled)",
            detector_count
        );
        eprintln!("    watching: {}", watch_root.display());
        eprintln!("    Ctrl-C to exit");
        eprintln!();
    }

    let (tx, rx) = channel::<notify::Result<Event>>();
    let notify_channel_closed_for_callback = AtomicBool::new(false);
    let watch_root_for_callback = watch_root.clone();

    // Hold the watcher for the duration of the daemon. The `notify` crate
    // requires us to keep the handle alive; dropping it stops the watcher.
    let mut watcher = notify::recommended_watcher(move |res| {
        // notify hands events on its own thread; forward to the main loop.
        if tx.send(res).is_err()
            && !notify_channel_closed_for_callback.swap(true, Ordering::Relaxed)
        {
            let palette = style::for_stderr();
            eprintln!(
                "{} keyhog watch: internal watcher event channel closed; a filesystem \
                 event could not be delivered and the changed path was NOT re-scanned. \
                 Restart watch, or run `keyhog scan {}` for a full one-shot rescan.",
                style::warn("WARN", &palette),
                watch_root_for_callback.display()
            );
        }
    })
    .map_err(|e| {
        anyhow::anyhow!(
            "failed to build filesystem watcher for {root}: {e}\n  \
             Fix: on Linux raise watcher limits with:\n    \
             sudo sysctl fs.inotify.max_user_instances=1024 fs.inotify.max_user_watches=524288\n  \
             then retry, or run `keyhog scan {root}` for a one-shot scan.",
            root = watch_root.display(),
        )
    })?;

    watcher
        .watch(&watch_root, RecursiveMode::Recursive)
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to watch {root}: {e}\n  \
             On Linux a large tree usually exhausts the inotify watch limit — raise it with:\n    \
             sudo sysctl fs.inotify.max_user_watches=524288   (persist in /etc/sysctl.conf)\n  \
             or run a one-shot `keyhog scan {root}` instead of watch.",
                root = watch_root.display(),
            )
        })?;

    // Per-path dedupe state: last (scan time, content hash) seen for a path.
    // notify fires Create then Modify for a single new-file write, which
    // without this would print every finding twice (KH-GAP-109).
    let mut recently_scanned = WatchDedupeState::default();
    let skip_dirs = SkipDirPolicy::load()?;

    for event in rx {
        let event = match event {
            Ok(e) => e,
            Err(e) => {
                let palette = style::for_stderr();
                // Law 10: a watcher error is a DROPPED filesystem event — a save
                // the watcher never told us about means that file went unscanned
                // (a recall loss). On Linux an inotify queue overflow
                // (`Error::Generic` / ENOSPC under heavy churn) is the common
                // case: events are coalesced/lost and the daemon's recall silently
                // degrades. A trace-only warning is invisible without RUST_LOG, so
                // surface it LOUDLY on stderr and tell the operator what to do.
                eprintln!(
                    "{} keyhog watch: filesystem watcher error ({e}); one or more change \
                     events were DROPPED and those files were NOT re-scanned. \
                     If this recurs under heavy file churn, raise \
                     fs.inotify.max_queued_events or run `keyhog scan {}` for a \
                     full one-shot rescan.",
                    style::warn("WARN", &palette),
                    watch_root.display()
                );
                continue;
            }
        };
        let interesting = matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_));
        if !interesting {
            continue;
        }

        for path in event.paths {
            // Skip directories and common build/IDE artifacts that produce
            // a flood of irrelevant events.
            if path.is_dir() || should_skip(&path, &skip_dirs) {
                continue;
            }
            scan_file(&scan_runtime, &path, &mut recently_scanned)
                .with_context(|| format!("scan changed path {}", path.display()))?;
        }
    }
    Ok(())
}

/// FNV-1a hash of the file contents. Cheap, allocation-free, and good
/// enough to tell "same bytes as the event we just scanned" from a real
/// edit - we only need to suppress the duplicate inotify event, not to
/// resist collisions.
fn content_hash(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in data {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn scan_file(
    scan_runtime: &DefaultScanRuntime,
    path: &std::path::Path,
    recently_scanned: &mut WatchDedupeState,
) -> Result<()> {
    // Read BYTES (not `read_to_string`) and decode through the SAME path the
    // `keyhog scan` walker uses. `read_to_string` failed on the first non-UTF-8
    // byte and silently dropped the whole file, so a config with one stray
    // Latin-1 byte was scanned by `scan` (lossy decode) but invisibly skipped by
    // `watch` — a recall divergence between the two entry points (Law 10). Now
    // both share `decode_file_bytes`, so watch recovers the same secrets.
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(error) => {
            // A file that VANISHED between the inotify event and our read is a
            // benign race (nothing to scan) — stay quiet. Any OTHER error
            // (permission denied, I/O failure) means a file that EXISTS went
            // unscanned: surface it loudly so the recall loss is never silent.
            if error.kind() != std::io::ErrorKind::NotFound {
                let palette = style::for_stderr();
                eprintln!(
                    "{} keyhog watch: could not read {} ({}); it was NOT scanned",
                    style::warn("WARN", &palette),
                    path.display(),
                    error.kind()
                );
            }
            return Ok(());
        }
    };

    // Dedupe the Create+Modify burst by raw bytes before decoding. Duplicate
    // filesystem notifications should not pay decode cost, while a real byte
    // edit must always be re-scanned even if lossy UTF-8 maps both versions to
    // the same string.
    if suppress_duplicate_event(path, &bytes, Instant::now(), recently_scanned) {
        return Ok(());
    }

    // `None` => the bytes are binary (no text to scan): an intentional,
    // documented skip that matches the scan walker's binary policy, not a
    // failure — so no warning, consistent with `keyhog scan`.
    let Some(data) = keyhog_sources::decode_file_bytes(&bytes) else {
        return Ok(());
    };
    if data.is_empty() {
        return Ok(());
    }

    let chunk = Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "filesystem".into(),
            path: Some(path.display().to_string()),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: None,
            decoded_span: None,
        },
    };
    let matches = match scan_runtime.scan_chunk(&chunk) {
        Ok(matches) => matches,
        Err(error) => {
            let palette = style::for_stderr();
            eprintln!("{} keyhog watch: {error}", style::fail("FAIL", &palette));
            return Ok(());
        }
    };
    for m in matches {
        crate::style::print_diagnostic_finding(
            "\u{1F50D}",
            &m.detector_id,
            &path.display().to_string(),
            m.location.line,
            m.severity,
            m.confidence,
            &keyhog_core::redact(&m.credential),
        )
        .with_context(|| format!("write watch finding for {}", path.display()))?;
    }
    Ok(())
}

fn suppress_duplicate_event(
    path: &std::path::Path,
    bytes: &[u8],
    now: Instant,
    recently_scanned: &mut WatchDedupeState,
) -> bool {
    let hash = content_hash(bytes);
    if let Some((last, last_hash)) = recently_scanned.entries.get(path) {
        if *last_hash == hash && now.saturating_duration_since(*last) < DEDUP_WINDOW {
            return true;
        }
    }
    recently_scanned
        .entries
        .insert(path.to_path_buf(), (now, hash));
    recently_scanned.scans_since_prune = recently_scanned.scans_since_prune.saturating_add(1);
    if recently_scanned.scans_since_prune >= DEDUP_PRUNE_INTERVAL {
        // Evict stale entries periodically so the map cannot grow without
        // bound, without making every event pay an O(active_paths) scan.
        recently_scanned.scans_since_prune = 0;
        recently_scanned
            .entries
            .retain(|_, (last, _)| now.saturating_duration_since(*last) < DEDUP_WINDOW);
    }
    false
}

pub(crate) mod testing {
    use std::path::Path;
    use std::time::{Duration, Instant};

    pub(crate) fn content_hash(data: &[u8]) -> u64 {
        super::content_hash(data)
    }

    pub(crate) fn duplicate_event_decisions(
        first: &[u8],
        second: &[u8],
        elapsed: Duration,
    ) -> (bool, bool) {
        let mut recently_scanned = super::WatchDedupeState::default();
        let path = Path::new("watched-file.txt");
        let first_at = Instant::now();
        let second_at = first_at + elapsed;
        let first_suppressed =
            super::suppress_duplicate_event(path, first, first_at, &mut recently_scanned);
        let second_suppressed =
            super::suppress_duplicate_event(path, second, second_at, &mut recently_scanned);
        (first_suppressed, second_suppressed)
    }
}

fn should_skip(path: &std::path::Path, skip_dirs: &SkipDirPolicy) -> bool {
    // Walk path components - handles both `/` and `\` natively and
    // doesn't allocate a lowercased copy of the entire path on every
    // watch event. The previous flow (a) didn't skip Windows paths
    // because the SKIP literals were POSIX-only and (b) burned a
    // String per event in the inotify hot loop.
    path.components().any(|c| {
        if let std::path::Component::Normal(os) = c {
            if let Some(s) = os.to_str() {
                return skip_dirs.is_watch_component(s);
            }
        }
        false
    })
}
