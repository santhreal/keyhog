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
use crate::style;
use anyhow::{Context, Result};
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::time::{Duration, Instant};

/// Within this window, a repeat event for the *same path and same content*
/// (e.g. the Create+Modify burst notify emits for a single new-file write,
/// KH-GAP-109) is suppressed so we print one finding set per real change,
/// not one per inotify event. A genuine later edit (different content) is
/// always re-scanned because the content hash changes.
const DEDUP_WINDOW: Duration = Duration::from_millis(750);

pub(crate) fn run(args: WatchArgs) -> Result<()> {
    crate::runtime_preflight::validate_scan_runtime_config()?;
    crate::orchestrator_config::configure_hyperscan_cache_dir(args.cache_dir.clone())?;

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

    let detectors = crate::orchestrator_config::load_detectors_or_embedded(&args.detectors)?;
    let detector_count = detectors.len();
    let scanner = CompiledScanner::compile(detectors.clone()).map_err(|e| {
        crate::orchestrator_config::detector_compile_failed("keyhog watch", &args.detectors, e)
    })?;
    let router =
        crate::orchestrator::cached_autoroute_router_for_default_config(&scanner, &detectors);

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

    // Hold the watcher for the duration of the daemon. The `notify` crate
    // requires us to keep the handle alive; dropping it stops the watcher.
    let mut watcher = notify::recommended_watcher(move |res| {
        // notify hands events on its own thread; forward to the main loop.
        let _ = tx.send(res); // LAW10: unused-binding marker; no runtime effect, not a fallback
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
    let mut recently_scanned: HashMap<PathBuf, (Instant, u64)> = HashMap::new();

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
            if path.is_dir() || should_skip(&path) {
                continue;
            }
            scan_file(&scanner, &router, &path, &mut recently_scanned);
        }
    }
    Ok(())
}

/// FNV-1a hash of the file contents. Cheap, allocation-free, and good
/// enough to tell "same bytes as the event we just scanned" from a real
/// edit - we only need to suppress the duplicate inotify event, not to
/// resist collisions.
fn content_hash(data: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in data.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn scan_file(
    scanner: &CompiledScanner,
    router: &crate::orchestrator::CachedBackendRouter,
    path: &std::path::Path,
    recently_scanned: &mut HashMap<PathBuf, (Instant, u64)>,
) {
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
            return;
        }
    };
    // `None` => the bytes are binary (no text to scan): an intentional,
    // documented skip that matches the scan walker's binary policy, not a
    // failure — so no warning, consistent with `keyhog scan`.
    let Some(data) = keyhog_sources::decode_file_bytes(&bytes) else {
        return;
    };
    if data.is_empty() {
        return;
    }

    // Dedupe the Create+Modify burst: if we scanned this exact content for
    // this path within DEDUP_WINDOW, skip - notify already gave us a finding
    // for it. A real edit changes the hash and is always re-scanned.
    let now = Instant::now();
    let hash = content_hash(&data);
    if let Some((last, last_hash)) = recently_scanned.get(path) {
        if *last_hash == hash && now.duration_since(*last) < DEDUP_WINDOW {
            return;
        }
    }
    recently_scanned.insert(path.to_path_buf(), (now, hash));
    // Evict stale entries so the map can't grow without bound on a
    // long-lived daemon watching a churning tree.
    recently_scanned.retain(|_, (last, _)| now.duration_since(*last) < DEDUP_WINDOW);

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
    let backend = match router.choose(None, std::slice::from_ref(&chunk)) {
        Ok(backend) => backend,
        Err(error) => {
            let palette = style::for_stderr();
            eprintln!("{} keyhog watch: {error}", style::fail("FAIL", &palette));
            return;
        }
    };
    let matches = scanner.scan_with_backend(&chunk, backend);
    for m in matches {
        let line = m.location.line.map(|l| format!(":{l}")).unwrap_or_default(); // LAW10: missing/non-string field => empty/placeholder; recall-safe
        let conf = m
            .confidence
            .map(|c| format!(" ({:.2})", c))
            .unwrap_or_default(); // LAW10: missing/non-string field => empty/placeholder; recall-safe
        println!(
            "\u{1F50D} {} {}{} {:?}{}  {}",
            m.detector_id,
            path.display(),
            line,
            m.severity,
            conf,
            keyhog_core::redact(&m.credential)
        );
    }
}

fn should_skip(path: &std::path::Path) -> bool {
    // Walk path components - handles both `/` and `\` natively and
    // doesn't allocate a lowercased copy of the entire path on every
    // watch event. The previous flow (a) didn't skip Windows paths
    // because the SKIP literals were POSIX-only and (b) burned a
    // String per event in the inotify hot loop.
    const SKIP_NAMES: &[&str] = &[
        ".git",
        ".svn",
        ".hg",
        "node_modules",
        "target",
        ".cargo",
        ".cache",
        ".venv",
        "venv",
        "__pycache__",
        ".next",
        ".turbo",
        "dist",
        "build",
    ];
    path.components().any(|c| {
        if let std::path::Component::Normal(os) = c {
            if let Some(s) = os.to_str() {
                return SKIP_NAMES.iter().any(|skip| s.eq_ignore_ascii_case(skip));
            }
        }
        false
    })
}
