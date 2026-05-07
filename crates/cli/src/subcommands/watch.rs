//! `keyhog watch <path>` — daemon mode.
//!
//! Tier-B moat innovation #7 from audits/legendary-2026-04-26: compile-once,
//! scan-many. The detector corpus + Hyperscan database are built ONCE at
//! startup; subsequent scans on a saved file run in O(file_size) without
//! the ~50-100 ms compile overhead a fresh `keyhog scan` invocation pays.
//!
//! Architecture:
//!   1. Compile a `CompiledScanner` once.
//!   2. Walk the path with `notify::recommended_watcher` (inotify on Linux,
//!      FSEvents on macOS, ReadDirectoryChangesW on Windows).
//!   3. On `Modify` or `Create` events: read the file, build a Chunk, call
//!      `scanner.scan(&chunk)`, print findings to stdout.
//!   4. Block on the channel forever; Ctrl-C exits cleanly.
//!
//! No batching, no orchestrator: a single saved file is the natural scan
//! unit for an editor workflow. If the user wants a directory-wide rescan
//! they can always invoke `keyhog scan` separately.

use crate::args::WatchArgs;
use anyhow::{Context, Result};
use keyhog_core::{Chunk, ChunkMetadata, DetectorFile};
use keyhog_scanner::CompiledScanner;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::sync::mpsc::channel;

pub fn run(args: WatchArgs) -> Result<()> {
    let detectors = load_detectors(&args.detectors)?;
    let detector_count = detectors.len();
    let scanner = CompiledScanner::compile(detectors)
        .map_err(|e| anyhow::anyhow!("scanner compile failed: {e:?}"))?;

    let watch_root = std::fs::canonicalize(&args.path)
        .with_context(|| format!("canonicalize {}", args.path.display()))?;

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
        let _ = tx.send(res);
    })
    .map_err(|e| anyhow::anyhow!("failed to build filesystem watcher: {e}"))?;

    watcher
        .watch(&watch_root, RecursiveMode::Recursive)
        .map_err(|e| anyhow::anyhow!("failed to watch {}: {e}", watch_root.display()))?;

    for event in rx {
        let event = match event {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("watcher error: {e}");
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
            scan_file(&scanner, &path);
        }
    }
    Ok(())
}

fn scan_file(scanner: &CompiledScanner, path: &std::path::Path) {
    let data = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return, // not text, deleted, or permission denied — skip
    };
    if data.is_empty() {
        return;
    }
    let chunk = Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            source_type: "filesystem/watch".into(),
            path: Some(path.display().to_string()),
            commit: None,
            author: None,
            date: None,
        },
    };
    let matches = scanner.scan(&chunk);
    for m in matches {
        let line = m.location.line.map(|l| format!(":{l}")).unwrap_or_default();
        let conf = m
            .confidence
            .map(|c| format!(" ({:.2})", c))
            .unwrap_or_default();
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
    // Walk path components — handles both `/` and `\` natively and
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

fn load_detectors(path: &std::path::Path) -> Result<Vec<keyhog_core::DetectorSpec>> {
    if path.exists() && path.is_dir() {
        return keyhog_core::load_detectors(path).context("loading detectors");
    }
    let embedded = keyhog_core::embedded_detector_tomls();
    if embedded.is_empty() {
        anyhow::bail!(
            "detector directory '{}' not found and no embedded detectors available",
            path.display()
        );
    }
    let mut out = Vec::with_capacity(embedded.len());
    for (name, body) in embedded {
        match toml::from_str::<DetectorFile>(body) {
            Ok(f) => out.push(f.detector),
            Err(e) => eprintln!("warning: failed to parse embedded detector {name}: {e}"),
        }
    }
    Ok(out)
}
