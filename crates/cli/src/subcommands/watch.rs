//! `keyhog watch <path>` - foreground filesystem watch mode.
//!
//! Tier-B moat innovation #7 from the internal design notes: compile-once,
//! scan-many. The detector corpus + Hyperscan database are built ONCE at
//! startup; subsequent scans on a saved file run in O(file_size) without
//! the ~50-100 ms compile overhead a fresh `keyhog scan` invocation pays.
//!
//! Architecture:
//!   1. Compile a `CompiledScanner` once.
//!   2. Register every resolved root with `notify::recommended_watcher`
//!      (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on
//!      Windows).
//!   3. Reconcile each root: scan what is already on disk, THEN print the
//!      readiness banner, so `watching:` means covered rather than merely
//!      subscribed (KH-505).
//!   4. On `Modify` or `Create` events: expand the event into concrete files,
//!      read each one, build a Chunk, select the persisted calibrated backend,
//!      scan, and print findings to stdout.
//!   5. On `Remove` of a watched root: exit loudly. The kernel discarded that
//!      watch, so continuing would report a clean tree nobody is watching.
//!   6. Block on the channel otherwise; Ctrl-C exits cleanly.
//!
//! One file is the natural scan unit for an editor workflow, but it is NOT the
//! only unit the filesystem hands us. A directory that appears in the tree
//! (`mv`, `cp -r`, `tar -xf`) arrives as ONE event with no events for the files
//! it already contained, so [`WatchSession::expand_event_paths`] walks that
//! subtree instead of dropping it. Startup reconciliation and the event loop
//! both dispatch through [`WatchSession::scan_paths`], the single place a
//! watched path meets the scan pipeline.

use crate::args::WatchArgs;
use crate::orchestrator::load_rule_suppressor;
use crate::orchestrator::{setup_default_scan_runtime, DefaultScanRuntime};
use crate::skip_dirs::SkipDirPolicy;
use crate::style;
use anyhow::{Context, Result};
use keyhog_core::{Chunk, ChunkMetadata, RawMatch, RuleSuppressor};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::collections::{HashMap, VecDeque};
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
/// Soft prune cadence: when the map is small this only runs occasionally.
const DEDUP_PRUNE_INTERVAL: usize = 128;
/// Hard cap on dedup map entries. When exceeded, drop oldest keys via FIFO
/// order (O(1) amortized per insert) instead of scanning every entry (KH-1311).
const DEDUP_MAX_ENTRIES: usize = 4096;
/// Hard cap on files enumerated for ONE directory-appearance event
/// (`reconcile_directory`). A directory moved into a watched tree is scanned
/// eagerly because inotify never reports the files it already contained; the
/// cap keeps one `mv` of a huge tree from stalling the event loop. Exceeding it
/// is reported LOUDLY, never truncated silently, because the untouched
/// remainder is a recall loss.
const WATCH_DIR_RECONCILE_MAX_FILES: usize = 10_000;
/// Hard cap on directory depth walked for one directory-appearance event.
/// Bounds the work a deliberately deep tree can force onto the event loop.
const WATCH_DIR_RECONCILE_MAX_DEPTH: usize = 64;
/// How many one-second checks to give a removed watched root before declaring
/// coverage unrecoverable. A root is more often replaced than deleted, so the
/// watcher waits rather than throwing away a working session; the bound stops
/// it parking forever on a root that is genuinely gone. This is supervision
/// over an operator action, NOT a retry of a failed call.
const WATCH_ROOT_REESTABLISH_ATTEMPTS: usize = 30;
/// Interval between those checks.
const WATCH_ROOT_REESTABLISH_INTERVAL: Duration = Duration::from_secs(1);

/// FNV-1a 64-bit offset basis and prime for the cheap pre-scan raw-content
/// filter. The post-scan finding identity uses the framed stable hasher because
/// it binds credential and complete location fields rather than arbitrary file
/// bytes.
const FNV_OFFSET_BASIS: u64 = keyhog_scanner::FNV_OFFSET_BASIS;
const FNV_PRIME: u64 = keyhog_scanner::FNV_PRIME;

#[derive(Default)]
struct WatchDedupeState {
    /// Pre-scan dedup keyed on RAW content hash: skips the scan when a burst
    /// event re-reads byte-identical content (the cheap common case).
    entries: HashMap<PathBuf, (Instant, u64)>,
    /// Insertion order for `entries` so overflow eviction is O(1) amortized.
    entry_order: VecDeque<PathBuf>,
    /// Post-scan dedup keyed on the FINDING-SET fingerprint: a single save fires
    /// a CREATE+MODIFY(+CLOSE_WRITE) burst, and a read taken mid-write can return
    /// bytes that differ from the final read (e.g. missing the trailing newline)
    /// yet yield the SAME findings -- which then printed twice. This layer
    /// collapses that to one print while a genuine edit (different findings)
    /// still prints.
    finding_entries: HashMap<PathBuf, (Instant, [u8; 32])>,
    /// Insertion order for `finding_entries`.
    finding_order: VecDeque<PathBuf>,
    scans_since_prune: usize,
}

fn cap_map_fifo<V>(
    map: &mut HashMap<PathBuf, V>,
    order: &mut VecDeque<PathBuf>,
    path: &std::path::Path,
    value: V,
) {
    if map.contains_key(path) {
        map.insert(path.to_path_buf(), value);
        return;
    }
    map.insert(path.to_path_buf(), value);
    order.push_back(path.to_path_buf());
    while map.len() > DEDUP_MAX_ENTRIES {
        if let Some(old) = order.pop_front() {
            map.remove(&old);
        } else {
            break;
        }
    }
}

pub(crate) fn run(args: WatchArgs) -> Result<()> {
    let watch_roots = resolve_watch_roots(&args.paths)?;
    // The space-joined root list doubles as actionable advice: `keyhog scan`
    // accepts the same multi-root form, so every "run keyhog scan <roots>"
    // hint below stays copy-pasteable for one, two, or many watched trees.
    let roots_hint = roots_hint(&watch_roots);
    // Tier-A knobs (KH-1461 / KH-1462): `0` or omitted max-file-size keeps the
    // scan default; consecutive-failure budget defaults via clap.
    let max_file_size = match args.max_file_size {
        None | Some(0) => keyhog_core::DEFAULT_MAX_FILE_SIZE_BYTES,
        Some(n) => n,
    };
    let max_consecutive_failures = if args.max_consecutive_failures == 0 {
        crate::args::DEFAULT_WATCH_MAX_CONSECUTIVE_SCAN_FAILURES
    } else {
        args.max_consecutive_failures
    };

    // Parse the explicit backend BEFORE compiling the scanner so an invalid
    // value fails fast. With it set, the per-file scan forces that backend and
    // never consults the autoroute cache -- so watch works on an uncalibrated
    // binary (and the autoroute error's `--backend` advice is actionable here).
    // Watch setup (root policy resolution, scanner compile, per-root
    // suppressor loads) is the command's collect/compute phase.
    let setup_span = keyhog_profile::span(keyhog_profile::Stage::Preprocess);
    let backend_override = crate::orchestrator::explicit_backend_override(args.backend.as_deref())?;
    // Root config discovery + allowlist loading at the primary watched tree, so
    // `keyhog watch` resolves the SAME `.keyhog.toml` / `.keyhogignore` policy an
    // equivalent `keyhog scan <root>` would (folded roots share one policy root,
    // mirroring scan's single-root allowlist anchor).
    let scan_runtime = setup_default_scan_runtime(
        &args.detectors,
        args.detectors_cli_explicit,
        args.cache_dir.clone(),
        None,
        backend_override,
        "keyhog watch",
        false,
        watch_roots.first().map(PathBuf::as_path),
    )?
    .prepare_persistent_watch(backend_override)?;
    let detector_count = scan_runtime.detector_count();
    // KH-1433: per-root `.keyhogignore.toml` RuleSuppressor map so multi-root
    // watch applies each tree's declarative suppressions (not only primary).
    // `.keyhog.toml` detector config still anchors on the primary root via
    // setup_default_scan_runtime (secondary-root full config is open).
    let mut rule_suppressors: HashMap<PathBuf, RuleSuppressor> =
        HashMap::with_capacity(watch_roots.len());
    for root in &watch_roots {
        rule_suppressors.insert(root.clone(), load_rule_suppressor(Some(root))?);
    }
    drop(setup_span);
    if watch_roots.len() > 1 && !args.quiet {
        let palette = style::for_stderr();
        eprintln!(
            "{} keyhog watch: loaded per-root .keyhogignore.toml for {} roots; \
             .keyhog.toml detector config still uses primary root {}",
            style::warn("WARN", &palette),
            watch_roots.len(),
            watch_roots[0].display()
        );
    }

    let (tx, rx) = channel::<notify::Result<Event>>();
    let notify_channel_closed_for_callback = AtomicBool::new(false);
    let roots_hint_for_callback = roots_hint.clone();

    // Hold the watcher for the duration of the foreground process. The `notify`
    // crate requires us to keep the handle alive; dropping it stops the watcher.
    // ONE watcher serves every root: `notify` lets us register additional
    // paths on the same handle below, so all roots share this channel and the
    // single dedup/scan loop, with no per-root thread or state divergence.
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
                roots_hint_for_callback
            );
        }
    })
    .map_err(|e| {
        anyhow::anyhow!(
            "failed to build filesystem watcher for {roots}: {e}\n  \
             Fix: on Linux raise watcher limits with:\n    \
             sudo sysctl fs.inotify.max_user_instances=1024 fs.inotify.max_user_watches=524288\n  \
             then retry, or run `keyhog scan {roots}` for a one-shot scan.",
            roots = roots_hint,
        )
    })?;

    // Register every resolved root on the shared watcher. A failure names the
    // exact root that could not be watched (not the whole set), so the inotify
    // remediation hint stays specific even with multiple trees.
    for root in &watch_roots {
        watcher.watch(root, RecursiveMode::Recursive).map_err(|e| {
            anyhow::anyhow!(
                "failed to watch {root}: {e}\n  \
             On Linux a large tree usually exhausts the inotify watch limit; raise it with:\n    \
             sudo sysctl fs.inotify.max_user_watches=524288   (persist in /etc/sysctl.conf)\n  \
             or run a one-shot `keyhog scan {root}` instead of watch.",
                root = root.display(),
            )
        })?;
    }

    let skip_dirs = SkipDirPolicy::load()?;
    let mut session = WatchSession {
        scan_runtime: &scan_runtime,
        watch_roots: &watch_roots,
        rule_suppressors: &rule_suppressors,
        skip_dirs: &skip_dirs,
        roots_hint: &roots_hint,
        max_file_size,
        max_consecutive_failures,
        // Per-path dedupe state: last (scan time, content hash) seen for a
        // path. notify fires Create then Modify for a single new-file write,
        // which without this would print every finding twice (KH-GAP-109).
        recently_scanned: WatchDedupeState::default(),
        consecutive_scan_failures: 0,
    };

    // KH-505: the watches are live but nothing has looked at what is ALREADY in
    // the tree, including anything written during detector compilation and
    // registration. Reconcile each root before declaring readiness, so
    // "watching:" means the current tree is covered and not merely that future
    // events will arrive. The dedup layer collapses the overlap with any event
    // that fires for the same file during this walk.
    for root in &watch_roots {
        let mut initial = Vec::new();
        collect_directory_files(root, &skip_dirs, &mut initial, &roots_hint);
        session.scan_paths(initial)?;
    }

    if !args.quiet {
        eprintln!(
            "\u{1F441}  keyhog watch (\u{2630} {} detectors compiled)",
            detector_count
        );
        eprintln!("    workers: {}", scan_runtime.worker_threads());
        // One status line per watched root so the operator can confirm every
        // tree the watcher is actually monitoring, not just the first.
        for root in &watch_roots {
            eprintln!("    watching: {}", root.display());
        }
        eprintln!("    Ctrl-C to exit");
        eprintln!();
    }

    for event in rx {
        let event = match event {
            Ok(e) => e,
            Err(e) => {
                let palette = style::for_stderr();
                // Law 10: a watcher error is a DROPPED filesystem event, a save
                // the watcher never told us about means that file went unscanned
                // (a recall loss). On Linux an inotify queue overflow
                // (`Error::Generic` / ENOSPC under heavy churn) is the common
                // case: events are coalesced/lost and the watcher's recall silently
                // degrades. A trace-only warning is invisible without RUST_LOG, so
                // surface it LOUDLY on stderr and tell the operator what to do.
                eprintln!(
                    "{} keyhog watch: filesystem watcher error ({e}); one or more change \
                     events were DROPPED and those files were NOT re-scanned. \
                     If this recurs under heavy file churn, raise \
                     fs.inotify.max_queued_events or run `keyhog scan {}` for a \
                     full one-shot rescan.",
                    style::warn("WARN", &palette),
                    roots_hint
                );
                continue;
            }
        };
        // A watched root that disappears takes its inotify watch with it. The
        // process would otherwise stay alive holding ZERO watch descriptors,
        // printing nothing, which is indistinguishable from "the tree is
        // clean" - the worst outcome in this product. Discarding the session
        // is not the answer either: a root is routinely replaced rather than
        // deleted (`rm -rf build && mkdir build`, a checkout that swaps a
        // directory, a deploy). Re-establish coverage instead, and reconcile
        // the subtree on return so anything written while we were blind is
        // scanned rather than quietly skipped.
        if matches!(event.kind, EventKind::Remove(_)) {
            if let Some(lost) = event
                .paths
                .iter()
                .find(|path| watch_roots.iter().any(|root| root == *path))
                .cloned()
            {
                reestablish_watched_root(
                    &mut watcher,
                    &lost,
                    &skip_dirs,
                    &roots_hint,
                    &mut session,
                )?;
            }
            continue;
        }
        let interesting = matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_));
        if !interesting {
            continue;
        }

        // Expand this event into the concrete files to scan, then hand them to
        // the one shared dispatch.
        let pending = session.expand_event_paths(event.paths);
        session.scan_paths(pending)?;
    }
    Ok(())
}

/// Wait for a removed watched root to come back, re-register its filesystem
/// watch, and rescan the subtree.
///
/// Deliberately NOT a retry: nothing keyhog did failed. The operator's tree
/// changed, and a root is far more often replaced than deleted, so this is a
/// supervision loop over an external action rather than a second attempt at a
/// fallible call. It stays bounded by [`WATCH_ROOT_REESTABLISH_ATTEMPTS`] so a
/// genuinely deleted root still terminates the process loudly instead of
/// leaving it parked forever pretending to watch.
///
/// The reconciliation on return is the half that matters. Between the removal
/// and the new registration nothing was observed, so the subtree is walked and
/// rescanned; without that, recovery would silently manufacture the very
/// coverage gap the exit was there to prevent.
fn reestablish_watched_root(
    watcher: &mut notify::RecommendedWatcher,
    root: &std::path::Path,
    skip_dirs: &SkipDirPolicy,
    roots_hint: &str,
    session: &mut WatchSession<'_>,
) -> Result<()> {
    let palette = style::for_stderr();
    eprintln!(
        "{} keyhog watch: watched root {} was removed; its filesystem watch is gone and \
         changes under that path are NOT being observed. Waiting up to {}s for it to \
         return.",
        style::warn("WARN", &palette),
        root.display(),
        WATCH_ROOT_REESTABLISH_ATTEMPTS,
    );
    for _ in 0..WATCH_ROOT_REESTABLISH_ATTEMPTS {
        std::thread::sleep(WATCH_ROOT_REESTABLISH_INTERVAL);
        if !root.is_dir() {
            continue;
        }
        // Register BEFORE reconciling, so a file written during the walk
        // arrives as an event instead of falling between the two steps.
        if let Err(error) = watcher.watch(root, RecursiveMode::Recursive) {
            eprintln!(
                "{} keyhog watch: {} returned but its watch could not be re-registered \
                 ({error}); still not observed.",
                style::warn("WARN", &palette),
                root.display(),
            );
            continue;
        }
        let mut pending = Vec::new();
        collect_directory_files(root, skip_dirs, &mut pending, roots_hint);
        let reconciled = pending.len();
        session.scan_paths(pending)?;
        eprintln!(
            "{} keyhog watch: {} is being watched again; rescanned {reconciled} file(s) \
             to cover the gap while it was missing.",
            style::warn("OK", &palette),
            root.display(),
        );
        return Ok(());
    }
    anyhow::bail!(
        "keyhog watch: watched root {root} did not return within {secs}s; its filesystem \
         watch is gone and changes under that path cannot be observed. Exiting rather than \
         reporting a clean tree that is not being watched. Recreate the path and restart \
         watch, or run `keyhog scan {roots_hint}`.",
        root = root.display(),
        secs = WATCH_ROOT_REESTABLISH_ATTEMPTS,
    );
}

/// The live state of one `keyhog watch` session plus the single place a
/// watched path meets the scan pipeline.
///
/// Both the startup reconciliation and the event loop call
/// [`WatchSession::scan_paths`], so read policy, suppression, dedup, and the
/// consecutive-failure budget cannot drift between "files that were already
/// there" and "files that changed later".
struct WatchSession<'a> {
    scan_runtime: &'a DefaultScanRuntime,
    watch_roots: &'a [PathBuf],
    rule_suppressors: &'a HashMap<PathBuf, RuleSuppressor>,
    skip_dirs: &'a SkipDirPolicy,
    roots_hint: &'a str,
    max_file_size: u64,
    max_consecutive_failures: usize,
    recently_scanned: WatchDedupeState,
    consecutive_scan_failures: usize,
}

impl WatchSession<'_> {
    /// Turn the raw paths of one filesystem event into the concrete files to
    /// scan.
    ///
    /// A DIRECTORY that appears in the tree (`mv dir watched/`, `cp -r`, an
    /// extracted archive) is the one shape inotify cannot describe: the kernel
    /// reports a single MOVED_TO/CREATE for the directory and NEVER an event
    /// for the files it already contained, so every one of them stayed
    /// unscanned forever. The recursive backend also registers a watch for a
    /// newly created directory only after the fact, losing any file written
    /// into it before that registration. Enumerating the subtree here closes
    /// both holes: files already present are found by this walk, files written
    /// afterwards arrive as ordinary events, and dedup collapses the overlap.
    fn expand_event_paths(&self, paths: Vec<PathBuf>) -> Vec<PathBuf> {
        let mut pending = Vec::with_capacity(paths.len());
        for path in paths {
            if should_skip(&path, self.skip_dirs) {
                continue;
            }
            if path.is_dir() {
                collect_directory_files(&path, self.skip_dirs, &mut pending, self.roots_hint);
            } else {
                pending.push(path);
            }
        }
        pending
    }

    fn scan_paths(&mut self, pending: Vec<PathBuf>) -> Result<()> {
        for path in pending {
            let rule_suppressor =
                rule_suppressor_for_path(&path, self.watch_roots, self.rule_suppressors);
            let outcome = scan_file(
                self.scan_runtime,
                rule_suppressor,
                &path,
                self.max_file_size,
                &mut self.recently_scanned,
            )
            .with_context(|| format!("scan changed path {}", path.display()))?;
            match outcome {
                WatchScanOutcome::Ok => self.consecutive_scan_failures = 0,
                // A path `keyhog scan` would not scan either (symlink, FIFO,
                // socket, device, over max-file-size). Surfaced, but NOT a
                // scanner fault: charging it to the failure budget let a
                // perfectly ordinary symlink farm (node_modules/.bin, vendored
                // links) kill the watcher outright.
                WatchScanOutcome::PolicySkip => {}
                WatchScanOutcome::EngineFailure => {
                    self.consecutive_scan_failures =
                        self.consecutive_scan_failures.saturating_add(1);
                    let failures = self.consecutive_scan_failures;
                    let limit = self.max_consecutive_failures;
                    if failures >= limit {
                        anyhow::bail!(
                            "keyhog watch: {failures} consecutive per-file scan failures \
                             (limit {limit}); exiting so a wedged scanner cannot silently \
                             drop secrets under editor saves (KH-1334). Fix the scanner \
                             fault and restart watch, or run `keyhog scan {}` for a full \
                             rescan.",
                            self.roots_hint
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchScanOutcome {
    Ok,
    /// The path is one `keyhog scan` would not scan either: a symlink, a
    /// special file, or a file over the max-file-size cap. Surfaced to the
    /// operator, but deliberately not charged to the consecutive-failure
    /// budget, which exists to catch a *wedged scanner*, not routine policy.
    PolicySkip,
    EngineFailure,
}

/// Enumerate the regular files under a directory that just appeared in a
/// watched tree, so they reach the same per-file scan an ordinary event would.
///
/// Bounded by [`WATCH_DIR_RECONCILE_MAX_FILES`] and
/// [`WATCH_DIR_RECONCILE_MAX_DEPTH`]; hitting either is announced LOUDLY with
/// the one-shot rescan command, because the unenumerated remainder is a real
/// recall loss and a silent truncation here would be a false clean. Symlinked
/// directories are never followed: `keyhog scan` does not traverse them either,
/// and following one would walk straight out of the watched root.
fn collect_directory_files(
    dir: &std::path::Path,
    skip_dirs: &SkipDirPolicy,
    out: &mut Vec<PathBuf>,
    roots_hint: &str,
) {
    let start = out.len();
    let mut stack: Vec<(PathBuf, usize)> = vec![(dir.to_path_buf(), 0)];
    let mut truncated: Option<&'static str> = None;
    while let Some((current, depth)) = stack.pop() {
        if depth > WATCH_DIR_RECONCILE_MAX_DEPTH {
            truncated = Some("directory depth");
            continue;
        }
        let entries = match std::fs::read_dir(&current) {
            Ok(entries) => entries,
            // A directory that vanished mid-walk is a benign race. Any other
            // error means files we cannot even enumerate went unscanned.
            Err(error) => {
                if error.kind() != std::io::ErrorKind::NotFound {
                    let palette = style::for_stderr();
                    eprintln!(
                        "{} keyhog watch: could not list {} ({}); files under it were NOT scanned",
                        style::warn("WARN", &palette),
                        current.display(),
                        error.kind()
                    );
                }
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if should_skip(&path, skip_dirs) {
                continue;
            }
            // `file_type` on the DirEntry does not follow symlinks, so a
            // symlinked directory is classified as a symlink and dropped here
            // rather than traversed.
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                stack.push((path, depth + 1));
            } else if file_type.is_file() {
                if out.len() - start >= WATCH_DIR_RECONCILE_MAX_FILES {
                    truncated = Some("file count");
                    break;
                }
                out.push(path);
            }
        }
        if truncated == Some("file count") {
            break;
        }
    }
    if let Some(limit) = truncated {
        let palette = style::for_stderr();
        eprintln!(
            "{} keyhog watch: {} appeared in a watched tree and exceeded the {limit} limit \
             ({} files enumerated, max {}); the remainder was NOT scanned. Run \
             `keyhog scan {roots_hint}` for full coverage of that path.",
            style::warn("WARN", &palette),
            dir.display(),
            out.len() - start,
            WATCH_DIR_RECONCILE_MAX_FILES,
        );
    }
}

/// Resolve the requested watch roots into the canonical directory set the
/// foreground watcher will monitor.
///
/// Shares [`crate::sources::resolve_scan_roots`] with `keyhog scan` so both
/// entry points validate, canonicalize, fold nested/duplicate roots (loudly,
/// Law 10), and preserve first-seen order through one resolution contract, no
/// drift between what `scan` and `watch` consider the same root set. Watch then
/// adds the single constraint `scan` does not impose: every root must be a
/// *directory*, because the filesystem watcher monitors trees, not single
/// files. A non-directory root fails closed with the same actionable message
/// the original single-root path used, naming the offending root and pointing
/// at `keyhog scan` for a one-shot file scan.
fn resolve_watch_roots(requested: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let folded = crate::sources::resolve_scan_roots(requested)?;
    let mut roots = Vec::with_capacity(folded.len());
    for root in folded {
        // Canonicalize each surviving root so the watcher registers, and every
        // finding reports, the absolute real path, exactly as the historical
        // single-root `watch` did. `resolve_scan_roots` keeps the user's
        // spelling (relative, `.`/`..`), which is fine for a one-shot scan but
        // would leave a live watcher printing `./foo` paths. Existence was
        // already validated upstream, so this only normalizes the spelling; a
        // failure here is a genuine TOCTOU race, surfaced loudly (Law 10),
        // never swallowed.
        let canonical = root
            .canonicalize()
            .with_context(|| format!("canonicalize watch root {}", root.display()))?;
        if !canonical.is_dir() {
            anyhow::bail!(
                "watch path '{}' is not a directory. \
                 Fix: pass a directory to monitor, or run `keyhog scan {}` for a one-shot file scan.",
                canonical.display(),
                canonical.display()
            );
        }
        roots.push(canonical);
    }
    Ok(roots)
}

/// Format the watched roots as a single space-joined string for error-message
/// remediation hints. `keyhog scan` accepts the same multi-root positional
/// form, so the result is always a copy-pasteable `keyhog scan <hint>` command
/// regardless of how many roots are being watched.
fn roots_hint(roots: &[PathBuf]) -> String {
    roots
        .iter()
        .map(|root| root.display().to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

/// FNV-1a hash of the file contents. Cheap, allocation-free, and good
/// enough to tell "same bytes as the event we just scanned" from a real
/// edit - we only need to suppress the duplicate inotify event, not to
/// resist collisions.
fn content_hash(data: &[u8]) -> u64 {
    let mut h: u64 = FNV_OFFSET_BASIS;
    for b in data {
        h ^= *b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Read a changed file through the SAME guarded read the `keyhog scan` walker
/// uses. A raw `std::fs::read` here bypassed three walker protections: (1) no
/// size cap, so a large (or TOCTOU-grown) file dropped into a watched tree
/// OOMs the single-threaded watcher; (2) no special-file guard, so a FIFO
/// created in the tree, which itself fires an inotify CREATE event, is opened
/// blocking and HANGS the event loop forever, wedging the whole watcher; (3) no
/// `O_NOFOLLOW`, so a symlink is followed out of the watched root. Cap defaults
/// to the same max-file-size as `keyhog scan` (KH-1310 / KH-1461); a special
/// file returns `InvalidInput` and an oversized file `InvalidData`, both
/// surfaced loudly by `scan_file`'s existing error arm.
fn read_watched_file(path: &std::path::Path, max_file_size: u64) -> std::io::Result<Vec<u8>> {
    keyhog_sources::read_file_safe_bytes(path, max_file_size)
}

/// Classify a guarded-read failure as routine policy or a scanner fault.
///
/// The consecutive-failure budget (KH-1334) exists to kill a watcher whose
/// SCANNER is wedged, so it must only count faults. A symlink, a FIFO, a
/// socket, a device node, or a file over the size cap is a path `keyhog scan`
/// declines to read as well: charging those to the budget meant six symlinks
/// created in a row terminated the watcher with exit 2, turning ordinary
/// repository layout into an outage. Permission and I/O errors stay faults,
/// because those are files that exist, are in policy, and went unscanned.
fn read_error_outcome(path: &std::path::Path, error: &std::io::Error) -> WatchScanOutcome {
    // `read_file_safe_bytes` opens `O_NOFOLLOW`, so a symlink fails with the
    // platform's ELOOP. `ErrorKind::FilesystemLoop` is still unstable, so ask
    // the filesystem directly instead of matching a raw errno: one `lstat`, on
    // the error path only, and it behaves the same on every platform.
    if path
        .symlink_metadata()
        .is_ok_and(|meta| meta.file_type().is_symlink())
    {
        return WatchScanOutcome::PolicySkip;
    }
    match error.kind() {
        // `read_file_safe_bytes` contract: special file (FIFO/socket/device).
        std::io::ErrorKind::InvalidInput => WatchScanOutcome::PolicySkip,
        // `read_file_safe_bytes` contract: over the effective size cap.
        std::io::ErrorKind::InvalidData => WatchScanOutcome::PolicySkip,
        _ => WatchScanOutcome::EngineFailure,
    }
}

/// Longest-prefix root match for multi-root watch (KH-1433). Falls back to the
/// first root's suppressor when a path is outside every watched tree (TOCTOU
/// move / external path); never panics.
fn rule_suppressor_for_path<'a>(
    path: &std::path::Path,
    roots: &[PathBuf],
    suppressors: &'a HashMap<PathBuf, RuleSuppressor>,
) -> &'a RuleSuppressor {
    let mut best: Option<&PathBuf> = None;
    for root in roots {
        if path.starts_with(root) {
            match best {
                None => best = Some(root),
                Some(current) if root.as_os_str().len() > current.as_os_str().len() => {
                    best = Some(root);
                }
                _ => {}
            }
        }
    }
    // LAW10: fail-closed; callers provide non-empty roots, and invariant violation aborts instead of omitting a watched tree.
    let key = best.unwrap_or(&roots[0]);
    suppressors
        .get(key)
        // LAW10: fail-closed; every root receives a suppressor, and invariant violation aborts instead of scanning without suppression.
        .unwrap_or_else(|| panic!("every watch root has a suppressor entry"))
}

fn scan_file(
    scan_runtime: &DefaultScanRuntime,
    rule_suppressor: &RuleSuppressor,
    path: &std::path::Path,
    max_file_size: u64,
    recently_scanned: &mut WatchDedupeState,
) -> Result<WatchScanOutcome> {
    // Read BYTES (not `read_to_string`) through the walker's guarded read (see
    // `read_watched_file`) and decode through the SAME path the `keyhog scan`
    // walker uses. `read_to_string` failed on the first non-UTF-8 byte and
    // silently dropped the whole file, so a config with one stray Latin-1 byte
    // was scanned by `scan` (lossy decode) but invisibly skipped by `watch`: a
    // recall divergence between the two entry points (Law 10). Now both share
    // the guarded read + `decode_file_bytes`, so watch recovers the same
    // secrets and can neither hang on a FIFO nor OOM on a huge file.
    let bytes = match read_watched_file(path, max_file_size) {
        Ok(b) => b,
        Err(error) => {
            // A file that VANISHED between the inotify event and our read is a
            // benign race (nothing to scan), stay quiet.
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(WatchScanOutcome::Ok);
            }
            let outcome = read_error_outcome(path, &error);
            let palette = style::for_stderr();
            let reason = match outcome {
                // Same disposition `keyhog scan` gives this path, so say so:
                // an operator chasing a missing finding needs to know the file
                // is out of policy, not that the watcher is broken.
                WatchScanOutcome::PolicySkip => "; `keyhog scan` skips it too",
                _ => "",
            };
            eprintln!(
                "{} keyhog watch: could not read {} ({}); it was NOT scanned{reason}",
                style::warn("WARN", &palette),
                path.display(),
                error.kind()
            );
            return Ok(outcome);
        }
    };

    // Dedupe the Create+Modify burst by raw bytes before decoding. Duplicate
    // filesystem notifications should not pay decode cost, while a real byte
    // edit must always be re-scanned even if lossy UTF-8 maps both versions to
    // the same string.
    if suppress_duplicate_event(path, &bytes, Instant::now(), recently_scanned) {
        return Ok(WatchScanOutcome::Ok);
    }

    // `None` => the bytes are binary (no text to scan): an intentional,
    // documented skip that matches the scan walker's binary policy, not a
    // failure (so no warning, consistent with `keyhog scan`).
    let Some(data) = keyhog_sources::decode_file_bytes(&bytes) else {
        return Ok(WatchScanOutcome::Ok);
    };
    if data.is_empty() {
        return Ok(WatchScanOutcome::Ok);
    }
    // Bind watch to the same full-source-size provenance as the ordinary
    // filesystem source. Autoroute keys distinguish a complete file from a
    // transformed/windowed payload, so `None` here made an editor save miss
    // calibration produced by `keyhog scan` over the identical file.
    let source_size_bytes = bytes.len() as u64;

    let chunk = Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "filesystem".into(),
            ctime_ns: None,
            path: Some(path.display().to_string().into()),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: Some(source_size_bytes),
            decoded_span: None,
        },
    };
    scan_runtime.clear_fragment_cache();
    let scan_result = scan_runtime.scan_chunk(&chunk);
    scan_runtime.clear_fragment_cache();
    let raw_matches = match scan_result {
        Ok(matches) => matches,
        Err(error) => {
            let palette = style::for_stderr();
            eprintln!("{} keyhog watch: {error}", style::fail("FAIL", &palette));
            return Ok(WatchScanOutcome::EngineFailure);
        }
    };
    // Route scanner matches through the SAME suppression + resolution pipeline
    // `keyhog scan` uses (allowlist / `.keyhogignore`, inline `keyhog:ignore`,
    // disabled detectors, confidence floors, severity, match resolution) before
    // printing, otherwise watch would surface findings the user explicitly
    // allowlisted purely because it took a different code path than scan (Law 10).
    let matches = match scan_runtime.filter_and_resolve(raw_matches) {
        Ok(matches) => matches,
        Err(error) => {
            let palette = style::for_stderr();
            eprintln!("{} keyhog watch: {error}", style::fail("FAIL", &palette));
            return Ok(WatchScanOutcome::EngineFailure);
        }
    };
    // Declarative `.keyhogignore.toml` (RuleSuppressor) — same post-filter
    // surface `keyhog scan` applies after finalize (KH-1329).
    let matches = filter_rule_suppressed(&rule_suppressor, matches);
    // Second dedup layer: the content pre-check above only suppresses a re-read
    // of byte-identical content, but a save's burst can read different
    // intermediate bytes that still produce the same findings. Collapse those to
    // one print by deduping on the finding SET; a genuine edit that changes
    // findings is a different fingerprint and prints again.
    if suppress_duplicate_findings(
        path,
        findings_fingerprint(&matches),
        Instant::now(),
        recently_scanned,
    ) {
        return Ok(WatchScanOutcome::Ok);
    }
    for m in matches {
        let credential_identity = format!(
            "{} sha256:{}",
            keyhog_core::redact(&m.credential),
            keyhog_core::hex_encode(m.credential_hash.as_bytes())
        );
        crate::style::print_diagnostic_finding(
            "\u{1F50D}",
            &m.detector_id,
            &path.display().to_string(),
            m.location.line,
            m.severity,
            m.confidence,
            &credential_identity,
        )
        .with_context(|| format!("write watch finding for {}", path.display()))?;
    }
    Ok(WatchScanOutcome::Ok)
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
    cap_map_fifo(
        &mut recently_scanned.entries,
        &mut recently_scanned.entry_order,
        path,
        (now, hash),
    );
    recently_scanned.scans_since_prune = recently_scanned.scans_since_prune.saturating_add(1);
    if recently_scanned.scans_since_prune >= DEDUP_PRUNE_INTERVAL {
        // Cheap time prune only when under the hard cap; overflow already uses
        // FIFO eviction so we never O(N) retain a multi-thousand-path map.
        recently_scanned.scans_since_prune = 0;
        if recently_scanned.entries.len() < DEDUP_MAX_ENTRIES / 2 {
            recently_scanned
                .entries
                .retain(|_, (last, _)| now.saturating_duration_since(*last) < DEDUP_WINDOW);
            recently_scanned
                .finding_entries
                .retain(|_, (last, _)| now.saturating_duration_since(*last) < DEDUP_WINDOW);
            // Rebuild order queues after retain (rare small-map path).
            recently_scanned
                .entry_order
                .retain(|p| recently_scanned.entries.contains_key(p));
            recently_scanned
                .finding_order
                .retain(|p| recently_scanned.finding_entries.contains_key(p));
        }
    }
    false
}

/// Order-independent fingerprint of a scan's complete finding identities.
/// Credential identity uses the scanner-owned SHA-256, never plaintext. The
/// complete stable location prevents two sources or history objects from
/// aliasing, while sorted framed digests avoid XOR cancellation for duplicates.
fn findings_fingerprint(matches: &[keyhog_core::RawMatch]) -> [u8; 32] {
    let mut identities = Vec::with_capacity(matches.len());
    for m in matches {
        let mut identity = crate::stable_hash::StableHasher::new("watch-finding-identity-v1");
        identity
            .field_str("detector_id", &m.detector_id)
            .field_bytes("credential_hash", m.credential_hash.as_bytes())
            .field_str("location.source", &m.location.source)
            .field_option_str("location.file_path", m.location.file_path.as_deref())
            .field_option_usize("location.line", m.location.line)
            .field_usize("location.offset", m.location.offset)
            .field_option_str("location.commit", m.location.commit.as_deref())
            .field_option_str("location.author", m.location.author.as_deref())
            .field_option_str("location.date", m.location.date.as_deref());
        identities.push(identity.finish_256());
    }
    identities.sort_unstable();
    let mut set = crate::stable_hash::StableHasher::new("watch-finding-set-v1");
    set.field_usize("findings", identities.len());
    for (index, identity) in identities.iter().enumerate() {
        set.field_usize("finding.index", index)
            .field_bytes("finding.identity", identity);
    }
    set.finish_256()
}

/// Suppress a re-print when the SAME finding set for `path` was already printed
/// within `DEDUP_WINDOW`. Mirrors `suppress_duplicate_event` but keyed on the
/// post-scan finding fingerprint, which (unlike the raw-content hash) is robust
/// to a burst's intermediate partial reads, so the operator sees one finding set
/// per real change.
fn suppress_duplicate_findings(
    path: &std::path::Path,
    fingerprint: [u8; 32],
    now: Instant,
    recently_scanned: &mut WatchDedupeState,
) -> bool {
    if let Some((last, last_fp)) = recently_scanned.finding_entries.get(path) {
        if *last_fp == fingerprint && now.saturating_duration_since(*last) < DEDUP_WINDOW {
            return true;
        }
    }
    cap_map_fifo(
        &mut recently_scanned.finding_entries,
        &mut recently_scanned.finding_order,
        path,
        (now, fingerprint),
    );
    false
}

pub(crate) mod testing {
    use anyhow::Result;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};
    pub(crate) fn content_hash(data: &[u8]) -> u64 {
        super::content_hash(data)
    }

    /// Resolve watch roots exactly as `keyhog watch` does at startup: shared
    /// scan-root folding plus the directory-only constraint.
    pub(crate) fn resolve_watch_roots(requested: &[PathBuf]) -> Result<Vec<PathBuf>> {
        super::resolve_watch_roots(requested)
    }

    /// Format watched roots into the `keyhog scan <hint>` remediation string.
    pub(crate) fn roots_hint(roots: &[PathBuf]) -> String {
        super::roots_hint(roots)
    }

    /// Longest-prefix root selection for multi-root RuleSuppressor maps (KH-1433).
    #[cfg(test)]
    pub(crate) fn rule_suppressor_for_path<'a>(
        path: &Path,
        roots: &[PathBuf],
        suppressors: &'a std::collections::HashMap<PathBuf, keyhog_core::RuleSuppressor>,
    ) -> &'a keyhog_core::RuleSuppressor {
        super::rule_suppressor_for_path(path, roots, suppressors)
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

    pub(crate) fn findings_fingerprint(matches: &[keyhog_core::RawMatch]) -> [u8; 32] {
        super::findings_fingerprint(matches)
    }

    /// Drive the REAL `keyhog watch` scan + suppression pipeline over `body`
    /// (written to `file_name` under `root`, which also anchors `.keyhog.toml` /
    /// `.keyhogignore` discovery) and return the detector ids that SURVIVE the
    /// shared filter, the exact set `watch` would print. Forces the CPU backend
    /// so the test needs no autoroute calibration, and writes the body to a real
    /// on-disk file so inline `keyhog:ignore` suppression (which re-reads the
    /// file) exercises the same path production does.
    ///
    /// Test-only: consumed solely by the `#[cfg(test)] mod tests` below, so it is
    /// gated to keep it out of release builds (Law-11 / no dead code in shipped
    /// binaries), unlike its `testing`-module siblings, which non-test integration
    /// helpers (`crate::testing`) still call.
    #[cfg(test)]
    pub(crate) fn scan_file_surviving_detector_ids(
        root: &Path,
        file_name: &str,
        body: &str,
    ) -> Result<Vec<String>> {
        use crate::orchestrator::load_rule_suppressor;
        use keyhog_core::{Chunk, ChunkMetadata};
        let file_path = root.join(file_name);
        std::fs::write(&file_path, body)?;
        // Pass the DEFAULT `detectors` sentinel, the ONLY non-existent path the
        // scan-config validator whitelists (`validate_detector_path_for_scan`)
        // so this resolves to the EMBEDDED corpus exactly as `keyhog watch` does
        // with no `--detectors` and no `detectors/` dir present (the cli crate
        // has none). A made-up non-existent path is (correctly) rejected as an
        // operator typo, so it can't be used to force embedded.
        let embedded_sentinel = std::path::Path::new("detectors");
        #[cfg(feature = "simd")]
        let test_backend = keyhog_scanner::ScanBackend::SimdCpu;
        #[cfg(not(feature = "simd"))]
        let test_backend = keyhog_scanner::ScanBackend::CpuFallback;
        let runtime = crate::orchestrator::setup_default_scan_runtime_for_test(
            embedded_sentinel,
            false,
            None,
            Some(rayon::current_num_threads()),
            Some(test_backend),
            "keyhog watch",
            false,
            Some(root),
        )?;
        let chunk = Chunk {
            data: body.to_string().into(),
            metadata: ChunkMetadata {
                source_type: "filesystem".into(),
                ctime_ns: None,
                path: Some(file_path.display().to_string().into()),
                ..Default::default()
            },
        };
        let matches = runtime.scan_chunk(&chunk)?;
        let filtered = runtime.filter_and_resolve(matches)?;
        let rule_suppressor = load_rule_suppressor(Some(root))?;
        let kept = super::filter_rule_suppressed(&rule_suppressor, filtered);
        Ok(kept
            .iter()
            .map(|m| m.detector_id.as_ref().to_string())
            .collect())
    }

    /// Drive two consecutive post-scan finding-set decisions for one path.
    /// Mirrors `duplicate_event_decisions` but on the finding fingerprint,
    /// which is what collapses a save burst's identical-finding re-prints.
    pub(crate) fn duplicate_findings_decisions(
        first: [u8; 32],
        second: [u8; 32],
        elapsed: Duration,
    ) -> (bool, bool) {
        let mut recently_scanned = super::WatchDedupeState::default();
        let path = Path::new("watched-file.txt");
        let first_at = Instant::now();
        let second_at = first_at + elapsed;
        let first_suppressed =
            super::suppress_duplicate_findings(path, first, first_at, &mut recently_scanned);
        let second_suppressed =
            super::suppress_duplicate_findings(path, second, second_at, &mut recently_scanned);
        (first_suppressed, second_suppressed)
    }
}

/// Apply the declarative `.keyhogignore.toml` suppressor to post-scan
/// matches. The suppression evaluation span lives here, the single owner, so
/// the watch scan path and its test seam measure the same filter.
pub(crate) fn filter_rule_suppressed(
    rule_suppressor: &RuleSuppressor,
    matches: Vec<RawMatch>,
) -> Vec<RawMatch> {
    let _eval_span = keyhog_profile::span(keyhog_profile::Stage::Suppression);
    matches
        .into_iter()
        .filter(|m| !rule_suppressor.matches_raw_match(m))
        .collect()
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

#[cfg(test)]
mod tests;
