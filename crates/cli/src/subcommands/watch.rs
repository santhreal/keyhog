//! `keyhog watch <path>` - daemon mode.
//!
//! Tier-B moat innovation #7 from the internal design notes: compile-once,
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
use crate::orchestrator::{setup_default_scan_runtime, DefaultScanRuntime};
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

/// FNV-1a 64-bit offset basis and prime. Shared by the raw-content hash
/// ([`content_hash`]) and the finding-set fingerprint ([`findings_fingerprint`]),
/// which both use the same non-cryptographic hash purely to collapse a save
/// burst's duplicate inotify events. Named here (instead of pasting the two
/// magic constants into each function) so both provably use one algorithm and
/// cannot silently drift apart.
const FNV_OFFSET_BASIS: u64 = keyhog_scanner::FNV_OFFSET_BASIS;
const FNV_PRIME: u64 = keyhog_scanner::FNV_PRIME;

#[derive(Default)]
struct WatchDedupeState {
    /// Pre-scan dedup keyed on RAW content hash: skips the scan when a burst
    /// event re-reads byte-identical content (the cheap common case).
    entries: HashMap<PathBuf, (Instant, u64)>,
    /// Post-scan dedup keyed on the FINDING-SET fingerprint: a single save fires
    /// a CREATE+MODIFY(+CLOSE_WRITE) burst, and a read taken mid-write can return
    /// bytes that differ from the final read (e.g. missing the trailing newline)
    /// yet yield the SAME findings -- which then printed twice. This layer
    /// collapses that to one print while a genuine edit (different findings)
    /// still prints.
    finding_entries: HashMap<PathBuf, (Instant, u64)>,
    scans_since_prune: usize,
}

pub(crate) fn run(args: WatchArgs) -> Result<()> {
    let watch_roots = resolve_watch_roots(&args.paths)?;
    // The space-joined root list doubles as actionable advice: `keyhog scan`
    // accepts the same multi-root form, so every "run keyhog scan <roots>"
    // hint below stays copy-pasteable for one, two, or many watched trees.
    let roots_hint = roots_hint(&watch_roots);

    // Parse the explicit backend BEFORE compiling the scanner so an invalid
    // value fails fast. With it set, the per-file scan forces that backend and
    // never consults the autoroute cache -- so watch works on an uncalibrated
    // binary (and the autoroute error's `--backend` advice is actionable here).
    let backend_override = crate::orchestrator::explicit_backend_override(args.backend.as_deref())?;
    // Root config discovery + allowlist loading at the primary watched tree, so
    // `keyhog watch` resolves the SAME `.keyhog.toml` / `.keyhogignore` policy an
    // equivalent `keyhog scan <root>` would (folded roots share one policy root,
    // mirroring scan's single-root allowlist anchor).
    let scan_runtime = setup_default_scan_runtime(
        &args.detectors,
        args.cache_dir.clone(),
        None,
        "keyhog watch",
        false,
        watch_roots.first().map(PathBuf::as_path),
    )?
    .with_backend_override(backend_override);
    let detector_count = scan_runtime.detector_count();

    if !args.quiet {
        eprintln!(
            "\u{1F441}  keyhog watch (\u{2630} {} detectors compiled)",
            detector_count
        );
        // One status line per watched root so the operator can confirm every
        // tree the daemon is actually monitoring, not just the first.
        for root in &watch_roots {
            eprintln!("    watching: {}", root.display());
        }
        eprintln!("    Ctrl-C to exit");
        eprintln!();
    }

    let (tx, rx) = channel::<notify::Result<Event>>();
    let notify_channel_closed_for_callback = AtomicBool::new(false);
    let roots_hint_for_callback = roots_hint.clone();

    // Hold the watcher for the duration of the daemon. The `notify` crate
    // requires us to keep the handle alive; dropping it stops the watcher.
    // ONE watcher serves every root — `notify` lets us register additional
    // paths on the same handle below — so all roots share this channel and the
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
                    roots_hint
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

/// Resolve the requested watch roots into the canonical directory set the
/// daemon will monitor.
///
/// Shares [`crate::sources::resolve_scan_roots`] with `keyhog scan` so both
/// entry points validate, canonicalize, fold nested/duplicate roots (loudly,
/// Law 10), and preserve first-seen order through one resolution contract — no
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
        // Canonicalize each surviving root so the watcher registers — and every
        // finding reports — the absolute real path, exactly as the historical
        // single-root `watch` did. `resolve_scan_roots` keeps the user's
        // spelling (relative, `.`/`..`), which is fine for a one-shot scan but
        // would leave a live daemon printing `./foo` paths. Existence was
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
/// OOMs the single-threaded daemon; (2) no special-file guard, so a FIFO
/// created in the tree — which itself fires an inotify CREATE event — is opened
/// blocking and HANGS the event loop forever, wedging the whole watcher; (3) no
/// `O_NOFOLLOW`, so a symlink is followed out of the watched root. `0` selects
/// the walker's hard 2 GiB TOCTOU sanity cap (watch carries no `--max-file-size`
/// budget); a special file returns `InvalidInput` and an oversized file
/// `InvalidData`, both surfaced loudly by `scan_file`'s existing error arm.
fn read_watched_file(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    keyhog_sources::read_file_safe_bytes(path, 0)
}

fn scan_file(
    scan_runtime: &DefaultScanRuntime,
    path: &std::path::Path,
    recently_scanned: &mut WatchDedupeState,
) -> Result<()> {
    // Read BYTES (not `read_to_string`) through the walker's guarded read (see
    // `read_watched_file`) and decode through the SAME path the `keyhog scan`
    // walker uses. `read_to_string` failed on the first non-UTF-8 byte and
    // silently dropped the whole file, so a config with one stray Latin-1 byte
    // was scanned by `scan` (lossy decode) but invisibly skipped by `watch` — a
    // recall divergence between the two entry points (Law 10). Now both share
    // the guarded read + `decode_file_bytes`, so watch recovers the same
    // secrets and can neither hang on a FIFO nor OOM on a huge file.
    let bytes = match read_watched_file(path) {
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
            path: Some(path.display().to_string().into()),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: None,
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
            return Ok(());
        }
    };
    // Route scanner matches through the SAME suppression + resolution pipeline
    // `keyhog scan` uses (allowlist / `.keyhogignore`, inline `keyhog:ignore`,
    // disabled detectors, confidence floors, severity, match resolution) before
    // printing — otherwise watch would surface findings the user explicitly
    // allowlisted purely because it took a different code path than scan (Law 10).
    let matches = match scan_runtime.filter_and_resolve(raw_matches) {
        Ok(matches) => matches,
        Err(error) => {
            let palette = style::for_stderr();
            eprintln!("{} keyhog watch: {error}", style::fail("FAIL", &palette));
            return Ok(());
        }
    };
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
        return Ok(());
    }
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
        // Evict stale entries periodically so the maps cannot grow without
        // bound, without making every event pay an O(active_paths) scan.
        recently_scanned.scans_since_prune = 0;
        recently_scanned
            .entries
            .retain(|_, (last, _)| now.saturating_duration_since(*last) < DEDUP_WINDOW);
        recently_scanned
            .finding_entries
            .retain(|_, (last, _)| now.saturating_duration_since(*last) < DEDUP_WINDOW);
    }
    false
}

/// Order-independent fingerprint of a scan's FINDING SET, built only from each
/// match's stable position identity (detector id + line + byte offset) -- never
/// the credential bytes. Two reads of the same save yield the same set even when
/// their raw bytes differ (a partial mid-write read missing the trailing
/// newline), so the burst's duplicate output collapses to one print.
fn findings_fingerprint(matches: &[keyhog_core::RawMatch]) -> u64 {
    let mut combined: u64 = 0;
    for m in matches {
        let mut h: u64 = FNV_OFFSET_BASIS;
        for b in m.detector_id.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(FNV_PRIME);
        }
        h ^= m.location.line.unwrap_or(0) as u64; // LAW10: dedup-key hash input; recall-safe
        h = h.wrapping_mul(FNV_PRIME);
        h ^= m.location.offset as u64;
        h = h.wrapping_mul(FNV_PRIME);
        // XOR-combine so the fingerprint is independent of match order.
        combined ^= h;
    }
    combined
}

/// Suppress a re-print when the SAME finding set for `path` was already printed
/// within `DEDUP_WINDOW`. Mirrors `suppress_duplicate_event` but keyed on the
/// post-scan finding fingerprint, which (unlike the raw-content hash) is robust
/// to a burst's intermediate partial reads, so the operator sees one finding set
/// per real change.
fn suppress_duplicate_findings(
    path: &std::path::Path,
    fingerprint: u64,
    now: Instant,
    recently_scanned: &mut WatchDedupeState,
) -> bool {
    if let Some((last, last_fp)) = recently_scanned.finding_entries.get(path) {
        if *last_fp == fingerprint && now.saturating_duration_since(*last) < DEDUP_WINDOW {
            return true;
        }
    }
    recently_scanned
        .finding_entries
        .insert(path.to_path_buf(), (now, fingerprint));
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

    pub(crate) fn findings_fingerprint(matches: &[keyhog_core::RawMatch]) -> u64 {
        super::findings_fingerprint(matches)
    }

    /// Drive the REAL `keyhog watch` scan + suppression pipeline over `body`
    /// (written to `file_name` under `root`, which also anchors `.keyhog.toml` /
    /// `.keyhogignore` discovery) and return the detector ids that SURVIVE the
    /// shared filter — the exact set `watch` would print. Forces the CPU backend
    /// so the test needs no autoroute calibration, and writes the body to a real
    /// on-disk file so inline `keyhog:ignore` suppression (which re-reads the
    /// file) exercises the same path production does.
    ///
    /// Test-only: consumed solely by the `#[cfg(test)] mod tests` below, so it is
    /// gated to keep it out of release builds (Law-11 / no dead code in shipped
    /// binaries) — unlike its `testing`-module siblings, which non-test integration
    /// helpers (`crate::testing`) still call.
    #[cfg(test)]
    pub(crate) fn scan_file_surviving_detector_ids(
        root: &Path,
        file_name: &str,
        body: &str,
    ) -> Result<Vec<String>> {
        use keyhog_core::{Chunk, ChunkMetadata};
        let file_path = root.join(file_name);
        std::fs::write(&file_path, body)?;
        // Pass the DEFAULT `detectors` sentinel — the ONLY non-existent path the
        // scan-config validator whitelists (`validate_detector_path_for_scan`) —
        // so this resolves to the EMBEDDED corpus exactly as `keyhog watch` does
        // with no `--detectors` and no `detectors/` dir present (the cli crate
        // has none). A made-up non-existent path is (correctly) rejected as an
        // operator typo, so it can't be used to force embedded.
        let embedded_sentinel = std::path::Path::new("detectors");
        let runtime = super::setup_default_scan_runtime(
            embedded_sentinel,
            None,
            None,
            "keyhog watch",
            false,
            Some(root),
        )?
        .with_backend_override(Some(keyhog_scanner::ScanBackend::SimdCpu));
        let chunk = Chunk {
            data: body.to_string().into(),
            metadata: ChunkMetadata {
                source_type: "filesystem".into(),
                path: Some(file_path.display().to_string().into()),
                ..Default::default()
            },
        };
        let matches = runtime.scan_chunk(&chunk)?;
        let filtered = runtime.filter_and_resolve(matches)?;
        Ok(filtered
            .iter()
            .map(|m| m.detector_id.as_ref().to_string())
            .collect())
    }

    /// Drive two consecutive post-scan finding-set decisions for one path.
    /// Mirrors `duplicate_event_decisions` but on the finding fingerprint,
    /// which is what collapses a save burst's identical-finding re-prints.
    pub(crate) fn duplicate_findings_decisions(
        first: u64,
        second: u64,
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
