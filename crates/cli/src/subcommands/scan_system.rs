//! `keyhog scan-system` - recursive system-wide credential audit.
//!
//! Walks every mounted drive (skipping pseudo-FS and, by default, network
//! mounts), discovers every `.git` repository on the way, and runs the
//! same scan + git-history pipeline that `keyhog scan --git-history`
//! uses on each. Honors a hard `--space <N>` ceiling on total bytes
//! scanned so it can't accidentally fill a CI runner.
//!
//! Use case (per CEO directive): triage a fresh machine for credentials
//! before EnvSeal-sealing them. Should be paranoid by default - does NOT
//! honor `.gitignore` unless `--respect-gitignore` is passed, because an
//! attacker stashing a leaked key would `.gitignore` it.

mod mounts;

use crate::args::ScanSystemArgs;
use crate::exit_codes::EXIT_FINDINGS;
use crate::format::format_bytes;
use crate::orchestrator::{compile_default_scan_runtime, DefaultScanRuntime, StreamingSourceEvent};
use crate::style;
use anyhow::{Context, Result};
use mounts::enumerate_mounts;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Hard ceiling on resident findings held in memory during a system scan.
///
/// audit (memory): the old code did `out.extend(matches)` for every chunk
/// across the whole filesystem walk + every git history into one unbounded
/// `Vec<RawMatch>`. The only bound was `--space` on BYTES SCANNED, not on
/// findings retained, so a secret-dense corpus (a file full of high-entropy
/// assignments) produced millions of `RawMatch` entries - each carrying the
/// plaintext `credential`, a path `String`, and a `companions` map - all held
/// resident until the whole multi-TB scan finished. We now (a) convert each
/// `RawMatch` to a disk-safe `RedactedFinding` the instant it is produced,
/// dropping the plaintext credential bytes immediately, and (b) cap the
/// resident set at this ceiling so memory is bounded independent of corpus
/// secret-density. Beyond the cap we stop retaining findings but keep counting
/// them, so the exit-code contract (0 = clean, 1 = findings) still holds.
const MAX_RESIDENT_FINDINGS: usize = 1_000_000;

/// Bounded collector for system-scan findings.
///
/// Holds only `RedactedFinding`s (never `RawMatch`, so no plaintext secret is
/// retained), caps the resident set at [`MAX_RESIDENT_FINDINGS`], and tracks
/// the total count seen even after the cap is hit. Conversion happens per
/// chunk in `scan_mount`/`scan_git_history`, so raw matches are dropped as
/// soon as they are produced rather than accumulated.
struct FindingSink {
    redacted: Vec<keyhog_core::RedactedFinding>,
    total: u64,
    cap: usize,
    capped_warned: bool,
    /// Chunks the source could not yield (corrupt git object, perm-denied
    /// `.git`, non-UTF-8 / unreadable file mid-walk). Law 10: a dropped chunk is
    /// unscanned bytes — a recall loss — so it is COUNTED and surfaced in the
    /// final summary, never silently `continue`d past. A non-zero count means the
    /// "complete" scan did not cover everything.
    skipped_chunks: u64,
}

impl FindingSink {
    fn new() -> Self {
        Self::with_cap(MAX_RESIDENT_FINDINGS)
    }

    fn with_cap(cap: usize) -> Self {
        Self {
            redacted: Vec::new(),
            total: 0,
            cap,
            capped_warned: false,
            skipped_chunks: 0,
        }
    }

    /// Record that a source chunk could not be read and was dropped from the
    /// scan. The count is surfaced in the final summary so the recall loss is
    /// visible (Law 10) instead of a silent `Err(_) => continue`.
    fn record_skipped_chunk(&mut self) {
        self.skipped_chunks += 1;
    }

    /// Number of source chunks dropped due to read errors (unscanned bytes).
    fn skipped_chunks(&self) -> u64 {
        self.skipped_chunks
    }

    /// Convert and absorb a chunk's worth of raw matches, dropping the raw
    /// (plaintext-bearing) matches immediately. Retains up to the resident
    /// cap; counts everything.
    fn absorb(&mut self, matches: Vec<keyhog_core::RawMatch>) {
        for m in &matches {
            self.total += 1;
            if self.redacted.len() < self.cap {
                self.redacted.push(m.to_redacted());
            } else if !self.capped_warned {
                self.capped_warned = true;
                let palette = style::for_stderr();
                eprintln!(
                    "{} resident findings cap ({}) reached; further findings are \
                     counted but not retained in memory",
                    style::warn("WARN", &palette),
                    self.cap
                );
            }
        }
        // `matches` (the plaintext-bearing RawMatch Vec) is dropped here.
    }

    fn is_empty(&self) -> bool {
        self.total == 0
    }

    fn total(&self) -> u64 {
        self.total
    }

    fn retained_len(&self) -> usize {
        self.redacted.len()
    }

    fn cap(&self) -> usize {
        self.cap
    }

    fn capped_warned(&self) -> bool {
        self.capped_warned
    }

    fn retained_hash(&self, index: usize) -> Option<keyhog_core::CredentialHash> {
        self.redacted
            .get(index)
            .map(|finding| finding.credential_hash)
    }

    fn retained_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.redacted)
    }
}

#[doc(hidden)]
pub(crate) mod testing {
    pub(crate) const MAX_RESIDENT_FINDINGS: usize = super::MAX_RESIDENT_FINDINGS;

    pub(crate) struct FindingSink {
        inner: super::FindingSink,
    }

    impl FindingSink {
        pub(crate) fn new() -> Self {
            Self {
                inner: super::FindingSink::new(),
            }
        }

        pub(crate) fn with_cap(cap: usize) -> Self {
            Self {
                inner: super::FindingSink::with_cap(cap),
            }
        }

        pub(crate) fn record_skipped_chunk(&mut self) {
            self.inner.record_skipped_chunk();
        }

        pub(crate) fn skipped_chunks(&self) -> u64 {
            self.inner.skipped_chunks()
        }

        pub(crate) fn absorb(&mut self, matches: Vec<keyhog_core::RawMatch>) {
            self.inner.absorb(matches);
        }

        pub(crate) fn is_empty(&self) -> bool {
            self.inner.is_empty()
        }

        pub(crate) fn total(&self) -> u64 {
            self.inner.total()
        }

        pub(crate) fn retained_len(&self) -> usize {
            self.inner.retained_len()
        }

        pub(crate) fn cap(&self) -> usize {
            self.inner.cap()
        }

        pub(crate) fn capped_warned(&self) -> bool {
            self.inner.capped_warned()
        }

        pub(crate) fn retained_hash(&self, index: usize) -> Option<keyhog_core::CredentialHash> {
            self.inner.retained_hash(index)
        }

        pub(crate) fn retained_json(&self) -> Result<String, serde_json::Error> {
            self.inner.retained_json()
        }
    }
}

pub(crate) fn run(args: ScanSystemArgs) -> Result<ExitCode> {
    crate::runtime_preflight::validate_scan_runtime_config()?;
    crate::orchestrator_config::configure_hyperscan_cache_dir(args.cache_dir.clone())?;

    if args.space == 0 {
        anyhow::bail!("scan-system --space must be greater than zero bytes");
    }
    let hw = keyhog_scanner::hw_probe::probe_hardware();
    crate::orchestrator_config::configure_threads(args.threads, hw.physical_cores);

    // kimi-wave3 §5: lockdown forbids --include-network on scan-system
    // because NFS/SMB/sshfs mounts host other tenants' data and a
    // scan-system run would walk straight through them.
    if args.lockdown && args.include_network {
        anyhow::bail!(
            "lockdown mode forbids --include-network (would scan NFS/SMB/sshfs \
             mounts that may host other tenants' credentials)."
        );
    }

    eprintln!(
        "🛰  keyhog scan-system | space cap: {} | network mounts: {} | git history: {}",
        format_bytes(args.space),
        if args.include_network { "yes" } else { "no" },
        if args.no_git_history { "no" } else { "yes" },
    );

    // Always-on hardening: every scan-system run disables core dumps and
    // ptrace, even outside lockdown mode. `--lockdown` applies the stronger
    // tier here because the main `scan` orchestrator gate does not run for
    // this subcommand.
    let report = keyhog_core::apply_protections(args.lockdown);
    if args.lockdown && !report.failures.is_empty() {
        anyhow::bail!(
            "lockdown mode requested but protections failed to apply: {:?}",
            report.failures
        );
    }
    if !args.lockdown && !report.failures.is_empty() {
        let palette = style::for_stderr();
        eprintln!(
            "{} hardening warnings: {:?}",
            style::warn("WARN", &palette),
            report.failures
        );
    }
    if args.lockdown {
        let palette = style::for_stderr();
        eprintln!(
            "{} LOCKDOWN MODE: coredump-blocked, mlocked, network mounts refused",
            style::info("INFO", &palette)
        );
    }
    let palette = style::for_stderr();
    eprintln!(
        "{} core_dumps={} ptrace={} (always-on protections applied)",
        style::info("INFO", &palette),
        if report.no_core_dumps { "off" } else { "on" },
        if report.no_ptrace {
            "denied"
        } else {
            "allowed"
        },
    );

    let detectors = crate::orchestrator_config::load_detectors_or_embedded(&args.detectors)?;
    let palette = style::for_stderr();
    eprintln!(
        "{} loaded {} detectors",
        style::info("INFO", &palette),
        detectors.len()
    );
    let scan_runtime = compile_default_scan_runtime(detectors, |e| {
        crate::orchestrator_config::detector_compile_failed(
            "keyhog scan-system",
            &args.detectors,
            e,
        )
    })?;
    // System-wide scan touches every mounted drive and every git history:
    // detector regexes compile lazily on first use, so warm them all up
    // front (in parallel) rather than stalling the first file that hits each
    // detector across a multi-hour, multi-TB walk.
    scan_runtime.warm();

    let mounts = enumerate_mounts(args.include_network)?;
    eprintln!("💾 will scan {} mount(s):", mounts.len());
    for m in &mounts {
        eprintln!("   {}", m.display());
    }

    // Discover git repos under each mount BEFORE walking files, so we can
    // include their .git directories explicitly even when they're hidden
    // by .gitignore-style filters.
    let mut git_repos: Vec<PathBuf> = Vec::new();
    if !args.no_git_history {
        let skip_dirs = crate::skip_dirs::SkipDirPolicy::load()?;
        for mount in &mounts {
            discover_git_repos(mount, &mut git_repos, &skip_dirs);
        }
        eprintln!("🌿 discovered {} git repo(s)", git_repos.len());
    }

    let bytes_scanned = Arc::new(AtomicU64::new(0));
    let space_cap = args.space;
    // Bounded sink: holds only redacted findings, capped at
    // MAX_RESIDENT_FINDINGS. Raw matches are converted + dropped per chunk in
    // scan_mount/scan_git_history so resident memory is bounded independent of
    // corpus secret-density (audit: memory / unbounded findings Vec).
    let mut sink = FindingSink::new();

    // Walk each mount with the existing walker but with a budget callback
    // that aborts when --space is hit.
    for mount in &mounts {
        if bytes_scanned.load(Ordering::Relaxed) >= space_cap {
            let palette = style::for_stderr();
            eprintln!(
                "{} space cap reached ({}); skipping remaining mounts",
                style::warn("WARN", &palette),
                format_bytes(space_cap)
            );
            break;
        }
        let palette = style::for_stderr();
        eprintln!(
            "{} walking {}",
            style::info("INFO", &palette),
            mount.display()
        );
        scan_mount(
            &scan_runtime,
            mount,
            &args,
            &bytes_scanned,
            space_cap,
            &mut sink,
        )?;
    }

    // Then walk every git history.
    if !args.no_git_history {
        for repo in &git_repos {
            if bytes_scanned.load(Ordering::Relaxed) >= space_cap {
                let palette = style::for_stderr();
                eprintln!(
                    "{} space cap reached; skipping remaining git histories",
                    style::warn("WARN", &palette)
                );
                break;
            }
            let palette = style::for_stderr();
            eprintln!(
                "{} git history: {}",
                style::info("INFO", &palette),
                repo.display()
            );
            scan_git_history(&scan_runtime, repo, &bytes_scanned, space_cap, &mut sink)?;
        }
    }

    let palette = style::for_stderr();
    eprintln!(
        "{} system scan complete | bytes scanned: {} | findings: {}",
        style::pass("PASS", &palette),
        format_bytes(bytes_scanned.load(Ordering::Relaxed)),
        sink.total
    );
    // Law 10: if any chunk was unreadable, the "complete" above covered LESS than
    // the whole tree. Say so loudly — a partial audit that looks clean is worse
    // than no audit.
    if sink.skipped_chunks() > 0 {
        let palette = style::for_stderr();
        eprintln!(
            "{} {} source chunk(s) were UNREADABLE and went unscanned (corrupt git \
             objects, permission-denied paths, or non-text files). This scan did \
             NOT cover everything; rerun affected paths with elevated permissions \
             to close the gap.",
            style::warn("WARN", &palette),
            sink.skipped_chunks()
        );
    }

    if let Some(out) = &args.output {
        // SECURITY: never write `RawMatch` to disk - its `credential` field
        // is the plaintext secret. The sink already holds `RedactedFinding`s
        // (converted per chunk), so no plaintext can reach disk here.
        // See kimi-wave1 audit finding 2.1.
        let json = serde_json::to_string_pretty(&sink.redacted).context("serialize findings")?;
        crate::atomic_file::write_bytes(out, json.as_bytes())
            .with_context(|| format!("atomically writing {}", out.display()))?;
        let palette = style::for_stderr();
        eprintln!(
            "{} wrote findings to {}",
            style::info("INFO", &palette),
            out.display()
        );
    } else {
        for m in &sink.redacted {
            println!(
                "FINDING {} {}{} {:?}  {}",
                m.detector_id,
                m.location.file_path.as_deref().unwrap_or("<no-path>"), // LAW10: absent path/field => display placeholder for REPORTING only; finding still emitted, recall-safe
                m.location.line.map(|l| format!(":{l}")).unwrap_or_default(), // LAW10: missing/non-string field => empty/placeholder; recall-safe
                m.severity,
                m.credential_redacted
            );
        }
    }

    // Exit-code contract (kimi CLI-001): scan-system has to surface
    // "found credentials" via a non-zero exit code or CI pipelines
    // can't gate on it. Match the rest of the CLI: 0 = clean,
    // 1 = findings above floor, 2 = error (handled by caller's
    // Result<_> path).
    if sink.is_empty() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(EXIT_FINDINGS))
    }
}

/// Recursively find `.git` directories (worktrees + bare repos).
///
/// kimi-wave2 §Critical: previously this followed symlinks via plain
/// `fs::read_dir` + `is_dir`. A circular symlink (e.g. `a/b -> ../a`)
/// or a long chain (`/proc/*/cwd` style) caused unbounded growth and
/// in some cases an OOM kill. We now canonicalize each candidate dir
/// before recursing and skip any path we've already visited.
fn discover_git_repos(
    root: &Path,
    out: &mut Vec<PathBuf>,
    skip_dirs: &crate::skip_dirs::SkipDirPolicy,
) {
    use std::collections::HashSet;
    use std::fs;
    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut stack: Vec<PathBuf> = Vec::new();

    let canon = match fs::canonicalize(root) {
        Ok(canon) => canon,
        Err(error) => {
            let palette = style::for_stderr();
            eprintln!(
                "{} cannot canonicalize root path while discovering git repositories; skipping discovery for {}: {}",
                style::warn("WARN", &palette),
                root.display(),
                error
            );
            tracing::warn!(
                root = %root.display(),
                %error,
                "cannot canonicalize root path while discovering git repositories; skipping discovery"
            );
            return;
        }
    };
    stack.push(canon);

    while let Some(dir) = stack.pop() {
        if !visited.insert(dir.clone()) {
            continue;
        }

        let dot_git = dir.join(".git");
        if dot_git.exists() {
            out.push(dir.clone());
            continue;
        }
        if dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".git"))
            && dir.join("HEAD").exists()
            && dir.join("objects").exists()
        {
            out.push(dir.clone());
            continue;
        }
        if let Some(name) = dir.file_name().and_then(|n| n.to_str()) {
            if skip_dirs.is_git_discovery_component(name) {
                continue;
            }
        }
        match fs::read_dir(&dir) {
            Ok(entries) => {
                for entry in entries {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(error) => {
                            tracing::warn!(
                                dir = %dir.display(),
                                %error,
                                "cannot read directory entry while discovering git repositories; skipping entry"
                            );
                            continue;
                        }
                    };
                    let file_type = match entry.file_type() {
                        Ok(file_type) => file_type,
                        Err(error) => {
                            tracing::warn!(
                                path = %entry.path().display(),
                                %error,
                                "cannot read directory entry type while discovering git repositories; skipping entry"
                            );
                            continue;
                        }
                    };
                    if file_type.is_dir() {
                        match fs::canonicalize(entry.path()) {
                            Ok(canon) => {
                                if !visited.contains(&canon) {
                                    stack.push(canon);
                                }
                            }
                            Err(error) => {
                                tracing::warn!(
                                    path = %entry.path().display(),
                                    %error,
                                    "cannot canonicalize directory while discovering git repositories; skipping subtree"
                                );
                            }
                        }
                    }
                }
            }
            Err(error) => {
                tracing::warn!(
                    dir = %dir.display(),
                    %error,
                    "cannot read directory while discovering git repositories; skipping subtree"
                );
            }
        }
    }
}

fn scan_mount(
    scan_runtime: &DefaultScanRuntime,
    root: &Path,
    args: &ScanSystemArgs,
    bytes_scanned: &AtomicU64,
    space_cap: u64,
    out: &mut FindingSink,
) -> Result<()> {
    use keyhog_sources::FilesystemSource;

    // scan-system is paranoid by default - walks files even if listed in
    // `.gitignore` / `.keyhogignore`. An attacker stashing a leaked key
    // would gitignore it; respecting gitignore here would let that hide.
    let source =
        FilesystemSource::new(root.to_path_buf()).with_respect_gitignore(args.respect_gitignore);
    crate::orchestrator::scan_streaming_source(
        scan_runtime,
        &source,
        "filesystem",
        root,
        || bytes_scanned.load(Ordering::Relaxed) >= space_cap,
        |event| {
            handle_streaming_source_event(event, bytes_scanned, out);
            Ok(())
        },
    )
}

fn scan_git_history(
    scan_runtime: &DefaultScanRuntime,
    repo: &Path,
    bytes_scanned: &AtomicU64,
    space_cap: u64,
    out: &mut FindingSink,
) -> Result<()> {
    #[cfg(feature = "git")]
    {
        let source = keyhog_sources::GitSource::new(repo.to_path_buf());
        crate::orchestrator::scan_streaming_source(
            scan_runtime,
            &source,
            "git-history",
            repo,
            || bytes_scanned.load(Ordering::Relaxed) >= space_cap,
            |event| {
                handle_streaming_source_event(event, bytes_scanned, out);
                Ok(())
            },
        )
    }
    #[cfg(not(feature = "git"))]
    {
        let _ = (scan_runtime, bytes_scanned, space_cap);
        // LAW10: unused-binding marker; no runtime effect, not a fallback.
        // Law 10: this binary was built WITHOUT the `git` feature, so the git
        // history of a discovered repo cannot be scanned — those commits are
        // unscanned bytes (a recall loss), not "nothing to do". The banner above
        // announced "git history: yes" and "discovered N git repo(s)", so a
        // trace-only skip would let a partial audit look complete.
        // Surface it LOUDLY on stderr AND count it as a skipped chunk so the
        // final summary's "did NOT cover everything" warning fires.
        let palette = style::for_stderr();
        eprintln!(
            "{} keyhog scan-system: git history of {} was NOT scanned — this binary \
             was built without the `git` feature. Reinstall with `git` (the default \
             build) or pass `--no-git-history` to stop discovering repos you cannot scan.",
            style::warn("WARN", &palette),
            repo.display()
        );
        out.record_skipped_chunk();
        Ok(())
    }
}

fn handle_streaming_source_event(
    event: StreamingSourceEvent,
    bytes_scanned: &AtomicU64,
    out: &mut FindingSink,
) {
    match event {
        StreamingSourceEvent::UnreadableChunk => out.record_skipped_chunk(),
        StreamingSourceEvent::Matches { chunk_len, matches } => {
            bytes_scanned.fetch_add(chunk_len as u64, Ordering::Relaxed);
            out.absorb(matches);
        }
    }
}
