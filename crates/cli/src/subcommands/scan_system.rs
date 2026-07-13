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
use crate::exit_codes::{EXIT_FINDINGS, EXIT_SOURCE_FAILED};
use crate::format::format_bytes;
use crate::orchestrator::{setup_default_scan_runtime, DefaultScanRuntime, StreamingSourceEvent};
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
    /// Source/discovery items that could not be yielded (corrupt git object,
    /// perm-denied `.git`, non-UTF-8 / unreadable file mid-walk, or unreadable
    /// git-discovery subtree). Law 10: dropped scope is unscanned bytes, a
    /// recall loss, so it is COUNTED and surfaced in the final summary, never
    /// silently `continue`d past. A non-zero count means the "complete" scan did
    /// not cover everything.
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

    /// Record that source/discovery scope could not be read and was dropped
    /// from the scan. The count is surfaced in the final summary so the recall
    /// loss is visible (Law 10) instead of a silent `Err(_) => continue`.
    fn record_skipped_chunk(&mut self) {
        self.record_skipped_chunks(1);
    }

    fn record_skipped_chunks(&mut self, count: u64) {
        self.skipped_chunks = self.skipped_chunks.saturating_add(count);
    }

    /// Number of source/discovery items dropped due to read errors (unscanned
    /// bytes or subtrees).
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

    pub(crate) fn chunk_fits_space_cap(
        bytes_scanned: u64,
        chunk_len: usize,
        space_cap: u64,
    ) -> bool {
        super::chunk_fits_space_cap(bytes_scanned, chunk_len, space_cap)
    }

    pub(crate) fn parse_macos_mount_table_for_test(
        text: &str,
        include_network: bool,
    ) -> Result<Vec<std::path::PathBuf>, toml::de::Error> {
        super::mounts::testing::parse_macos_mount_table_for_test(text, include_network)
    }

    pub(crate) fn windows_drive_filter_decisions_for_test(
    ) -> Result<(bool, bool, bool, bool), toml::de::Error> {
        super::mounts::testing::windows_drive_filter_decisions_for_test()
    }

    pub(crate) fn windows_drive_skip_prefix_decisions_for_test() -> (bool, bool) {
        super::mounts::testing::windows_drive_skip_prefix_decisions_for_test()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn decoded_mount_target_if_included_for_test(
        target: &str,
        skip_path_prefixes: Vec<String>,
    ) -> anyhow::Result<Option<String>> {
        super::mounts::testing::decoded_mount_target_if_included_for_test(
            target,
            skip_path_prefixes,
        )
    }

    pub(crate) fn git_repos_for_test(
        root: &std::path::Path,
    ) -> anyhow::Result<Vec<std::path::PathBuf>> {
        let skip_dirs = crate::skip_dirs::SkipDirPolicy::load()?;
        let mut repos = Vec::new();
        let gaps = super::discover_git_repos(root, &mut repos, &skip_dirs);
        if gaps != 0 {
            anyhow::bail!("git discovery reported {gaps} coverage gap(s)");
        }
        repos.sort();
        Ok(repos)
    }

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
    if args.space == 0 {
        anyhow::bail!("scan-system --space must be greater than zero bytes");
    }

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

    // `None` filter root: scan-system runs paranoid and deliberately ignores the
    // local `.keyhogignore` allowlist (an attacker would allowlist their leak),
    // so no post-scan allowlist filter is installed. It STILL benefits from the
    // resolved `.keyhog.toml` detector/scanner config applied inside setup.
    let scan_runtime = setup_default_scan_runtime(
        &args.detectors,
        args.detectors_cli_explicit,
        args.cache_dir.clone(),
        args.threads,
        None,
        "keyhog scan-system",
        true,
        None,
    )?;
    let palette = style::for_stderr();
    eprintln!(
        "{} loaded {} detectors",
        style::info("INFO", &palette),
        scan_runtime.detector_count()
    );
    eprintln!(
        "{} {} workers",
        style::info("INFO", &palette),
        scan_runtime.worker_threads()
    );

    let mounts = enumerate_mounts(args.include_network)?;
    eprintln!("💾 will scan {} mount(s):", mounts.len());
    for m in &mounts {
        eprintln!("   {}", m.display());
    }

    // Discover git repos under each mount BEFORE walking files, so we can
    // include their .git directories explicitly even when they're hidden
    // by .gitignore-style filters.
    let mut git_repos: Vec<PathBuf> = Vec::new();
    let mut git_discovery_gaps = 0_u64;
    if !args.no_git_history {
        let skip_dirs = crate::skip_dirs::SkipDirPolicy::load()?;
        for mount in &mounts {
            git_discovery_gaps += discover_git_repos(mount, &mut git_repos, &skip_dirs);
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
    sink.record_skipped_chunks(git_discovery_gaps);

    // Walk each mount with the existing walker but with a budget callback
    // that aborts when --space is hit.
    for mount in &mounts {
        if bytes_scanned.load(Ordering::Relaxed) >= space_cap {
            record_space_cap_gap(&mut sink, space_cap, "skipping remaining mounts");
            break;
        }
        let palette = style::for_stderr();
        eprintln!(
            "{} walking {}",
            style::info("INFO", &palette),
            mount.display()
        );
        let stopped_by_space_cap = scan_mount(
            &scan_runtime,
            mount,
            &args,
            &bytes_scanned,
            space_cap,
            &mut sink,
        )?;
        if stopped_by_space_cap || bytes_scanned.load(Ordering::Relaxed) >= space_cap {
            record_space_cap_gap(&mut sink, space_cap, "stopping filesystem walk");
            break;
        }
    }

    // Then walk every git history.
    if !args.no_git_history && bytes_scanned.load(Ordering::Relaxed) < space_cap {
        for repo in &git_repos {
            if bytes_scanned.load(Ordering::Relaxed) >= space_cap {
                record_space_cap_gap(&mut sink, space_cap, "skipping remaining git histories");
                break;
            }
            let palette = style::for_stderr();
            eprintln!(
                "{} git history: {}",
                style::info("INFO", &palette),
                repo.display()
            );
            let stopped_by_space_cap =
                scan_git_history(&scan_runtime, repo, &bytes_scanned, space_cap, &mut sink)?;
            if stopped_by_space_cap || bytes_scanned.load(Ordering::Relaxed) >= space_cap {
                record_space_cap_gap(&mut sink, space_cap, "stopping git history walk");
                break;
            }
        }
    }

    let palette = style::for_stderr();
    if sink.skipped_chunks() > 0 {
        eprintln!(
            "{} system scan partial | bytes scanned: {} | findings: {}",
            style::warn("WARN", &palette),
            format_bytes(bytes_scanned.load(Ordering::Relaxed)),
            sink.total
        );
    } else {
        eprintln!(
            "{} system scan complete | bytes scanned: {} | findings: {}",
            style::pass("PASS", &palette),
            format_bytes(bytes_scanned.load(Ordering::Relaxed)),
            sink.total
        );
    }
    // Law 10: if any chunk was unreadable, the "complete" above covered LESS than
    // the whole tree. Say so loudly, a partial audit that looks clean is worse
    // than no audit.
    if sink.skipped_chunks() > 0 {
        let palette = style::for_stderr();
        eprintln!(
            "{} {} source/discovery coverage gap(s) were UNREADABLE or skipped \
             before scanning (space cap reached, git discovery errors, corrupt \
             git objects, permission-denied paths, or non-text files). This scan \
             did NOT cover everything; rerun affected paths with elevated \
             permissions or raise --space to close the gap.",
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
            let file_path = match m.location.file_path.as_deref() {
                Some(file_path) => file_path,
                None => "<no-path>",
            };
            crate::style::print_diagnostic_finding(
                "FINDING",
                &m.detector_id,
                file_path,
                m.location.line,
                m.severity,
                m.confidence,
                &m.credential_redacted,
            )
            .with_context(|| format!("write scan-system finding for {file_path}"))?;
        }
    }

    // Exit-code contract (kimi CLI-001): scan-system has to surface
    // "found credentials" via a non-zero exit code or CI pipelines
    // can't gate on it. Match the rest of the CLI: 0 = clean,
    // 1 = findings above floor, 2 = error (handled by caller's
    // Result<_> path).
    if !sink.is_empty() {
        Ok(ExitCode::from(EXIT_FINDINGS))
    } else if sink.skipped_chunks() > 0 {
        Ok(ExitCode::from(EXIT_SOURCE_FAILED))
    } else {
        Ok(ExitCode::SUCCESS)
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
) -> u64 {
    use std::collections::HashSet;
    use std::fs;
    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut stack: Vec<PathBuf> = Vec::new();
    let mut discovery_gaps = 0_u64;

    let canon = match fs::canonicalize(root) {
        Ok(canon) => canon,
        Err(error) => {
            record_git_discovery_gap(&mut discovery_gaps, root, error, "root canonicalization");
            return discovery_gaps;
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
                            record_git_discovery_gap(
                                &mut discovery_gaps,
                                &dir,
                                error,
                                "directory entry read",
                            );
                            continue;
                        }
                    };
                    let file_type = match entry.file_type() {
                        Ok(file_type) => file_type,
                        Err(error) => {
                            record_git_discovery_gap(
                                &mut discovery_gaps,
                                &entry.path(),
                                error,
                                "directory entry type read",
                            );
                            continue;
                        }
                    };
                    if file_type.is_dir() {
                        if entry.file_name().to_str().is_some_and(|name| {
                            name.eq_ignore_ascii_case(".git")
                                || skip_dirs.is_git_discovery_component(name)
                        }) {
                            continue;
                        }
                        match fs::canonicalize(entry.path()) {
                            Ok(canon) => {
                                if !visited.contains(&canon) {
                                    stack.push(canon);
                                }
                            }
                            Err(error) => {
                                record_git_discovery_gap(
                                    &mut discovery_gaps,
                                    &entry.path(),
                                    error,
                                    "subtree canonicalization",
                                );
                            }
                        }
                    }
                }
            }
            Err(error) => {
                record_git_discovery_gap(&mut discovery_gaps, &dir, error, "directory read");
            }
        }
    }
    discovery_gaps
}

fn record_git_discovery_gap(
    discovery_gaps: &mut u64,
    path: &Path,
    error: impl std::fmt::Display,
    operation: &'static str,
) {
    *discovery_gaps = discovery_gaps.saturating_add(1);
    let palette = style::for_stderr();
    eprintln!(
        "{} git repository discovery skipped {} for {}: {}. This scan did NOT prove coverage for that subtree.",
        style::warn("WARN", &palette),
        operation,
        path.display(),
        error
    );
    tracing::warn!(
        path = %path.display(),
        %operation,
        %error,
        "git repository discovery skipped scope; scan coverage gap"
    );
}

fn record_space_cap_gap(out: &mut FindingSink, space_cap: u64, skipped_scope: &'static str) {
    out.record_skipped_chunk();
    let palette = style::for_stderr();
    eprintln!(
        "{} space cap reached ({}); {}. This scan did NOT cover everything.",
        style::warn("WARN", &palette),
        format_bytes(space_cap),
        skipped_scope
    );
    tracing::warn!(
        space_cap,
        skipped_scope,
        "space cap stopped scan before all requested scope was scanned"
    );
}

fn chunk_fits_space_cap(bytes_scanned: u64, chunk_len: usize, space_cap: u64) -> bool {
    bytes_scanned < space_cap
        && bytes_scanned
            .checked_add(chunk_len as u64)
            .is_some_and(|total| total <= space_cap)
}

fn scan_mount(
    scan_runtime: &DefaultScanRuntime,
    root: &Path,
    args: &ScanSystemArgs,
    bytes_scanned: &AtomicU64,
    space_cap: u64,
    out: &mut FindingSink,
) -> Result<bool> {
    use keyhog_sources::FilesystemSource;

    // scan-system is paranoid by default - walks files even if listed in
    // `.gitignore` / `.keyhogignore`. An attacker stashing a leaked key
    // would gitignore it; respecting gitignore here would let that hide.
    let source =
        FilesystemSource::new(root.to_path_buf()).with_respect_gitignore(args.respect_gitignore);
    let mut stopped_by_space_cap = false;
    crate::orchestrator::scan_streaming_source(
        scan_runtime,
        &source,
        "filesystem",
        root,
        |chunk_len| {
            let fits =
                chunk_fits_space_cap(bytes_scanned.load(Ordering::Relaxed), chunk_len, space_cap);
            if !fits {
                stopped_by_space_cap = true;
            }
            !fits
        },
        |event| {
            handle_streaming_source_event(event, bytes_scanned, out);
            Ok(())
        },
    )?;
    Ok(stopped_by_space_cap)
}

fn scan_git_history(
    scan_runtime: &DefaultScanRuntime,
    repo: &Path,
    bytes_scanned: &AtomicU64,
    space_cap: u64,
    out: &mut FindingSink,
) -> Result<bool> {
    #[cfg(feature = "git")]
    {
        let source = keyhog_sources::GitSource::new(repo.to_path_buf()).with_default_excludes(true);
        let mut stopped_by_space_cap = false;
        crate::orchestrator::scan_streaming_source(
            scan_runtime,
            &source,
            "git-history",
            repo,
            |chunk_len| {
                let fits = chunk_fits_space_cap(
                    bytes_scanned.load(Ordering::Relaxed),
                    chunk_len,
                    space_cap,
                );
                if !fits {
                    stopped_by_space_cap = true;
                }
                !fits
            },
            |event| {
                handle_streaming_source_event(event, bytes_scanned, out);
                Ok(())
            },
        )?;
        Ok(stopped_by_space_cap)
    }
    #[cfg(not(feature = "git"))]
    {
        let _ = (scan_runtime, bytes_scanned, space_cap);
        // LAW10: unused-binding marker; no runtime effect, not a fallback.
        // Law 10: this binary was built WITHOUT the `git` feature, so the git
        // history of a discovered repo cannot be scanned, those commits are
        // unscanned bytes (a recall loss), not "nothing to do". The banner above
        // announced "git history: yes" and "discovered N git repo(s)", so a
        // trace-only skip would let a partial audit look complete.
        // Surface it LOUDLY on stderr AND count it as a skipped chunk so the
        // final summary's "did NOT cover everything" warning fires.
        let palette = style::for_stderr();
        eprintln!(
            "{} keyhog scan-system: git history of {} was NOT scanned: this binary \
             was built without the `git` feature. Reinstall with `git` (the default \
             build) or pass `--no-git-history` to stop discovering repos you cannot scan.",
            style::warn("WARN", &palette),
            repo.display()
        );
        out.record_skipped_chunk();
        Ok(false)
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
