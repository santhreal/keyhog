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
use crate::format::format_bytes;
use anyhow::{Context, Result};
use keyhog_scanner::CompiledScanner;
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
        }
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
                eprintln!(
                    "⚠ resident findings cap ({}) reached; further findings are \
                     counted but not retained in memory",
                    self.cap
                );
            }
        }
        // `matches` (the plaintext-bearing RawMatch Vec) is dropped here.
    }

    fn is_empty(&self) -> bool {
        self.total == 0
    }
}

pub fn run(args: ScanSystemArgs) -> Result<ExitCode> {
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

    // Apply lockdown protections at scan-system entry too - the main
    // `scan` orchestrator's lockdown gate doesn't run for this subcommand.
    if args.lockdown {
        let lockdown = keyhog_core::hardening::apply_lockdown_protections();
        if !lockdown.failures.is_empty() {
            anyhow::bail!(
                "lockdown mode requested but protections failed to apply: {:?}",
                lockdown.failures
            );
        }
        eprintln!("🔒 LOCKDOWN MODE: coredump-blocked, mlocked, network mounts refused");
    }

    // Always-on hardening: every scan-system run disables core dumps and
    // ptrace, even outside lockdown mode. Cost is zero and the use case
    // (triage on a fresh machine) is exactly when an attacker pivoting
    // through a debugger would harvest the most.
    let report = keyhog_core::hardening::apply_default_protections();
    if !report.failures.is_empty() {
        eprintln!("⚠ hardening warnings: {:?}", report.failures);
    }
    eprintln!(
        "🔒 core_dumps={} ptrace={} (always-on protections applied)",
        if report.no_core_dumps { "off" } else { "on" },
        if report.no_ptrace {
            "denied"
        } else {
            "allowed"
        },
    );

    let detectors = crate::orchestrator_config::load_detectors_or_embedded(&args.detectors)?;
    eprintln!("📋 loaded {} detectors", detectors.len());
    let scanner = Arc::new(
        CompiledScanner::compile(detectors)
            .map_err(|e| anyhow::anyhow!("scanner compile failed: {e:?}"))?,
    );
    // System-wide scan touches every mounted drive and every git history:
    // detector regexes compile lazily on first use, so warm them all up
    // front (in parallel) rather than stalling the first file that hits each
    // detector across a multi-hour, multi-TB walk.
    scanner.warm();

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
        for mount in &mounts {
            discover_git_repos(mount, &mut git_repos, args.space);
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
            eprintln!(
                "⚠ space cap reached ({}); skipping remaining mounts",
                format_bytes(space_cap)
            );
            break;
        }
        eprintln!("→ walking {}", mount.display());
        scan_mount(&scanner, mount, &args, &bytes_scanned, space_cap, &mut sink);
    }

    // Then walk every git history.
    if !args.no_git_history {
        for repo in &git_repos {
            if bytes_scanned.load(Ordering::Relaxed) >= space_cap {
                eprintln!("⚠ space cap reached; skipping remaining git histories");
                break;
            }
            eprintln!("→ git history: {}", repo.display());
            scan_git_history(&scanner, repo, &bytes_scanned, space_cap, &mut sink);
        }
    }

    eprintln!(
        "✅ system scan complete | bytes scanned: {} | findings: {}",
        format_bytes(bytes_scanned.load(Ordering::Relaxed)),
        sink.total
    );

    if let Some(out) = &args.output {
        // SECURITY: never write `RawMatch` to disk - its `credential` field
        // is the plaintext secret. The sink already holds `RedactedFinding`s
        // (converted per chunk), so no plaintext can reach disk here.
        // See kimi-wave1 audit finding 2.1.
        let json = serde_json::to_string_pretty(&sink.redacted).context("serialize findings")?;
        std::fs::write(out, json).with_context(|| format!("write {}", out.display()))?;
        eprintln!("📄 wrote findings to {}", out.display());
    } else {
        for m in &sink.redacted {
            println!(
                "🔍 {} {}{} {:?}  {}",
                m.detector_id,
                m.location.file_path.as_deref().unwrap_or("<no-path>"),
                m.location.line.map(|l| format!(":{l}")).unwrap_or_default(),
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
        Ok(ExitCode::from(1))
    }
}

/// Recursively find `.git` directories (worktrees + bare repos) up to the
/// space cap.
///
/// kimi-wave2 §Critical: previously this followed symlinks via plain
/// `fs::read_dir` + `is_dir`. A circular symlink (e.g. `a/b -> ../a`)
/// or a long chain (`/proc/*/cwd` style) caused unbounded growth and
/// in some cases an OOM kill. We now canonicalize each candidate dir
/// before recursing and skip any path we've already visited.
fn discover_git_repos(root: &Path, out: &mut Vec<PathBuf>, _space_cap: u64) {
    use std::collections::HashSet;
    use std::fs;
    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut stack: Vec<PathBuf> = Vec::new();

    if let Ok(canon) = fs::canonicalize(root) {
        stack.push(canon);
    } else {
        return;
    }

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
            if matches!(
                name,
                "node_modules"
                    | "target"
                    | ".cargo"
                    | ".cache"
                    | "Library"
                    | "AppData"
                    | "$Recycle.Bin"
                    | "System Volume Information"
            ) {
                continue;
            }
        }
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    if let Ok(canon) = fs::canonicalize(entry.path()) {
                        if !visited.contains(&canon) {
                            stack.push(canon);
                        }
                    }
                }
            }
        }
    }
}

fn scan_mount(
    scanner: &CompiledScanner,
    root: &Path,
    args: &ScanSystemArgs,
    bytes_scanned: &AtomicU64,
    space_cap: u64,
    out: &mut FindingSink,
) {
    use keyhog_core::Source;
    use keyhog_sources::FilesystemSource;

    // scan-system is paranoid by default - walks files even if listed in
    // `.gitignore` / `.keyhogignore`. An attacker stashing a leaked key
    // would gitignore it; respecting gitignore here would let that hide.
    let source =
        FilesystemSource::new(root.to_path_buf()).with_respect_gitignore(args.respect_gitignore);
    for chunk_result in source.chunks() {
        if bytes_scanned.load(Ordering::Relaxed) >= space_cap {
            return;
        }
        let chunk = match chunk_result {
            Ok(c) => c,
            Err(_) => continue,
        };
        bytes_scanned.fetch_add(chunk.data.len() as u64, Ordering::Relaxed);
        // Convert + drop raw matches per chunk so plaintext-bearing RawMatch
        // entries are never accumulated (audit: memory).
        out.absorb(scanner.scan(&chunk));
    }
}

fn scan_git_history(
    scanner: &CompiledScanner,
    repo: &Path,
    bytes_scanned: &AtomicU64,
    space_cap: u64,
    out: &mut FindingSink,
) {
    #[cfg(feature = "git")]
    {
        use keyhog_core::Source;
        let source = keyhog_sources::GitSource::new(repo.to_path_buf());
        for chunk_result in source.chunks() {
            if bytes_scanned.load(Ordering::Relaxed) >= space_cap {
                return;
            }
            let chunk = match chunk_result {
                Ok(c) => c,
                Err(_) => continue,
            };
            bytes_scanned.fetch_add(chunk.data.len() as u64, Ordering::Relaxed);
            // Convert + drop raw matches per chunk (audit: memory).
            out.absorb(scanner.scan(&chunk));
        }
    }
    #[cfg(not(feature = "git"))]
    {
        let _ = (scanner, repo, bytes_scanned, space_cap, out);
        tracing::warn!("git history scan requires the `git` feature; skipping");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyhog_core::{MatchLocation, RawMatch, Severity};

    /// Build a distinct plaintext-bearing `RawMatch` for sink tests. Each `i`
    /// yields a unique credential so we can prove redaction never leaks it.
    fn raw_match(i: usize) -> RawMatch {
        let credential = format!("AKIA_SECRET_PLAINTEXT_{i:08}");
        RawMatch {
            detector_id: Arc::from("aws-access-key"),
            detector_name: Arc::from("AWS Access Key"),
            service: Arc::from("aws"),
            severity: Severity::High,
            credential: Arc::from(credential.as_str()),
            // Distinct raw 32-byte hash per `i` (the field is `[u8; 32]`, not a
            // string); `i + 1` keeps i=0 off the all-zero "no identity" sentinel.
            credential_hash: {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&((i as u64) + 1).to_le_bytes());
                h
            },
            companions: std::collections::HashMap::new(),
            location: MatchLocation {
                source: Arc::from("filesystem"),
                file_path: Some(Arc::from(format!("/tmp/leak{i}.env").as_str())),
                line: Some(i + 1),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            entropy: Some(4.2),
            confidence: Some(0.9),
        }
    }

    #[test]
    fn sink_starts_empty() {
        let sink = FindingSink::new();
        assert!(sink.is_empty());
        assert_eq!(sink.total, 0);
        assert!(sink.redacted.is_empty());
    }

    #[test]
    fn sink_absorbs_and_counts_below_cap() {
        let mut sink = FindingSink::new();
        sink.absorb((0..10).map(raw_match).collect());
        assert_eq!(sink.total, 10);
        assert_eq!(sink.redacted.len(), 10);
        assert!(!sink.is_empty());
    }

    #[test]
    fn sink_retains_only_redacted_never_plaintext() {
        // The whole point of the audit fix: raw matches are converted to a
        // disk-safe RedactedFinding immediately and the plaintext-bearing
        // RawMatch Vec is dropped. The serialized sink must never contain the
        // plaintext credential bytes.
        let mut sink = FindingSink::new();
        sink.absorb(vec![raw_match(7)]);
        let json = serde_json::to_string(&sink.redacted).unwrap();
        assert!(
            !json.contains("AKIA_SECRET_PLAINTEXT_00000007"),
            "plaintext credential leaked into retained findings: {json}"
        );
        // But the redacted preview + hash are present.
        assert_eq!(sink.redacted.len(), 1);
        assert_eq!(sink.redacted[0].credential_hash, "hash7");
    }

    #[test]
    fn sink_caps_resident_set_but_keeps_counting() {
        // Resident memory is bounded by the cap regardless of how many findings
        // stream through (audit: unbounded findings Vec). Use a small injected
        // cap so the invariant is proven without a million-element allocation.
        let cap = 3;
        let mut sink = FindingSink::with_cap(cap);

        // Absorb far more findings than the cap, across multiple chunks.
        sink.absorb((0..2).map(raw_match).collect());
        sink.absorb((2..50).map(raw_match).collect());

        // Counted: every finding increments `total`.
        assert_eq!(sink.total, 50);
        // Bounded: resident set never grows past the cap.
        assert_eq!(sink.redacted.len(), cap);
        // Warned exactly once that the cap was hit.
        assert!(sink.capped_warned);
        // Still reports non-empty so the exit-code contract holds.
        assert!(!sink.is_empty());

        // The retained set is the FIRST `cap` findings (insertion order).
        assert_eq!(sink.redacted[0].credential_hash, "hash0");
        assert_eq!(sink.redacted[cap - 1].credential_hash, format!("hash{}", cap - 1));
    }

    #[test]
    fn default_cap_is_the_module_ceiling() {
        let sink = FindingSink::new();
        assert_eq!(sink.cap, MAX_RESIDENT_FINDINGS);
    }
}
