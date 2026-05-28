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
    let mut all_findings: Vec<keyhog_core::RawMatch> = Vec::new();

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
        scan_mount(
            &scanner,
            mount,
            &args,
            &bytes_scanned,
            space_cap,
            &mut all_findings,
        );
    }

    // Then walk every git history.
    if !args.no_git_history {
        for repo in &git_repos {
            if bytes_scanned.load(Ordering::Relaxed) >= space_cap {
                eprintln!("⚠ space cap reached; skipping remaining git histories");
                break;
            }
            eprintln!("→ git history: {}", repo.display());
            scan_git_history(&scanner, repo, &bytes_scanned, space_cap, &mut all_findings);
        }
    }

    eprintln!(
        "✅ system scan complete | bytes scanned: {} | findings: {}",
        format_bytes(bytes_scanned.load(Ordering::Relaxed)),
        all_findings.len()
    );

    if let Some(out) = &args.output {
        // SECURITY: never write `RawMatch` to disk - its `credential` field
        // is the plaintext secret. Always convert to `RedactedFinding` first.
        // See kimi-wave1 audit finding 2.1.
        let redacted: Vec<keyhog_core::RedactedFinding> = all_findings
            .iter()
            .map(keyhog_core::RawMatch::to_redacted)
            .collect();
        let json = serde_json::to_string_pretty(&redacted).context("serialize findings")?;
        std::fs::write(out, json).with_context(|| format!("write {}", out.display()))?;
        eprintln!("📄 wrote findings to {}", out.display());
    } else {
        for m in &all_findings {
            println!(
                "🔍 {} {}{} {:?}  {}",
                m.detector_id,
                m.location.file_path.as_deref().unwrap_or("<no-path>"),
                m.location.line.map(|l| format!(":{l}")).unwrap_or_default(),
                m.severity,
                keyhog_core::redact(&m.credential)
            );
        }
    }

    // Exit-code contract (kimi CLI-001): scan-system has to surface
    // "found credentials" via a non-zero exit code or CI pipelines
    // can't gate on it. Match the rest of the CLI: 0 = clean,
    // 1 = findings above floor, 2 = error (handled by caller's
    // Result<_> path).
    if all_findings.is_empty() {
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
    out: &mut Vec<keyhog_core::RawMatch>,
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
        let matches = scanner.scan(&chunk);
        out.extend(matches);
    }
}

fn scan_git_history(
    scanner: &CompiledScanner,
    repo: &Path,
    bytes_scanned: &AtomicU64,
    space_cap: u64,
    out: &mut Vec<keyhog_core::RawMatch>,
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
            out.extend(scanner.scan(&chunk));
        }
    }
    #[cfg(not(feature = "git"))]
    {
        let _ = (scanner, repo, bytes_scanned, space_cap, out);
        tracing::warn!("git history scan requires the `git` feature; skipping");
    }
}
