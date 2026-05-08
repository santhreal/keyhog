//! `keyhog scan-system` — recursive system-wide credential audit.
//!
//! Walks every mounted drive (skipping pseudo-FS and, by default, network
//! mounts), discovers every `.git` repository on the way, and runs the
//! same scan + git-history pipeline that `keyhog scan --git-history`
//! uses on each. Honors a hard `--space <N>` ceiling on total bytes
//! scanned so it can't accidentally fill a CI runner.
//!
//! Use case (per CEO directive): triage a fresh machine for credentials
//! before EnvSeal-sealing them. Should be paranoid by default — does NOT
//! honor `.gitignore` unless `--respect-gitignore` is passed, because an
//! attacker stashing a leaked key would `.gitignore` it.

use crate::args::ScanSystemArgs;
use anyhow::{Context, Result};
use keyhog_scanner::CompiledScanner;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub fn run(args: ScanSystemArgs) -> Result<()> {
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

    // Apply lockdown protections at scan-system entry too — the main
    // `scan` orchestrator's lockdown gate doesn't run for this subcommand.
    if args.lockdown {
        let lockdown = keyhog_core::hardening::apply_lockdown_protections();
        if !lockdown.failures.is_empty() {
            anyhow::bail!(
                "lockdown mode requested but protections failed to apply: {:?}",
                lockdown.failures
            );
        }
        eprintln!("🔒 LOCKDOWN MODE — coredump-blocked, mlocked, network mounts refused");
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

    let detectors = load_detectors(&args.detectors)?;
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
        // SECURITY: never write `RawMatch` to disk — its `credential` field
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

    Ok(())
}

/// Enumerate mounted filesystems on the current OS, filtering pseudo-FS
/// and (optionally) network mounts. Returns root paths.
///
/// `include_network` is honored on Linux and macOS where we walk
/// `/proc/mounts` / `getmntinfo` and can filter NFS/SMB. Windows drive
/// enumeration via `GetLogicalDrives` doesn't distinguish network from
/// local at the API level (the user already chose to include them by
/// running `scan-system` with the flag), so the parameter is unused on
/// Windows — silenced with a leading underscore rather than a stray
/// `let _ =` for symmetry with the other platform paths.
fn enumerate_mounts(_include_network: bool) -> Result<Vec<PathBuf>> {
    #[cfg(target_os = "linux")]
    {
        linux_mounts(_include_network)
    }
    #[cfg(target_os = "macos")]
    {
        macos_mounts(_include_network)
    }
    #[cfg(target_os = "windows")]
    {
        windows_drives()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        // Fallback: just the current working directory.
        Ok(vec![std::env::current_dir()?])
    }
}

#[cfg(target_os = "linux")]
fn linux_mounts(include_network: bool) -> Result<Vec<PathBuf>> {
    const SKIP_FS_TYPES: &[&str] = &[
        "proc",
        "sysfs",
        "tmpfs",
        "devtmpfs",
        "devpts",
        "cgroup",
        "cgroup2",
        "pstore",
        "bpf",
        "tracefs",
        "debugfs",
        "securityfs",
        "configfs",
        "fusectl",
        "binfmt_misc",
        "rpc_pipefs",
        "ramfs",
        "autofs",
        "mqueue",
        "hugetlbfs",
        "fuse.gvfsd-fuse",
        "overlay",
        "squashfs",
        "nsfs",
        "fuse.portal",
        "fuse.snapfuse",
        "fuse.gvfs-fuse-daemon",
        "fuse.fusectl",
        "rootfs",
    ];
    // Per-path skips for synthetic mount points the FS-type filter doesn't
    // cover (e.g. /run/user/* doc-FUSE bind mounts that report as `fuse`
    // but contain no real files).
    const SKIP_PATH_PREFIXES: &[&str] = &["/run/", "/proc/", "/sys/", "/dev/", "/snap/"];
    const NETWORK_FS_TYPES: &[&str] = &[
        "nfs",
        "nfs4",
        "cifs",
        "smb",
        "smbfs",
        "fuse.sshfs",
        "fuse.rclone",
        "9p",
        "afs",
        "ceph",
    ];

    let mounts_text = std::fs::read_to_string("/proc/mounts").context("read /proc/mounts")?;
    let mut roots = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in mounts_text.lines() {
        let mut fields = line.split_whitespace();
        let _device = fields.next();
        let target = match fields.next() {
            Some(t) => t,
            None => continue,
        };
        let fstype = fields.next().unwrap_or("");
        if SKIP_FS_TYPES.contains(&fstype) {
            continue;
        }
        if !include_network && NETWORK_FS_TYPES.contains(&fstype) {
            continue;
        }
        if SKIP_PATH_PREFIXES.iter().any(|p| target.starts_with(p)) {
            continue;
        }
        // Decode octal escapes in the target path (kernel emits these for
        // spaces as `\040`, etc).
        let decoded = decode_octal_escapes(target);
        if seen.insert(decoded.clone()) {
            roots.push(PathBuf::from(decoded));
        }
    }
    // kimi-wave2 §High: sort ASCENDING (shortest path first). Previous
    // descending sort meant `deduped` only contained paths >= current
    // length, so `r.starts_with(d)` was always false — the dedup was a
    // no-op and `/` and `/home` would both end up in the result, causing
    // every file under `/home` to be scanned twice. With ascending
    // sort, `/` lands first; subsequent paths that start with `/` (i.e.
    // every absolute path) are detected as already covered and skipped.
    roots.sort_by_key(|p| p.as_os_str().len());
    let mut deduped: Vec<PathBuf> = Vec::new();
    for r in roots {
        let already_covered = deduped.iter().any(|d| r.starts_with(d) && r != *d);
        if !already_covered {
            deduped.push(r);
        }
    }
    Ok(deduped)
}

/// Linux `/proc/mounts` emits spaces and special characters as `\040`,
/// `\011`, etc. — POSIX octal escapes. Only the `linux_mounts` parser
/// consumes this, so gate the helper to `target_os = "linux"` to avoid
/// a dead-code warning on Windows / macOS where the parser isn't built.
#[cfg(target_os = "linux")]
fn decode_octal_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let mut octal = String::with_capacity(3);
            for _ in 0..3 {
                if let Some(&d) = chars.peek() {
                    if d.is_ascii_digit() {
                        octal.push(d);
                        chars.next();
                    }
                }
            }
            if octal.len() == 3 {
                if let Ok(byte) = u8::from_str_radix(&octal, 8) {
                    out.push(byte as char);
                    continue;
                }
            }
            out.push('\\');
            out.push_str(&octal);
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(target_os = "macos")]
fn macos_mounts(include_network: bool) -> Result<Vec<PathBuf>> {
    // SECURITY: kimi-wave1 audit finding 3.PATH-mount. Use absolute path.
    let bin = keyhog_core::safe_bin::resolve_or_fallback("mount");
    let output = std::process::Command::new(&bin)
        .output()
        .context("run mount(8)")?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut roots = Vec::new();
    for line in text.lines() {
        // mount output: "/dev/disk1s1 on / (apfs, ...)"
        if let Some(on_idx) = line.find(" on ") {
            let rest = &line[on_idx + 4..];
            if let Some(paren_idx) = rest.find(" (") {
                let path = &rest[..paren_idx];
                let fs_info = &rest[paren_idx + 2..];
                let fstype = fs_info.split(',').next().unwrap_or("").trim();
                if matches!(fstype, "devfs" | "autofs" | "tmpfs") {
                    continue;
                }
                if !include_network && matches!(fstype, "nfs" | "smbfs" | "afpfs") {
                    continue;
                }
                roots.push(PathBuf::from(path));
            }
        }
    }
    Ok(roots)
}

#[cfg(target_os = "windows")]
fn windows_drives() -> Result<Vec<PathBuf>> {
    let mut drives = Vec::new();
    for letter in b'A'..=b'Z' {
        let root = format!("{}:\\", letter as char);
        if Path::new(&root).exists() {
            drives.push(PathBuf::from(root));
        }
    }
    Ok(drives)
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

    // scan-system is paranoid by default — walks files even if listed in
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

fn load_detectors(path: &Path) -> Result<Vec<keyhog_core::DetectorSpec>> {
    if path.exists() && path.is_dir() {
        let loaded = keyhog_core::load_detectors(path).context("load detectors")?;
        crate::orchestrator_config::require_non_empty_detectors(&loaded, path)?;
        return Ok(loaded);
    }
    let embedded = keyhog_core::embedded_detector_tomls();
    let mut out = Vec::with_capacity(embedded.len());
    for (name, body) in embedded {
        match toml::from_str::<keyhog_core::DetectorFile>(body) {
            Ok(f) => out.push(f.detector),
            Err(e) => tracing::warn!("embedded detector {name}: {e}"),
        }
    }
    crate::orchestrator_config::require_non_empty_detectors(&out, path)?;
    Ok(out)
}

fn format_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    const TIB: u64 = 1024 * 1024 * 1024 * 1024;
    if n >= TIB {
        format!("{:.2} TiB", n as f64 / TIB as f64)
    } else if n >= GIB {
        format!("{:.2} GiB", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.2} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.2} KiB", n as f64 / KIB as f64)
    } else {
        format!("{n} B")
    }
}
