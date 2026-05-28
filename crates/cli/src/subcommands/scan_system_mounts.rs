use anyhow::{Context, Result};
use keyhog_scanner::CompiledScanner;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::args::ScanSystemArgs;

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
pub(crate) fn enumerate_mounts(_include_network: bool) -> Result<Vec<PathBuf>> {
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
pub(crate) fn discover_git_repos(root: &Path, out: &mut Vec<PathBuf>, _space_cap: u64) {
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

pub(crate) fn scan_mount(
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

pub(crate) fn scan_git_history(
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

pub(crate) fn format_bytes(n: u64) -> String {
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
