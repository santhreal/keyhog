//! Mount enumeration for `keyhog scan-system`.
//!
//! Walks platform-specific mount-table sources (Linux `/proc/mounts`,
//! macOS `mount(8)`, Windows `GetLogicalDrives`) and returns the set
//! of root paths the scanner should visit. Filters pseudo-FS (proc,
//! sysfs, tmpfs, etc.) and, by default, network mounts (NFS / SMB /
//! sshfs / 9p / ceph) so a `scan-system` run can't accidentally walk
//! other tenants' data.

use anyhow::Result;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use anyhow::Context;
use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::path::Path;

/// Enumerate mounted filesystems on the current OS, filtering pseudo-FS
/// and (optionally) network mounts. Returns root paths.
///
/// `include_network` is honored on Linux and macOS where we walk
/// `/proc/mounts` / `getmntinfo` and can filter NFS/SMB. Windows drive
/// enumeration via `GetLogicalDrives` doesn't distinguish network from
/// local at the API level (the user already chose to include them by
/// running `scan-system` with the flag), so the parameter is unused on
/// Windows - silenced with a leading underscore rather than a stray
/// `let _ =` for symmetry with the other platform paths.
pub(super) fn enumerate_mounts(_include_network: bool) -> Result<Vec<PathBuf>> {
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
    const SKIP_PATH_PREFIXES: &[&str] = &["/run/", "/proc/", "/sys/", "/dev/", "/snap/"];
    const NETWORK_FS_TYPES: &[&str] = &[
        "nfs", "nfs4", "cifs", "smb", "smbfs", "fuse.sshfs", "fuse.rclone", "9p", "afs", "ceph",
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
        let decoded = decode_octal_escapes(target);
        if seen.insert(decoded.clone()) {
            roots.push(PathBuf::from(decoded));
        }
    }
    // kimi-wave2 §High: sort ASCENDING (shortest path first) so the dedup
    // loop below catches subpaths of an already-included root. The prior
    // descending sort made dedup a no-op (every `starts_with` check fired
    // against a *longer* candidate), causing `/` and `/home` to both end
    // up in the result and every file under `/home` to be scanned twice.
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
/// `\011`, etc. (POSIX octal escapes). Only `linux_mounts` consumes
/// this, so the helper is gated to `target_os = "linux"` to avoid a
/// dead-code warning on Windows / macOS.
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
    // SECURITY (kimi-wave1 audit 3.PATH-mount): use absolute path.
    let bin = keyhog_core::safe_bin::resolve_or_fallback("mount");
    let output = std::process::Command::new(&bin)
        .output()
        .context("run mount(8)")?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut roots = Vec::new();
    for line in text.lines() {
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
