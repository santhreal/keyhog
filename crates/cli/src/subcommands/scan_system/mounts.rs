//! Mount enumeration for `keyhog scan-system`.
//!
//! Walks platform-specific mount-table sources (Linux `/proc/mounts`,
//! macOS `mount(8)`, Windows `GetLogicalDrives`) and returns the set
//! of root paths the scanner should visit. Filters pseudo-FS (proc,
//! sysfs, tmpfs, etc.) and, by default, network mounts (NFS / SMB /
//! sshfs / 9p / ceph) so a `scan-system` run can't accidentally walk
//! other tenants' data.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use anyhow::Context;
use anyhow::Result;
#[cfg(target_os = "windows")]
use std::path::Path;
use std::path::PathBuf;

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

/// Scan-system mount filters loaded from Tier-B data.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Default, serde::Deserialize)]
struct MountFilters {
    #[serde(default)]
    skip_fs_types: Vec<String>,
    #[serde(default)]
    skip_path_prefixes: Vec<String>,
    #[serde(default)]
    network_fs_types: Vec<String>,
}

/// Compiled-in Tier-B baseline. Always applied.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const BUNDLED_MOUNT_FILTERS: &str = include_str!("../../../data/scan_system/mount_filters.toml");

/// Load scan-system mount filters: the embedded baseline UNIONED with an
/// optional `<config>/keyhog/mount_filters.toml`, so an operator can skip an
/// exotic filesystem or path without recompiling.
///
/// No silent fallback (Law 10): the baseline parse is surfaced as an error (a
/// failure means the embedded data is corrupt — a build bug, caught by the data
/// test), and a user file that EXISTS but is unreadable or unparseable is a hard
/// error. Only the ordinary "no user file present" case uses the baseline alone,
/// which is the intended default — not a degraded fallback.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn load_mount_filters() -> Result<MountFilters> {
    let mut filters: MountFilters = toml::from_str(BUNDLED_MOUNT_FILTERS)
        .context("parse bundled scan_system/mount_filters.toml (build bug)")?;
    let Some(user_path) = dirs::config_dir().map(|d| d.join("keyhog/mount_filters.toml")) else {
        return Ok(filters);
    };
    match std::fs::read_to_string(&user_path) {
        Ok(text) => {
            let user: MountFilters = toml::from_str(&text)
                .with_context(|| format!("parse mount filters {}", user_path.display()))?;
            filters.skip_fs_types.extend(user.skip_fs_types);
            filters.skip_path_prefixes.extend(user.skip_path_prefixes);
            filters.network_fs_types.extend(user.network_fs_types);
            Ok(filters)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(filters),
        Err(error) => Err(anyhow::Error::new(error))
            .with_context(|| format!("read mount filters {}", user_path.display())),
    }
}

#[cfg(target_os = "linux")]
fn linux_mounts(include_network: bool) -> Result<Vec<PathBuf>> {
    // Tier-B data, not a hardcoded list: the shipped baseline plus any user
    // extension. A user file that exists but won't parse is a hard error here,
    // never a silent fall back to defaults (Law 10).
    let filters = load_mount_filters()?;
    let skip_fs_types: std::collections::HashSet<&str> =
        filters.skip_fs_types.iter().map(String::as_str).collect();
    let network_fs_types: std::collections::HashSet<&str> = filters
        .network_fs_types
        .iter()
        .map(String::as_str)
        .collect();

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
        let fstype = fields.next().unwrap_or(""); // LAW10: missing/non-string field => empty/placeholder; recall-safe
        if skip_fs_types.contains(fstype) {
            continue;
        }
        if !include_network && network_fs_types.contains(fstype) {
            continue;
        }
        let Some(decoded) = decoded_mount_target_if_included(target, &filters) else {
            continue;
        };
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

#[cfg(target_os = "linux")]
fn decoded_mount_target_if_included(target: &str, filters: &MountFilters) -> Option<String> {
    let decoded = decode_octal_escapes(target);
    if filters
        .skip_path_prefixes
        .iter()
        .any(|prefix| decoded.starts_with(prefix))
    {
        return None;
    }
    Some(decoded)
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{MountFilters, decoded_mount_target_if_included};

    #[test]
    fn skip_path_prefixes_match_decoded_mount_targets() {
        let filters = MountFilters {
            skip_path_prefixes: vec!["/mnt/my disk/".to_string()],
            ..MountFilters::default()
        };

        assert_eq!(
            decoded_mount_target_if_included("/mnt/my\\040disk/secrets", &filters),
            None,
            "Tier-B skip prefixes must match decoded /proc/mounts targets"
        );
        assert_eq!(
            decoded_mount_target_if_included("/mnt/other\\040disk/secrets", &filters).as_deref(),
            Some("/mnt/other disk/secrets")
        );
    }
}

#[cfg(target_os = "macos")]
fn macos_mounts(include_network: bool) -> Result<Vec<PathBuf>> {
    let filters = load_mount_filters()?;
    let skip_fs_types: std::collections::HashSet<&str> =
        filters.skip_fs_types.iter().map(String::as_str).collect();
    let network_fs_types: std::collections::HashSet<&str> = filters
        .network_fs_types
        .iter()
        .map(String::as_str)
        .collect();
    // SECURITY (kimi-wave1 audit 3.PATH-mount): use a trusted absolute path.
    // `scan-system` is an operator-visible audit surface; do not execute an
    // arbitrary PATH `mount` binary if the safe resolver misses.
    let bin = keyhog_core::resolve_safe_bin("mount").ok_or_else(|| {
        anyhow::anyhow!(
            "scan-system: trusted mount(8) binary not found. Install the system mount tool or \
             add its absolute directory to [system].trusted_bin_dirs in .keyhog.toml"
        )
    })?;
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
                let fstype = fs_info.split(',').next().unwrap_or("").trim(); // LAW10: missing/non-string field => empty/placeholder; recall-safe
                if skip_fs_types.contains(fstype) {
                    continue;
                }
                if !include_network && network_fs_types.contains(fstype) {
                    continue;
                }
                if filters
                    .skip_path_prefixes
                    .iter()
                    .any(|prefix| path.starts_with(prefix))
                {
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
