//! Mount enumeration for `keyhog scan-system`.
//!
//! Walks platform-specific mount-table sources (Linux `/proc/mounts`,
//! macOS `mount(8)`, Windows `GetLogicalDrives`) and returns the set
//! of root paths the scanner should visit. Filters pseudo-FS (proc,
//! sysfs, tmpfs, etc.) and, by default, network mounts (NFS / SMB /
//! sshfs / 9p / ceph) so a `scan-system` run can't accidentally walk
//! other tenants' data.

use anyhow::{Context, Result};
use std::path::PathBuf;

/// Enumerate mounted filesystems on the current OS, filtering pseudo-FS
/// and (optionally) network mounts. Returns root paths.
///
/// `include_network` is honored on Linux, macOS, and Windows. Missing or
/// malformed platform mount evidence is an error; substituting a different
/// root set would make the system scan coverage dishonest.
pub(super) fn enumerate_mounts(include_network: bool) -> Result<Vec<PathBuf>> {
    #[cfg(target_os = "linux")]
    {
        linux_mounts(include_network)
    }
    #[cfg(target_os = "macos")]
    {
        macos_mounts(include_network)
    }
    #[cfg(target_os = "windows")]
    {
        windows_drives(include_network)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Ok(vec![std::env::current_dir()?])
    }
}

/// Scan-system mount filters loaded from Tier-B data.
#[derive(Debug, Default, serde::Deserialize)]
struct MountFilters {
    #[serde(default)]
    skip_fs_types: Vec<String>,
    #[serde(default)]
    skip_path_prefixes: Vec<String>,
    #[serde(default)]
    network_fs_types: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsDriveClass {
    Local,
    Network,
    Unsupported,
}

/// Compiled-in Tier-B baseline. Always applied.
const BUNDLED_MOUNT_FILTERS: &str = include_str!("../../../data/scan_system/mount_filters.toml");

/// Load scan-system mount filters: the embedded baseline UNIONED with an
/// optional `<config>/keyhog/mount_filters.toml`, so an operator can skip an
/// exotic filesystem or path without recompiling.
///
/// No silent fallback (Law 10): the baseline parse is surfaced as an error (a
/// failure means the embedded data is corrupt, a build bug, caught by the data
/// test), and a user file that EXISTS but is unreadable or unparseable is a hard
/// error. Only the ordinary "no user file present" case uses the baseline alone,
/// which is the intended default (not a degraded fallback).
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

fn include_windows_drive(
    root: &str,
    drive_class: WindowsDriveClass,
    include_network: bool,
    filters: &MountFilters,
) -> bool {
    if windows_root_matches_any_skip_prefix(root, &filters.skip_path_prefixes) {
        return false;
    }
    match drive_class {
        WindowsDriveClass::Local => true,
        WindowsDriveClass::Network => include_network,
        WindowsDriveClass::Unsupported => false,
    }
}

fn windows_root_matches_any_skip_prefix(root: &str, prefixes: &[String]) -> bool {
    let normalized_root = root.replace('/', "\\");
    prefixes.iter().any(|prefix| {
        let normalized_prefix = prefix.replace('/', "\\");
        normalized_root
            .get(..normalized_prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(&normalized_prefix))
    })
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
        let Some(decoded) = decoded_mount_target_if_included(target, &filters)? else {
            continue;
        };
        if seen.insert(decoded.clone()) {
            roots.push(PathBuf::from(decoded));
        }
    }
    Ok(dedupe_mount_roots(roots))
}

fn dedupe_mount_roots(mut roots: Vec<PathBuf>) -> Vec<PathBuf> {
    // Sort ASCENDING (shortest path first) so the loop below catches subpaths of
    // an already-included root. The prior descending Linux sort made dedup a
    // no-op, causing `/` and `/home` to both be scanned.
    roots.sort_by_key(|p| p.as_os_str().len());
    let mut deduped: Vec<PathBuf> = Vec::new();
    for r in roots {
        let already_covered = deduped.iter().any(|d| r.starts_with(d) && r != *d);
        if !already_covered {
            deduped.push(r);
        }
    }
    deduped
}

#[cfg(target_os = "linux")]
fn decoded_mount_target_if_included(
    target: &str,
    filters: &MountFilters,
) -> Result<Option<String>> {
    let decoded = decode_octal_escapes(target)
        .with_context(|| format!("decode /proc/mounts target {target:?}"))?;
    if filters
        .skip_path_prefixes
        .iter()
        .any(|prefix| decoded.starts_with(prefix))
    {
        return Ok(None);
    }
    Ok(Some(decoded))
}

/// Linux `/proc/mounts` emits spaces and special characters as `\040`,
/// `\011`, etc. (POSIX octal escapes). Only `linux_mounts` consumes
/// this, so the helper is gated to `target_os = "linux"` to avoid a
/// dead-code warning on Windows / macOS.
#[cfg(target_os = "linux")]
fn decode_octal_escapes(s: &str) -> Result<String> {
    // Decode into a byte buffer, not a `String`: a `\NNN` escape names a single
    // raw path BYTE, and `byte as char` would map a byte >= 0x80 to its Latin-1
    // scalar (U+0080..U+00FF), corrupting any multi-byte path. `/proc/mounts` is
    // read via `read_to_string`, so the input is already valid UTF-8 and the
    // kernel only escapes ASCII controls (space/tab/newline/backslash); the final
    // `from_utf8` therefore succeeds, but if a high-byte escape ever produced
    // invalid UTF-8 we fail closed loudly rather than silently mojibake the path.
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let mut bytes = s.bytes().peekable();
    while let Some(b) = bytes.next() {
        if b == b'\\' {
            let mut octal = String::with_capacity(3);
            for _ in 0..3 {
                match bytes.peek() {
                    Some(&d) if d.is_ascii_digit() => {
                        octal.push(d as char);
                        bytes.next();
                    }
                    _ => break,
                }
            }
            if octal.len() == 3 {
                let byte = u8::from_str_radix(&octal, 8)
                    .with_context(|| format!("invalid octal mount escape \\{octal}"))?;
                out.push(byte);
                continue;
            }
            anyhow::bail!("incomplete mount escape \\{octal}");
        } else {
            out.push(b);
        }
    }
    String::from_utf8(out)
        .with_context(|| format!("decoded /proc/mounts target is not UTF-8: {s:?}"))
}

#[cfg(target_os = "macos")]
fn macos_mounts(include_network: bool) -> Result<Vec<PathBuf>> {
    let filters = load_mount_filters()?;
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
    Ok(parse_macos_mount_table(&text, include_network, &filters))
}

fn parse_macos_mount_table(
    text: &str,
    include_network: bool,
    filters: &MountFilters,
) -> Vec<PathBuf> {
    let skip_fs_types: std::collections::HashSet<&str> =
        filters.skip_fs_types.iter().map(String::as_str).collect();
    let network_fs_types: std::collections::HashSet<&str> = filters
        .network_fs_types
        .iter()
        .map(String::as_str)
        .collect();
    let mut roots = Vec::new();
    for line in text.lines() {
        if let Some(on_idx) = line.rfind(" on ") {
            let rest = &line[on_idx + 4..];
            if let Some(paren_idx) = rest.rfind(" (") {
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
    dedupe_mount_roots(roots)
}

pub(crate) mod testing {
    use super::{include_windows_drive, parse_macos_mount_table, MountFilters, WindowsDriveClass};
    use std::path::PathBuf;

    pub(crate) fn parse_macos_mount_table_for_test(
        text: &str,
        include_network: bool,
    ) -> Result<Vec<PathBuf>, toml::de::Error> {
        let filters: MountFilters = toml::from_str(super::BUNDLED_MOUNT_FILTERS)?;
        Ok(parse_macos_mount_table(text, include_network, &filters))
    }

    pub(crate) fn windows_drive_filter_decisions_for_test(
    ) -> Result<(bool, bool, bool, bool), toml::de::Error> {
        let filters: MountFilters = toml::from_str(super::BUNDLED_MOUNT_FILTERS)?;
        let local_without_network =
            include_windows_drive("C:\\", WindowsDriveClass::Local, false, &filters);
        let remote_without_network =
            include_windows_drive("Z:\\", WindowsDriveClass::Network, false, &filters);
        let remote_with_network =
            include_windows_drive("Z:\\", WindowsDriveClass::Network, true, &filters);
        let unsupported =
            include_windows_drive("Q:\\", WindowsDriveClass::Unsupported, true, &filters);
        Ok((
            local_without_network,
            remote_without_network,
            remote_with_network,
            unsupported,
        ))
    }

    pub(crate) fn windows_drive_skip_prefix_decisions_for_test() -> (bool, bool) {
        let prefixes = vec!["z:/".to_string()];
        (
            super::windows_root_matches_any_skip_prefix("Z:\\", &prefixes),
            super::windows_root_matches_any_skip_prefix("C:\\", &prefixes),
        )
    }

    /// Decode a `/proc/mounts` octal-escaped target and apply Tier-B skip
    /// prefixes, returning `Ok(None)` when the decoded path is skipped and
    /// `Err` on a malformed octal escape. Linux-only (the underlying
    /// `decoded_mount_target_if_included` is `#[cfg(target_os = "linux")]`).
    #[cfg(target_os = "linux")]
    pub(crate) fn decoded_mount_target_if_included_for_test(
        target: &str,
        skip_path_prefixes: Vec<String>,
    ) -> anyhow::Result<Option<String>> {
        let filters = MountFilters {
            skip_path_prefixes,
            ..MountFilters::default()
        };
        super::decoded_mount_target_if_included(target, &filters)
    }
}

#[cfg(target_os = "windows")]
fn windows_drives(include_network: bool) -> Result<Vec<PathBuf>> {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    use windows_sys::Win32::System::WindowsProgramming::{
        DRIVE_FIXED, DRIVE_RAMDISK, DRIVE_REMOTE,
    };

    let filters = load_mount_filters()?;
    let mask = unsafe { GetLogicalDrives() };
    if mask == 0 {
        return Err(std::io::Error::last_os_error()).context("enumerate Windows logical drives");
    }

    let mut drives = Vec::new();
    for (idx, letter) in (b'A'..=b'Z').enumerate() {
        if (mask & (1 << idx)) == 0 {
            continue;
        }
        let root = format!("{}:\\", letter as char);
        let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
        let drive_class = match unsafe { GetDriveTypeW(wide.as_ptr()) } {
            DRIVE_FIXED | DRIVE_RAMDISK => WindowsDriveClass::Local,
            DRIVE_REMOTE => WindowsDriveClass::Network,
            _ => WindowsDriveClass::Unsupported,
        };
        if include_windows_drive(&root, drive_class, include_network, &filters) {
            drives.push(PathBuf::from(root));
        }
    }
    Ok(dedupe_mount_roots(drives))
}
