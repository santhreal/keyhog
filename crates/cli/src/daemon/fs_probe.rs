//! Backing filesystem authority probe for guard root event delivery (Row 132).
//!
//! Kernel notification subsystems (inotify, FSEvents, ReadDirectoryChangesW) are only
//! authoritative when backed by local block storage or memory filesystems.
//! Network filesystems (NFS, SMB/CIFS, 9P, AFS, CEPH) and userspace/FUSE filesystems
//! do not reliably generate notification events when modifications occur remotely or
//! bypass the local kernel VFS.
//!
//! When an unauthoritative filesystem is registered as a guard root, KeyHog automatically
//! enforces a periodic scrub interval (default 60s) to catch unnotified changes.

use keyhog_core::guard_state::FilesystemAuthority;
use std::path::Path;

/// Default scrub interval in seconds enforced for unauthoritative filesystems
/// when no operator scrub interval is configured.
pub const DEFAULT_UNAUTHORITATIVE_SCRUB_INTERVAL_SECS: u64 = 60;

static TEST_FS_AUTHORITY_OVERRIDE: parking_lot::RwLock<Option<FilesystemAuthority>> =
    parking_lot::RwLock::new(None);

/// Set or clear in-memory filesystem authority override for tests.
pub fn set_test_fs_authority_override(auth: Option<FilesystemAuthority>) {
    *TEST_FS_AUTHORITY_OVERRIDE.write() = auth;
}
/// Assess whether a filesystem type string is authoritative for change notifications.
#[must_use]
pub fn classify_filesystem_type(fs_type: &str) -> FilesystemAuthority {
    let lower = fs_type.to_ascii_lowercase();
    let (authoritative, reason) = match lower.as_str() {
        // Local authoritative Linux / Unix filesystems
        "ext4" | "ext3" | "ext2" | "btrfs" | "xfs" | "zfs" | "jfs" | "f2fs" | "vfat" | "fat32"
        | "exfat" | "ntfs" | "ntfs3" | "tmpfs" | "ramfs" => (true, None),

        // macOS local filesystems
        "apfs" | "hfs" | "hfs+" | "ufs" => (true, None),

        // Windows local volume types
        "refs" | "fat" => (true, None),

        // Network filesystems (unauthoritative)
        "nfs" | "nfs4" | "nfs3" => (
            false,
            Some("network filesystem (NFS) does not deliver kernel events for remote modifications"),
        ),
        "cifs" | "smb" | "smbfs" | "smb2" | "smb3" => (
            false,
            Some("network filesystem (SMB/CIFS) does not deliver kernel events for remote modifications"),
        ),
        "9p" | "9p2000" => (
            false,
            Some("plan 9 network/virtio filesystem (9P) does not guarantee host kernel change notifications"),
        ),
        "afs" => (
            false,
            Some("Andrew File System (AFS) does not deliver kernel change events for remote writes"),
        ),
        "ceph" | "cephfs" => (
            false,
            Some("Ceph distributed filesystem does not guarantee real-time local VFS change events"),
        ),
        "glusterfs" => (
            false,
            Some("GlusterFS distributed filesystem does not guarantee real-time local change events"),
        ),

        // Userspace / virtual filesystems
        "fuse" | "fuseblk" | "osxfuse" | "macfuse" | "fuse.sshfs" | "sshfs" => (
            false,
            Some("userspace filesystem (FUSE) does not reliably propagate kernel inotify events"),
        ),
        "overlay" | "overlayfs" => (
            false,
            Some("overlayfs layers may bypass upperdir inotify notifications on lower layer edits"),
        ),

        // Unknown / unclassified -> fail closed
        _ => (
            false,
            Some("unrecognized filesystem type defaults to unauthoritative (fail closed)"),
        ),
    };

    if authoritative {
        FilesystemAuthority::authoritative(lower)
    } else {
        FilesystemAuthority::unauthoritative(
            lower,
            reason.unwrap_or("unauthoritative filesystem requires periodic scrub"), // LAW10: documented default reason fails closed to unauthoritative periodic scrub
        )
    }
}

/// Probe the filesystem authority for a given path.
#[must_use]
pub fn probe_filesystem_authority(path: &Path) -> FilesystemAuthority {
    if let Some(auth) = TEST_FS_AUTHORITY_OVERRIDE.read().as_ref() {
        return auth.clone();
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(auth) = probe_linux(path) {
            return auth;
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(auth) = probe_macos(path) {
            return auth;
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(auth) = probe_windows(path) {
            return auth;
        }
    }

    // Generic fallback if OS-specific probe fails or is unsupported
    FilesystemAuthority::unauthoritative(
        "unknown",
        "filesystem probe could not determine backing filesystem type (fail closed)",
    )
}

#[cfg(target_os = "linux")]
fn probe_linux(path: &Path) -> Option<FilesystemAuthority> {
    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        // LAW10: fail-open for suppression: mount table probing failure falls through to statfs probing
        if let Some(fs_type) = find_mount_fs_type(&mounts, path) {
            return Some(classify_filesystem_type(&fs_type));
        }
    }

    probe_statfs_magic(path)
}

#[cfg(target_os = "linux")]
fn find_mount_fs_type(mounts: &str, target_path: &Path) -> Option<String> {
    let canonical = target_path
        .canonicalize()
        .unwrap_or_else(|_| target_path.to_path_buf()); // LAW10: recall-preserving fallback to uncanonicalized path when canonicalize fails
    let mut best_match: Option<(usize, String)> = None;

    for line in mounts.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 {
            let mount_point = Path::new(fields[1]);
            let fs_type = fields[2];
            if canonical.starts_with(mount_point) {
                let len = mount_point.as_os_str().len();
                if best_match
                    .as_ref()
                    .map_or(true, |(best_len, _)| len > *best_len)
                {
                    best_match = Some((len, fs_type.to_string()));
                }
            }
        }
    }

    best_match.map(|(_, fs_type)| fs_type)
}

#[cfg(target_os = "linux")]
fn probe_statfs_magic(path: &Path) -> Option<FilesystemAuthority> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?; // LAW10: fail-closed: non-nul path conversion failure falls closed to unauthoritative
                                                                  // SAFETY: libc::statfs populates a zeroed statfs struct for a valid nul-terminated path pointer.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::statfs(c_path.as_ptr(), &mut stat) };
    if res != 0 {
        return None;
    }

    // Common filesystem magic numbers on Linux:
    let f_type = stat.f_type as u64;
    let fs_name = match f_type {
        0xEF53 => "ext4",
        0x9123_683E => "btrfs",
        0x5846_5342 => "xfs",
        0x0102_1994 => "tmpfs",
        0x6969 => "nfs",
        0xFF53_4D42 | 0x517B => "cifs",
        0x6573_5546 => "fuse",
        0x794C_7630 => "overlay",
        0x0102_1997 => "9p",
        _ => {
            return Some(classify_filesystem_type(&format!(
                "unknown-magic-{f_type:#x}"
            )))
        }
    };

    Some(classify_filesystem_type(fs_name))
}

#[cfg(target_os = "macos")]
fn probe_macos(path: &Path) -> Option<FilesystemAuthority> {
    use std::ffi::CStr;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?; // LAW10: fail-closed: non-nul path conversion failure falls closed to unauthoritative
                                                                  // SAFETY: libc::statfs populates a zeroed statfs struct for a valid nul-terminated path pointer.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::statfs(c_path.as_ptr(), &mut stat) };
    if res != 0 {
        return None;
    }

    // SAFETY: f_fstypename is a nul-terminated C string in the populated statfs struct.
    let fstypename = unsafe { CStr::from_ptr(stat.f_fstypename.as_ptr()) };
    let fs_str = fstypename.to_str().ok()?; // LAW10: fail-closed: non-utf8 fstypename falls closed to unauthoritative
    Some(classify_filesystem_type(fs_str))
}

#[cfg(target_os = "windows")]
fn probe_windows(path: &Path) -> Option<FilesystemAuthority> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        GetDriveTypeW, GetVolumeInformationW, DRIVE_REMOTE,
    };

    let mut path_buf = path.to_path_buf();
    if !path_buf.is_absolute() {
        path_buf = path_buf.canonicalize().ok()?; // LAW10: fail-closed: canonicalization failure falls closed to unauthoritative
    }
    let root_str = path_buf.components().next()?.as_os_str();
    let root_with_slash = format!("{}\\", root_str.to_string_lossy());
    let wide_root: Vec<u16> = OsStr::new(&root_with_slash)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: wide_root is a nul-terminated wide string path representing the drive root.
    let drive_type = unsafe { GetDriveTypeW(wide_root.as_ptr()) };
    if drive_type == DRIVE_REMOTE {
        return Some(FilesystemAuthority::unauthoritative(
            "network-drive",
            "remote network drive (DRIVE_REMOTE) does not reliably generate change events",
        ));
    }

    let mut fs_name_buf = [0u16; 256];
    // SAFETY: GetVolumeInformationW is passed valid buffer pointers and buffer lengths.
    let ok = unsafe {
        GetVolumeInformationW(
            wide_root.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            fs_name_buf.as_mut_ptr(),
            fs_name_buf.len() as u32,
        )
    };

    if ok != 0 {
        let len = fs_name_buf.iter().position(|&c| c == 0).unwrap_or(0); // LAW10: documented default fallback length if no nul terminator in buffer
        let fs_name = String::from_utf16_lossy(&fs_name_buf[..len]);
        Some(classify_filesystem_type(&fs_name))
    } else {
        Some(classify_filesystem_type("unknown-windows-volume"))
    }
}
