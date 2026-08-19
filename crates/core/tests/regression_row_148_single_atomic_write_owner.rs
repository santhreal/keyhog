//! Regression: Row 148 — Single atomic durable-write implementation in `keyhog_core::state_file`.
//!
//! Verifies that `keyhog_core::state_file::write_atomically` and
//! `keyhog_core::state_file::write_atomically_with_writer` are the single source
//! of truth for atomic durable writes across KeyHog.
//!
//! Tests:
//! - Atomic slice writes (`write_atomically` & `write_atomically_with_prefix`)
//! - Streaming closure writes (`write_atomically_with_writer` & `write_atomically_with_writer_and_prefix`)
//! - Parent directory creation for nested destinations
//! - Fail-closed error handling: tempfile cleanup and target preservation on failure
//! - Stale tempfile sweeping hygiene

use keyhog_core::state_file::{
    sweep_stale_tmp_siblings, write_atomically, write_atomically_with_prefix,
    write_atomically_with_writer, write_atomically_with_writer_and_prefix, DEFAULT_TMP_PREFIX,
};
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::time::{Duration, SystemTime};
use tempfile::TempDir;

#[test]
fn write_atomically_creates_new_file_and_leaves_no_temp_sibling() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("state.json");
    let payload = b"{\"version\": 1, \"status\": \"ok\"}";

    write_atomically(&target, payload).expect("write_atomically should succeed");

    assert_eq!(
        std::fs::read(&target).expect("read target"),
        payload,
        "written content must match payload"
    );

    // Ensure no leftover temp files exist in the parent directory
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read_dir")
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "parent directory must hold only the target file"
    );
    assert_eq!(entries[0].path(), target);
}

#[test]
fn write_atomically_replaces_existing_file_durably() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("state.bin");
    let initial_data = b"initial uncorrupted state data";
    let updated_data = b"updated atomic state payload with new checksums";

    write_atomically(&target, initial_data).expect("initial write");
    assert_eq!(std::fs::read(&target).expect("read"), initial_data);

    write_atomically(&target, updated_data).expect("update write");
    assert_eq!(std::fs::read(&target).expect("read"), updated_data);

    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read_dir")
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "only the target file must exist after atomic replacement"
    );
}

#[test]
fn write_atomically_creates_missing_parent_directories() {
    let dir = TempDir::new().expect("tempdir");
    let deeply_nested = dir
        .path()
        .join("level1")
        .join("level2")
        .join("level3")
        .join("artifact.idx");
    let payload = b"merkle-index-v4-content";

    write_atomically(&deeply_nested, payload).expect("must create parents");
    assert_eq!(std::fs::read(&deeply_nested).expect("read nested"), payload);
}

#[test]
fn write_atomically_with_writer_streams_and_persists() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("matcher.bin");

    let magic = b"KHMB";
    let version: u32 = 4;
    let data = b"payload segment 1 -- payload segment 2";

    write_atomically_with_writer(&target, |tmp| {
        tmp.write_all(magic)?;
        tmp.write_all(&version.to_le_bytes())?;
        tmp.write_all(data)?;
        Ok(())
    })
    .expect("streaming write must succeed");

    let mut expected = Vec::new();
    expected.extend_from_slice(magic);
    expected.extend_from_slice(&version.to_le_bytes());
    expected.extend_from_slice(data);

    assert_eq!(std::fs::read(&target).expect("read streamed"), expected);
}

#[test]
fn write_atomically_with_writer_fails_closed_on_error() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("critical_state.json");
    let original = b"original intact state";

    // Seed original target
    std::fs::write(&target, original).expect("seed target");

    // Attempt streaming write that fails halfway through
    let result = write_atomically_with_writer(&target, |tmp| {
        tmp.write_all(b"corrupted partial write...")?;
        Err(std::io::Error::other(
            "simulated unexpected I/O failure during serialization",
        ))
    });

    assert!(
        result.is_err(),
        "write must fail when closure returns error"
    );

    // Original target must remain completely unmodified
    assert_eq!(
        std::fs::read(&target).expect("read original"),
        original,
        "target file must remain intact after failed atomic write"
    );

    // No temp files left in directory
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read_dir")
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "failed write must unlink temp file and leave no orphaned siblings"
    );
    assert_eq!(entries[0].path(), target);
}

#[test]
fn write_atomically_with_prefix_uses_custom_prefix() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("calibration.json");
    let custom_prefix = ".tmp.keyhog-calibration-custom-";
    let payload = b"{\"calibration\": true}";

    write_atomically_with_prefix(&target, custom_prefix, payload)
        .expect("write with prefix must succeed");

    assert_eq!(std::fs::read(&target).expect("read"), payload);
}

#[test]
fn write_atomically_with_writer_and_prefix_streams_with_custom_prefix() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("merkle.idx");
    let custom_prefix = ".tmp.keyhog-merkle-custom-";

    write_atomically_with_writer_and_prefix(&target, custom_prefix, |tmp| {
        tmp.write_all(b"custom prefixed merkle data")
    })
    .expect("write with writer and prefix");

    assert_eq!(
        std::fs::read(&target).expect("read"),
        b"custom prefixed merkle data"
    );
}

#[cfg(unix)]
fn set_mtime(path: &Path, t: SystemTime) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let dur = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(std::io::Error::other)?;
    let cpath = CString::new(path.as_os_str().as_bytes()).map_err(std::io::Error::other)?;
    let times = [
        libc::timespec {
            tv_sec: dur.as_secs() as libc::time_t,
            tv_nsec: dur.subsec_nanos() as libc::c_long,
        },
        libc::timespec {
            tv_sec: dur.as_secs() as libc::time_t,
            tv_nsec: dur.subsec_nanos() as libc::c_long,
        },
    ];
    let rc = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            cpath.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[test]
fn stale_tmp_siblings_hygiene_sweeps_only_old_matching_prefixes() {
    let dir = TempDir::new().expect("tempdir");
    let active_target = dir.path().join("state.idx");
    std::fs::write(&active_target, b"active file").expect("write active");

    let old_tmp = dir.path().join(format!("{DEFAULT_TMP_PREFIX}old12345"));
    let fresh_tmp = dir.path().join(format!("{DEFAULT_TMP_PREFIX}fresh6789"));
    let unrelated_old_file = dir.path().join("unrelated_old_file.txt");

    std::fs::write(&old_tmp, b"stale data").expect("write old_tmp");
    std::fs::write(&fresh_tmp, b"in-flight data").expect("write fresh_tmp");
    std::fs::write(&unrelated_old_file, b"unrelated").expect("write unrelated");

    #[cfg(unix)]
    {
        // Age the `old_tmp` and `unrelated_old_file` by 2 hours
        let two_hours_ago = SystemTime::now() - Duration::from_secs(7200);
        let _ = set_mtime(&old_tmp, two_hours_ago);
        let _ = set_mtime(&unrelated_old_file, two_hours_ago);

        // Sweep with 3600 second (1 hour) cutoff
        let swept = sweep_stale_tmp_siblings(&active_target, &[DEFAULT_TMP_PREFIX], 3600);

        assert_eq!(swept, 1, "exactly one stale tmp file must be swept");
        assert!(!old_tmp.exists(), "old tmp file must be deleted");
        assert!(
            fresh_tmp.exists(),
            "recent in-flight tmp file must NOT be deleted"
        );
        assert!(
            unrelated_old_file.exists(),
            "unrelated old file without matching prefix must NOT be deleted"
        );
        assert!(
            active_target.exists(),
            "active target file must NOT be touched"
        );
    }
}
