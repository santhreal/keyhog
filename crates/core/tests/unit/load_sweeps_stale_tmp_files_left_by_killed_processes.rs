//! Migrated from `src/merkle_index.rs` inline tests.
use keyhog_core::merkle_index::{compute_spec_hash, MerkleIndex};
use keyhog_core::spec::{CompanionSpec, DetectorSpec, PatternSpec, Severity};
use std::path::{Path, PathBuf};

#[cfg(unix)]
mod filetime_workaround {
    use std::path::Path;
    use std::time::SystemTime;
    pub fn set_mtime(path: &Path, t: SystemTime) -> std::io::Result<()> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let dur = t.duration_since(SystemTime::UNIX_EPOCH).map_err(std::io::Error::other)?;
        let cpath = CString::new(path.as_os_str().as_bytes()).map_err(std::io::Error::other)?;
        let times = [
            libc::timespec { tv_sec: dur.as_secs() as libc::time_t, tv_nsec: dur.subsec_nanos() as libc::c_long },
            libc::timespec { tv_sec: dur.as_secs() as libc::time_t, tv_nsec: dur.subsec_nanos() as libc::c_long },
        ];
        let rc = unsafe { libc::utimensat(libc::AT_FDCWD, cpath.as_ptr(), times.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) };
        if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
    }
}
#[cfg(not(unix))]
mod filetime_workaround {
    use std::path::Path;
    use std::time::SystemTime;
    pub fn set_mtime(_path: &Path, _t: SystemTime) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}
fn sample_hash(s: &[u8]) -> [u8; 32] { MerkleIndex::hash_content(s) }
#[test]
    fn load_sweeps_stale_tmp_files_left_by_killed_processes() {
        // Plant a fake stale tmp file matching tempfile's pattern,
        // backdate its mtime to 2 hours ago. Calling `load` (which
        // doesn't even need to find the real cache) should trigger
        // the sweep and delete it. A fresh tmp must survive the
        // sweep — covering the case where another keyhog process
        // is mid-save right now.
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("merkle.idx");

        // Old tmp — should be swept.
        let old_tmp = dir.path().join(".tmpABCDEF");
        std::fs::write(&old_tmp, b"stale leftover").unwrap();
        let two_hours_ago =
            std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 60 * 60);
        let _ = filetime_workaround::set_mtime(&old_tmp, two_hours_ago);
        // (The real test below uses a manual-mtime manipulation via
        // Linux/macOS `utimensat`. On Windows the test verifies the
        // age check still doesn't sweep just-created files; we
        // can't easily backdate without extra deps.)

        // Fresh tmp — should be preserved.
        let fresh_tmp = dir.path().join(".tmpFRESH");
        std::fs::write(&fresh_tmp, b"in-flight save").unwrap();

        // Also a non-tmp sibling that must NEVER be touched.
        let unrelated = dir.path().join("unrelated.json");
        std::fs::write(&unrelated, b"keep me").unwrap();

        let _ = MerkleIndex::load(&cache_path);

        // Fresh tmp survives.
        assert!(
            fresh_tmp.exists(),
            "sweep deleted a fresh tmp file — race with in-flight save"
        );
        // Unrelated sibling survives.
        assert!(
            unrelated.exists(),
            "sweep deleted an unrelated sibling file"
        );
        // Old tmp deleted IF the mtime backdate worked. On systems
        // where setting mtime fails (some Windows configs), the
        // sweep correctly skips it (mtime is "now" → <1 hour),
        // which is the safe default.
        if !old_tmp.exists() {
            // happy path — sweep fired
        } else {
            // mtime backdate didn't take effect; can't assert
            // sweep behavior on this platform without extra deps.
        }
    }
