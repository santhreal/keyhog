//! Lane-10 (dogfood/robustness) regression: `reap_stale_binaries` must clear
//! ALL of the temp artifacts a crashed `update`/`repair` can leave beside the
//! binary — not just the rename-away stash.
//!
//! The leak this pins: `install_with_rollback` copies the working binary to a
//! `.<name>.keyhog-bak-<PID>` backup before swapping. The success/rollback
//! paths delete it, but a process KILLED (SIGKILL, OOM, power loss) between the
//! copy and its removal orphans that backup forever — one stale file per
//! crashed update accumulating in the install dir. `install_binary` likewise
//! stages to a `.<name>-update-<PID>.tmp` file that a hard kill orphans. Both
//! are now reaped on the next update/repair, while UNRELATED files beside the
//! binary (and the live binary itself) are always left untouched.

use keyhog::testing::{CliTestApi as _, API};

#[test]
fn reap_clears_orphaned_backup_from_crashed_update() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("keyhog");
    std::fs::write(&exe, b"WORKING-BINARY").unwrap();

    // A backup left behind by a `keyhog update` that was killed mid-rollback.
    let orphan_backup = dir.path().join(".keyhog.keyhog-bak-12345");
    std::fs::write(&orphan_backup, b"PRIOR-WORKING-BINARY").unwrap();

    API.reap_stale_binaries(&exe);

    assert!(
        !orphan_backup.exists(),
        "an orphaned .keyhog-bak-* backup from a crashed update must be reaped, \
         not accumulate forever in the install dir"
    );
    assert_eq!(
        std::fs::read(&exe).unwrap(),
        b"WORKING-BINARY",
        "the live binary must never be touched by the reap"
    );
}

#[test]
fn reap_clears_orphaned_staging_tmp() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("keyhog");
    std::fs::write(&exe, b"WORKING-BINARY").unwrap();

    // A staging file left behind by install_binary killed mid-write.
    let orphan_tmp = dir.path().join(".keyhog-update-67890.tmp");
    std::fs::write(&orphan_tmp, b"HALF-WRITTEN").unwrap();

    API.reap_stale_binaries(&exe);

    assert!(
        !orphan_tmp.exists(),
        "an orphaned .keyhog-update-*.tmp staging file must be reaped"
    );
}

#[test]
fn reap_clears_orphaned_stash_and_backup_together() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("keyhog");
    std::fs::write(&exe, b"WORKING-BINARY").unwrap();

    let orphan_stash = dir.path().join(".keyhog.keyhog-old-11111");
    let orphan_backup = dir.path().join(".keyhog.keyhog-bak-22222");
    std::fs::write(&orphan_stash, b"old").unwrap();
    std::fs::write(&orphan_backup, b"bak").unwrap();

    API.reap_stale_binaries(&exe);

    assert!(!orphan_stash.exists(), "stash must be reaped");
    assert!(!orphan_backup.exists(), "backup must be reaped");
}

#[test]
fn reap_never_touches_unrelated_files_or_live_binary() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("keyhog");
    std::fs::write(&exe, b"WORKING-BINARY").unwrap();

    // Files that merely live beside the binary must survive: a user config, a
    // log, a similarly-named-but-not-ours file.
    let config = dir.path().join("keyhog.toml");
    let log = dir.path().join("keyhog.log");
    let lookalike = dir.path().join("keyhog-backup-notes.txt");
    std::fs::write(&config, b"[scan]\n").unwrap();
    std::fs::write(&log, b"log line\n").unwrap();
    std::fs::write(&lookalike, b"notes\n").unwrap();

    API.reap_stale_binaries(&exe);

    assert!(config.exists(), "user config must be left alone");
    assert!(log.exists(), "log file must be left alone");
    assert!(
        lookalike.exists(),
        "a file whose name does not match the hidden PID-scoped artifact pattern \
         must be left alone"
    );
    assert!(exe.exists(), "the live binary must never be reaped");
    assert_eq!(std::fs::read(&exe).unwrap(), b"WORKING-BINARY");
}
