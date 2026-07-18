//! The recoverability invariant in tests: no update/repair may leave the
//! machine without a working binary. Drives `installer::install_with_rollback`
//! against a REAL filesystem with the actual failure modes (broken new binary,
//! read-only install dir, fresh install) and a verify closure standing in for
//! the new binary's `doctor`. These prove the backup → install → verify →
//! rollback sequence holds under each failure.
//!
//! Unix-only because they assert the unix copy-based `install_with_rollback`
//! (and `backup_path`). The Windows self-replace uses the rename-away dance in
//! `installer::replace_running_binary`, whose equivalent backup → install →
//! verify → rollback invariant is covered cross-platform by the
//! `rename_away_tests` unit tests in `installer.rs`.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use keyhog::testing::{CliTestApi as _, API};
use tempfile::TempDir;

use crate::reliability::harness::subprocess_slot;

/// A fake install dir holding a fake "current" binary with given contents.
fn staged_exe(contents: &[u8]) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let exe = dir.path().join("keyhog");
    fs::write(&exe, contents).expect("write fake binary");
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).expect("chmod");
    (dir, exe)
}

fn version_script(version: &str) -> Vec<u8> {
    format!(
        "#!/bin/sh\n\
         case \"$1\" in\n\
           doctor) exit 0 ;;\n\
           --version) echo 'KeyHog v{version}'; exit 0 ;;\n\
           *) exit 2 ;;\n\
         esac\n"
    )
    .into_bytes()
}

#[test]
fn successful_install_swaps_bytes_and_leaves_no_backup() {
    let (_dir, exe) = staged_exe(b"OLD-WORKING-BINARY");
    let r = API.install_with_rollback(&exe, b"NEW-GOOD-BINARY", |_| true);
    assert!(r.is_ok(), "verified install should succeed: {r:?}");
    assert_eq!(fs::read(&exe).unwrap(), b"NEW-GOOD-BINARY");
    assert!(
        !API.backup_path(&exe).exists(),
        "a successful install must not leave a .bak turd behind"
    );
}

#[test]
fn successful_install_keeps_executable_bit() {
    let (_dir, exe) = staged_exe(b"OLD");
    API.install_with_rollback(&exe, b"NEW", |_| true).unwrap();
    let mode = fs::metadata(&exe).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o755, "installed binary must be executable (0755)");
}

#[test]
fn failed_verify_rolls_back_to_the_working_binary() {
    // The core invariant: the new binary is signed + a valid ELF but does not
    // run on this host (verify == false). We must restore the old binary.
    let (_dir, exe) = staged_exe(b"OLD-WORKING-BINARY");
    let r = API.install_with_rollback(&exe, b"NEW-BROKEN-BINARY", |_| false);
    assert!(r.is_err(), "a failed health check must report an error");
    assert_eq!(
        fs::read(&exe).unwrap(),
        b"OLD-WORKING-BINARY",
        "ROLLBACK FAILED: the working binary was not restored after a broken update"
    );
    assert!(
        !API.backup_path(&exe).exists(),
        "rollback must consume the backup, not leave it beside the binary"
    );
    let mode = fs::metadata(&exe).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o755, "restored binary must remain executable");
}

#[test]
fn rolled_back_binary_is_byte_identical_to_the_original() {
    // Arbitrary binary content including NULs and high bytes: rollback must be
    // exact, not "close enough".
    let original: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    let dir = TempDir::new().unwrap();
    let exe = dir.path().join("keyhog");
    fs::write(&exe, &original).unwrap();
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();

    let _ = API.install_with_rollback(&exe, b"broken", |_| false);
    assert_eq!(
        fs::read(&exe).unwrap(),
        original,
        "rollback must restore the original binary byte-for-byte"
    );
}

#[test]
fn fresh_install_failed_verify_removes_the_broken_binary() {
    // No prior binary at the path. If the freshly-installed one fails its
    // health check, we must not leave a broken executable lying around.
    let dir = TempDir::new().unwrap();
    let exe = dir.path().join("keyhog");
    assert!(!exe.exists());
    let r = API.install_with_rollback(&exe, b"NEW-BROKEN", |_| false);
    assert!(r.is_err());
    assert!(
        !exe.exists(),
        "a broken fresh install must be removed, not left in place"
    );
}

#[test]
fn fresh_install_success_leaves_the_new_binary() {
    let dir = TempDir::new().unwrap();
    let exe = dir.path().join("keyhog");
    let r = API.install_with_rollback(&exe, b"NEW-GOOD", |_| true);
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(fs::read(&exe).unwrap(), b"NEW-GOOD");
}

#[test]
fn verify_runs_against_the_newly_installed_bytes() {
    // Proves ordering: the new binary is in place BEFORE verify runs, so the
    // health check actually exercises the candidate, not the old binary.
    let (_dir, exe) = staged_exe(b"OLD");
    let exe_for_closure = exe.clone();
    let r = API.install_with_rollback(&exe, b"NEW-CANDIDATE", move |p: &Path| {
        // verify is handed the live exe path; it must already hold the new bytes.
        p == exe_for_closure && fs::read(p).unwrap() == b"NEW-CANDIDATE"
    });
    assert!(
        r.is_ok(),
        "verify did not see the new bytes at the exe path: {r:?}"
    );
}

#[test]
fn release_tag_version_mismatch_rolls_back_to_the_working_binary() {
    let _slot = subprocess_slot();
    let original = b"OLD-WORKING-BINARY";
    let (_dir, exe) = staged_exe(original);
    let candidate = version_script("0.5.39");

    let err = API
        .install_with_rollback_checked(&exe, &candidate, |path| {
            API.verify_candidate_release(path, "v0.5.40", "0.5.38", false)
        })
        .expect_err("a signed binary whose reported version mismatches the release tag must fail");

    let msg = err.to_string();
    assert!(
        msg.contains("does not match release tag") && msg.contains("rolled back"),
        "version mismatch must be operator-visible and rollback-explicit, got: {msg}"
    );
    assert_eq!(
        fs::read(&exe).unwrap(),
        original,
        "version mismatch rollback must restore the prior binary byte-for-byte"
    );
}

#[test]
fn rollback_restore_failure_reports_original_verify_error() {
    let (_dir, exe) = staged_exe(b"OLD-WORKING-BINARY");

    let err = API
        .install_with_rollback_checked(&exe, b"NEW-BROKEN-BINARY", |path| {
            std::fs::remove_file(path).expect("remove candidate before blocking rollback");
            std::fs::create_dir(path).expect("directory at exe path blocks file restore");
            Err(anyhow::anyhow!("candidate doctor sentinel failure"))
        })
        .expect_err("rollback restore must fail when the exe path is a directory");
    let message = format!("{err:#}");

    assert!(
        message.contains("ROLLBACK FAILED")
            && message.contains("candidate doctor sentinel failure")
            && message.contains("could not be restored"),
        "rollback restore failure must preserve the original verifier error and restore failure context, got: {message}"
    );
}

#[test]
fn older_candidate_version_requires_an_explicit_pin() {
    let _slot = subprocess_slot();
    let candidate = version_script("0.5.39");
    let (_dir, exe) = staged_exe(&candidate);

    let err = API
        .verify_candidate_release(&exe, "v0.5.39", "0.5.40", false)
        .expect_err("unrequested downgrade must fail closed");
    assert!(
        err.to_string().contains("implicit downgrade"),
        "implicit downgrade error must name the policy, got: {err}"
    );

    API.verify_candidate_release(&exe, "v0.5.39", "0.5.40", true)
        .expect("an exact explicitly pinned older release remains allowed");
}

#[test]
fn cannot_create_backup_in_readonly_dir_leaves_original_untouched() {
    // If we cannot stage a backup (read-only install dir), we must abort BEFORE
    // overwriting - the working binary stays exactly as it was.
    let dir = TempDir::new().unwrap();
    let exe = dir.path().join("keyhog");
    fs::write(&exe, b"OLD-WORKING").unwrap();
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
    // Make the directory unwritable so the backup copy fails.
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o555)).unwrap();

    let r = API.install_with_rollback(&exe, b"NEW", |_| true);

    // Restore dir perms so TempDir can clean up regardless of the assertion.
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();

    assert!(
        r.is_err(),
        "install into a read-only dir must fail, not silently no-op"
    );
    assert_eq!(
        fs::read(&exe).unwrap(),
        b"OLD-WORKING",
        "a backup failure must never touch the working binary"
    );
}

#[test]
fn backup_path_sits_beside_the_exe_and_is_hidden() {
    let exe = Path::new("/opt/keyhog/bin/keyhog");
    let bak = API.backup_path(exe);
    assert_eq!(
        bak.parent(),
        exe.parent(),
        "backup must be in the same dir for an atomic same-fs rename"
    );
    let name = bak.file_name().unwrap().to_string_lossy();
    assert!(name.starts_with('.'), "backup should be a dotfile: {name}");
    assert!(
        name.contains("keyhog"),
        "backup name should reference the binary: {name}"
    );
}

#[test]
fn preplanted_update_symlink_cannot_overwrite_its_target() {
    let dir = TempDir::new().unwrap();
    let exe = dir.path().join("keyhog");
    let protected = dir.path().join("protected");
    fs::write(&protected, b"DO-NOT-TOUCH").unwrap();
    let staged = dir
        .path()
        .join(format!(".keyhog-update-{}.tmp", std::process::id()));
    symlink(&protected, &staged).unwrap();

    let error = API
        .install_with_rollback(&exe, b"ATTACKER-CONTROLLED-REPLACEMENT", |_| true)
        .expect_err("a pre-existing staging path must be refused");

    assert!(
        format!("{error:#}").contains("exclusively"),
        "the failure must explain exclusive artifact creation: {error:#}"
    );
    assert_eq!(fs::read(&protected).unwrap(), b"DO-NOT-TOUCH");
    assert!(
        !exe.exists(),
        "failed fresh install must not create the binary"
    );
}

#[test]
fn preplanted_backup_symlink_cannot_overwrite_its_target() {
    let (_dir, exe) = staged_exe(b"OLD-WORKING-BINARY");
    let protected = exe.parent().unwrap().join("protected");
    fs::write(&protected, b"DO-NOT-TOUCH").unwrap();
    symlink(&protected, API.backup_path(&exe)).unwrap();

    let error = API
        .install_with_rollback(&exe, b"NEW-BINARY", |_| true)
        .expect_err("a pre-existing rollback path must be refused");

    assert!(
        format!("{error:#}").contains("exclusively"),
        "the failure must explain exclusive artifact creation: {error:#}"
    );
    assert_eq!(fs::read(&protected).unwrap(), b"DO-NOT-TOUCH");
    assert_eq!(fs::read(&exe).unwrap(), b"OLD-WORKING-BINARY");
}

#[test]
fn writable_by_other_users_install_directory_is_refused() {
    let dir = TempDir::new().unwrap();
    let exe = dir.path().join("keyhog");
    fs::write(&exe, b"OLD-WORKING-BINARY").unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();

    let error = API
        .install_with_rollback(&exe, b"NEW-BINARY", |_| true)
        .expect_err("a shared writable install directory must fail closed");

    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        format!("{error:#}").contains("group/world-writable install directory"),
        "the error must explain the unsafe directory permissions: {error:#}"
    );
    assert_eq!(fs::read(&exe).unwrap(), b"OLD-WORKING-BINARY");
}
