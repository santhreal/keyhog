use keyhog_core::{SourceCoverageGapKind, SourceError};

use super::{
    clone_materialization_cap, clone_materialization_truncated, CloneMaterializationCap,
    CloneMaterializationGuard,
};

#[test]
fn guard_enforces_byte_and_entry_caps() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("clone");
    std::fs::create_dir(&root).expect("clone root");
    std::fs::write(root.join("payload"), b"0123456789").expect("payload");

    let bytes = clone_materialization_cap(CloneMaterializationGuard {
        root: &root,
        byte_cap: 9,
        entry_cap: 10,
    })
    .expect("materialization observation");
    assert_eq!(
        bytes,
        Some(CloneMaterializationCap::Bytes {
            observed: 10,
            cap: 9,
        })
    );
    assert_eq!(
        clone_materialization_cap(CloneMaterializationGuard {
            root: &root,
            byte_cap: 10,
            entry_cap: 1,
        })
        .expect("exact-cap observation"),
        None,
        "materialization exactly at both configured maxima remains valid"
    );

    let entries = clone_materialization_cap(CloneMaterializationGuard {
        root: &root,
        byte_cap: usize::MAX,
        entry_cap: 0,
    })
    .expect("materialization observation");
    assert_eq!(
        entries,
        Some(CloneMaterializationCap::Entries {
            observed: 1,
            cap: 0,
        })
    );
}

#[test]
fn limit_is_a_typed_truncation() {
    let error = clone_materialization_truncated(
        "github",
        "acme/rocket",
        CloneMaterializationCap::Bytes {
            observed: 11,
            cap: 10,
        },
        None,
    );
    match error {
        SourceError::Coverage {
            adapter,
            surface,
            target,
            kind,
            detail,
        } => {
            assert_eq!(adapter, "github");
            assert_eq!(surface, "clone");
            assert_eq!(target, "acme/rocket");
            assert_eq!(kind, SourceCoverageGapKind::Truncated);
            assert!(
                detail.contains("git_total_bytes")
                    && detail.contains("stopped")
                    && detail.contains("not scanned"),
                "truncation must explain the cap and incomplete coverage: {detail}"
            );
        }
        other => panic!("clone materialization cap must stay typed, got {other}"),
    }
}

#[cfg(unix)]
#[test]
fn guard_does_not_follow_symlinks() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("clone");
    std::fs::create_dir(&root).expect("clone root");
    let outside = temp.path().join("outside");
    std::fs::write(&outside, vec![b'x'; 4096]).expect("outside payload");
    symlink(&outside, root.join("link")).expect("symlink");

    let cap = outside.as_os_str().len() + 1;
    let result = clone_materialization_cap(CloneMaterializationGuard {
        root: &root,
        byte_cap: cap,
        entry_cap: 1,
    })
    .expect("materialization observation");
    assert_eq!(
        result, None,
        "the guard must count the symlink itself without traversing its target"
    );
}

#[cfg(unix)]
#[test]
fn cap_kills_and_reaps_the_child() {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("clone");
    std::fs::create_dir(&root).expect("clone root");
    let child = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("printf 0123456789 > \"$1/payload\"; while :; do :; done")
        .arg("keyhog-materialization-fixture")
        .arg(&root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("fixture child");
    let child_id = child.id();
    let started = Instant::now();
    let result = super::wait_for_command_with_timeout(
        child,
        None,
        None,
        Duration::from_secs(5),
        CloneMaterializationGuard {
            root: &root,
            byte_cap: 9,
            entry_cap: 10,
        },
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("oversized materialization must stop the clone child"),
    };

    assert!(
        matches!(
            error,
            super::HostedGitWaitError::MaterializationCap {
                cap: CloneMaterializationCap::Bytes {
                    observed: 10,
                    cap: 9
                },
                cleanup_error: None,
            }
        ),
        "unexpected wait error: {error:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "materialization guard must stop the child before the timeout"
    );
    if std::path::Path::new("/proc").is_dir() {
        assert!(
            !std::path::PathBuf::from(format!("/proc/{child_id}")).exists(),
            "materialization guard returned before child {child_id} was reaped"
        );
    }
}
