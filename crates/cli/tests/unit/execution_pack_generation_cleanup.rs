use super::*;

const DEAD_PID: u32 = u32::MAX;

fn artifact(output: &Path, kind: &str, pid: u32) -> PathBuf {
    let name = output
        .file_name()
        .and_then(|name| name.to_str())
        .expect("UTF-8 output name");
    output.with_file_name(format!(".{name}.{kind}.{pid}"))
}

#[test]
fn unique_siblings_bind_output_kind_and_process() {
    let output = Path::new("/cache/keyhog/execution-packs/current");
    assert_eq!(
        unique_sibling(output, "stage"),
        output.with_file_name(format!(".current.stage.{}", std::process::id()))
    );
    assert_eq!(
        unique_sibling(output, "backup"),
        output.with_file_name(format!(".current.backup.{}", std::process::id()))
    );
}

#[test]
fn stale_stage_and_replaced_backup_are_removed_without_touching_other_entries() {
    let root = tempfile::tempdir().expect("temporary pack parent");
    let output = root.path().join("current");
    let stage = artifact(&output, "stage", DEAD_PID);
    let backup = artifact(&output, "backup", DEAD_PID);
    let unrelated = root.path().join(".current.stage.not-a-pid");
    fs::create_dir(&output).expect("current generation");
    fs::create_dir(&stage).expect("stale stage");
    fs::create_dir(&backup).expect("stale backup");
    fs::create_dir(&unrelated).expect("unrelated entry");

    reap_stale_generation_siblings(&output).expect("reap stale siblings");

    assert!(output.is_dir());
    assert!(!stage.exists());
    assert!(!backup.exists());
    assert!(unrelated.is_dir());
}

#[test]
fn one_stale_backup_recovers_a_missing_generation_exactly() {
    let root = tempfile::tempdir().expect("temporary pack parent");
    let output = root.path().join("current");
    let backup = artifact(&output, "backup", DEAD_PID);
    fs::create_dir(&backup).expect("stale backup");
    fs::write(backup.join("manifest.json"), b"previous-generation").expect("backup manifest");

    reap_stale_generation_siblings(&output).expect("recover stale backup");

    assert_eq!(
        fs::read(output.join("manifest.json")).expect("recovered manifest"),
        b"previous-generation"
    );
    assert!(!backup.exists());
}

#[test]
fn multiple_stale_backups_fail_closed_without_deleting_evidence() {
    let root = tempfile::tempdir().expect("temporary pack parent");
    let output = root.path().join("current");
    let first = artifact(&output, "backup", DEAD_PID);
    let second = artifact(&output, "backup", DEAD_PID - 1);
    fs::create_dir(&first).expect("first backup");
    fs::create_dir(&second).expect("second backup");

    let error = reap_stale_generation_siblings(&output).expect_err("ambiguous backups must fail");

    assert!(error
        .to_string()
        .contains("multiple stale execution-pack backups"));
    assert!(!output.exists());
    assert!(first.is_dir());
    assert!(second.is_dir());
}

#[cfg(unix)]
#[test]
fn stale_symlink_is_rejected_without_following_or_deleting_its_target() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("temporary pack parent");
    let output = root.path().join("current");
    let target = root.path().join("outside");
    let stage = artifact(&output, "stage", DEAD_PID);
    fs::create_dir(&target).expect("symlink target");
    fs::write(target.join("keep"), b"untouched").expect("target fixture");
    symlink(&target, &stage).expect("stale stage symlink");

    let error = reap_stale_generation_siblings(&output).expect_err("symlink must fail closed");

    assert!(error.to_string().contains("is not a real directory"));
    assert_eq!(
        fs::read(target.join("keep")).expect("target remains"),
        b"untouched"
    );
    assert!(stage
        .symlink_metadata()
        .expect("symlink remains")
        .file_type()
        .is_symlink());
}
