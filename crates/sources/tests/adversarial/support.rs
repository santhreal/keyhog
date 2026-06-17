//! Shared hostile oracles for adversarial source tests (Unix + Windows).

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub fn oracle_plain_file_symlink_refused() {
    let outer = tempfile::tempdir().expect("outer");
    std::fs::write(outer.path().join("target.env"), "TARGET=secret\n").expect("target");

    let root = tempfile::tempdir().expect("root");
    symlink_file(
        outer.path().join("target.env"),
        root.path().join("link.env"),
    )
    .expect("symlink");
    std::fs::write(root.path().join("real.txt"), "REAL=ok\n").expect("real");

    let paths: Vec<_> = FilesystemSource::new(root.path().to_path_buf())
        .chunks()
        .flatten()
        .filter_map(|c| c.metadata.path.clone())
        .collect();

    assert!(paths.iter().any(|p| p.ends_with("real.txt")));
    assert!(
        !paths.iter().any(|p| p.ends_with("link.env")),
        "symlinked plain file must be skipped, not followed; paths={paths:?}"
    );
}

pub fn oracle_walker_symlink_escape_outside_root() {
    let outer = tempfile::tempdir().expect("outer");
    std::fs::write(
        outer.path().join("outside_secret.env"),
        "OUTSIDE_LEAK=ghp_outsideRootMustNotBeRead000000000000\n",
    )
    .expect("outside secret");

    let root = tempfile::tempdir().expect("root");
    symlink_file(
        outer.path().join("outside_secret.env"),
        root.path().join("escape.env"),
    )
    .expect("symlink");
    std::fs::write(root.path().join("inside.txt"), "INSIDE=ok\n").expect("inside");

    let bodies: Vec<String> = FilesystemSource::new(root.path().to_path_buf())
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();

    assert!(bodies.iter().any(|b| b.contains("INSIDE=ok")));
    assert!(
        !bodies.iter().any(|b| b.contains("OUTSIDE_LEAK")),
        "symlink escape must not leak outside-root content; got {bodies:?}"
    );
}

pub fn oracle_permission_denied_subtree_scan_continues() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("open.txt"), "OPEN=visible\n").expect("open");

    let locked = dir.path().join("locked");
    std::fs::create_dir(&locked).expect("mkdir locked");
    std::fs::write(locked.join("secret.env"), "LOCKED=secret\n").expect("secret");
    deny_read_subtree(&locked).expect("deny locked subtree");

    let bodies: Vec<String> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();

    restore_read_subtree(&locked);

    assert!(
        bodies.iter().any(|b| b.contains("OPEN=visible")),
        "scan must continue past permission-denied subtree"
    );
    assert!(
        !bodies.iter().any(|b| b.contains("LOCKED=secret")),
        "permission-denied file must not be read"
    );
}

pub fn oracle_archive_symlink_target_swap_attempt() {
    use std::fs::File;
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    let staging = tempfile::tempdir().expect("staging");
    let benign = staging.path().join("benign.jar");
    let evil = staging.path().join("evil.jar");

    for (path, secret) in [
        (&benign, b"BENIGN=1\n" as &[u8]),
        (&evil, b"EVIL=AKIAQYLPMN5HFIQR7XYA\n" as &[u8]),
    ] {
        let file = File::create(path).expect("create");
        let mut zip = ZipWriter::new(file);
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zip.start_file("inner.env", opts).expect("start");
        zip.write_all(secret).expect("write");
        zip.finish().expect("finish");
    }

    let scan_root = tempfile::tempdir().expect("scan root");
    let link = scan_root.path().join("linked.jar");
    symlink_file(&benign, &link).expect("link benign");
    std::fs::remove_file(&link).expect("remove");
    symlink_file(&evil, &link).expect("link evil");

    let count = FilesystemSource::new(scan_root.path().to_path_buf())
        .chunks()
        .flatten()
        .count();
    assert_eq!(count, 0, "symlinked archive open must be refused entirely");
}

#[cfg(unix)]
fn symlink_file(
    src: impl AsRef<std::path::Path>,
    dst: impl AsRef<std::path::Path>,
) -> std::io::Result<()> {
    std::os::unix::fs::symlink(src, dst)
}

#[cfg(windows)]
fn symlink_file(
    src: impl AsRef<std::path::Path>,
    dst: impl AsRef<std::path::Path>,
) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(src, dst)
}

#[cfg(unix)]
fn deny_read_subtree(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000))
}

#[cfg(unix)]
fn restore_read_subtree(path: &std::path::Path) {
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

#[cfg(windows)]
fn deny_read_subtree(path: &std::path::Path) -> Result<(), String> {
    use std::process::Command;
    let username = std::env::var("USERNAME").map_err(|e| e.to_string())?;
    let deny = format!("{username}:(OI)(CI)(DENY)(R)");
    let status = Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/deny", &deny])
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("icacls deny failed with {status}"))
    }
}

#[cfg(windows)]
fn restore_read_subtree(path: &std::path::Path) {
    let _ = std::process::Command::new("icacls")
        .arg(path)
        .args(["/reset", "/T"])
        .status();
}
