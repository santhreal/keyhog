//! Deep directory nesting must not stack-overflow the walker.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn deeply_nested_dirs_scan_continues() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut path = dir.path().to_path_buf();
    for i in 0..32 {
        path.push(format!("d{i}"));
        std::fs::create_dir(&path).expect("mkdir");
    }
    std::fs::write(path.join("deep.txt"), "DEEP=found\n").expect("deep");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "deep directory traversal should not emit SourceError rows: {errors:?}"
    );
    assert!(
        chunks.iter().any(|chunk| chunk.data.contains("DEEP=found")
            && chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|path| path.ends_with("deep.txt"))),
        "deep leaf file must scan with path metadata; chunks={chunks:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn path_beyond_path_max_scans_descriptor_relative() {
    use std::ffi::CString;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let mut directory = std::fs::File::open(dir.path()).expect("open fixture root");
    let child = CString::new("d").expect("static child component");
    let mut logical_directory = dir.path().to_path_buf();
    for _ in 0..2100 {
        let status = unsafe { libc::mkdirat(directory.as_raw_fd(), child.as_ptr(), 0o700) };
        assert_eq!(
            status,
            0,
            "create descriptor-relative fixture directory: {}",
            std::io::Error::last_os_error()
        );
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                child.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        assert!(
            fd >= 0,
            "open descriptor-relative fixture directory: {}",
            std::io::Error::last_os_error()
        );
        directory = unsafe { std::fs::File::from_raw_fd(fd) };
        logical_directory.push("d");
    }

    let leaf = CString::new("deep.txt").expect("static leaf component");
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o600,
        )
    };
    assert!(
        fd >= 0,
        "create descriptor-relative fixture file: {}",
        std::io::Error::last_os_error()
    );
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(b"DEEP=descriptor-relative\n")
        .expect("write descriptor-relative fixture");
    drop(file);

    let logical_leaf = logical_directory.join("deep.txt");
    assert!(
        logical_leaf.as_os_str().len() > libc::PATH_MAX as usize,
        "fixture must exceed the pathname syscall limit"
    );
    let logical_leaf_display = logical_leaf.to_string_lossy().into_owned();
    // The pathname walk sees this before it reaches the overlong leaf. A
    // successful descriptor rebuild must replace, not duplicate, that partial
    // archive-symlink classification.
    let archive_link = dir.path().join("credentials.zip");
    symlink("/etc/hostname", &archive_link).expect("create archive symlink");
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert_eq!(
        errors.len(),
        1,
        "descriptor replacement must retain one archive-symlink refusal: {errors:?}"
    );
    let refusal = format!("{:#}", errors[0]);
    let archive_display = archive_link.to_string_lossy();
    assert!(
        refusal.contains(archive_display.as_ref())
            && refusal.contains("archive symlink expansion is blocked"),
        "descriptor replacement must preserve the exact archive refusal: {refusal}"
    );
    assert!(
        chunks.iter().any(|chunk| {
            chunk.data.contains("DEEP=descriptor-relative")
                && chunk.metadata.path.as_deref() == Some(logical_leaf_display.as_str())
        }),
        "overlong leaf must scan with exact path metadata; chunks={chunks:?}"
    );
}
