use super::read_file_safe_bytes;
use crate::filesystem::special_file_test_support::{
    make_fifo, symlink_to, within_timeout, write_regular,
};
use std::io::ErrorKind;

// A regular file reads back byte-for-byte (the guarded read is a drop-in
// replacement for `std::fs::read` on the happy path (no recall loss)).
#[test]
fn reads_a_regular_file_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_regular(dir.path(), "cfg.txt", b"api_key=ABCDEF0123456789");
    let bytes = read_file_safe_bytes(&path, 0).expect("regular file must read");
    assert_eq!(bytes, b"api_key=ABCDEF0123456789");
}

// The core watch-daemon fix: a writer-less FIFO must be REFUSED with
// `InvalidInput` and the call must RETURN (the watchdog proves it did not
// hang, which a missing `O_NONBLOCK` would cause). Before the fix a raw
// `std::fs::read` on this path blocked the single watcher thread forever.
#[test]
fn refuses_a_fifo_without_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = make_fifo(dir.path(), "pipe");
    let kind = within_timeout(move || {
        read_file_safe_bytes(&fifo, 0)
            .expect_err("a FIFO must be refused, not read")
            .kind()
    });
    assert_eq!(kind, ErrorKind::InvalidInput);
}

// `O_NOFOLLOW`: a symlink pointing at a secret outside the watched tree is
// refused, and the secret's bytes are never returned (no info-leak / no
// read-outside-root divergence from `scan`). The target itself IS readable,
// proving the refusal is the link, not the content.
#[test]
fn refuses_a_symlink_and_never_leaks_the_target() {
    let dir = tempfile::tempdir().unwrap();
    let secret = write_regular(dir.path(), "secret", b"aws_secret_access_key_LEAK");
    let link = symlink_to(dir.path(), "link", &secret);
    let result = read_file_safe_bytes(&link, 0);
    assert!(result.is_err(), "a symlink must be refused (O_NOFOLLOW)");
    // The target is a normal file and reads fine, so the refusal above is
    // the link, not an unreadable target.
    assert_eq!(
        read_file_safe_bytes(&secret, 0).unwrap(),
        b"aws_secret_access_key_LEAK"
    );
}

// A path that vanished before the read (the benign inotify race) surfaces as
// `NotFound`, which `scan_file` deliberately swallows quietly.
#[test]
fn missing_file_is_notfound() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("does-not-exist");
    assert_eq!(
        read_file_safe_bytes(&path, 0).unwrap_err().kind(),
        ErrorKind::NotFound
    );
}
