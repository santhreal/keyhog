//! Adversarial (Unix): non-UTF-8 path components must fail with explicit stderr.

#[cfg(unix)]
#[test]
fn invalid_utf8_filename_rejected_unix() {
    crate::adversarial::support::oracle_invalid_utf8_filename_rejected();
}
