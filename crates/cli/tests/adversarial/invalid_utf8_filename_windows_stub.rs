//! Windows stub: byte-path UTF-8 preflight is Unix-specific; wide-char paths use the unicode oracle.

#[cfg(unix)]
#[test]
fn invalid_utf8_filename_windows_stub() {
    crate::adversarial::support::oracle_invalid_utf8_filename_rejected();
}

#[cfg(not(unix))]
#[test]
fn invalid_utf8_filename_windows_stub() {
    crate::adversarial::support::oracle_unicode_path_scan();
}
