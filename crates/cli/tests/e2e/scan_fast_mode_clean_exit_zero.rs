//! E2E: `--fast` scan of clean file exits 0.

use crate::e2e::support::scan_text_file;

#[test]
fn scan_fast_mode_clean_exit_zero() {
    let (_, _, code) = scan_text_file("fn main() {}\n", &["--fast"]);
    assert_eq!(code, Some(0));
}
