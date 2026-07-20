//! Contract: runtime exit 0 when no secrets are found.

use crate::support::scan_text_file;

#[test]
fn scan_runtime_exit_zero_on_clean_file() {
    let (_stdout, _stderr, code) = scan_text_file("nothing sensitive here\n", &[]);
    assert_eq!(code, Some(0));
}
