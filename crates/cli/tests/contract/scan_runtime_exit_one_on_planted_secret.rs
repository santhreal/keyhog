//! Contract: runtime exit 1 when unverified findings exist.

use crate::support::scan_text_file;

#[test]
fn scan_runtime_exit_one_on_planted_secret() {
    let (_stdout, _stderr, code) = scan_text_file(
        "AWS_ACCESS_KEY_ID = \"AKIAKPQXRMSNTBVWYZBN\"\n",
        &["--no-suppress-test-fixtures"],
    );
    assert_eq!(code, Some(1));
}
