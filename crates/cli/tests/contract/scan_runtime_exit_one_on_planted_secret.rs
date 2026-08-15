//! Contract: paranoid policy exits 1 when an unverified review finding exists.

use crate::support::scan_text_file;

#[test]
fn scan_runtime_paranoid_exit_one_on_planted_secret() {
    let (_stdout, _stderr, code) = scan_text_file(
        "AWS_ACCESS_KEY_ID = \"AKIAKPQXRMSNTBVWYZBN\"\n",
        &[
            "--no-suppress-test-fixtures",
            "--evidence-policy",
            "paranoid",
        ],
    );
    assert_eq!(code, Some(1));
}
