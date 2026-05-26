//! SOPS markers within lookback infer Encrypted context.

use keyhog_scanner::context::{infer_context, CodeContext};

#[test]
fn context_encrypted_sops_marker() {
    let lines = vec!["sops:", "  encrypted_regex: ^data$", "  token: ghp_abc"];
    assert_eq!(
        infer_context(&lines, 2, None),
        CodeContext::Encrypted,
        "sops: marker within lookback marks encrypted context"
    );
}
