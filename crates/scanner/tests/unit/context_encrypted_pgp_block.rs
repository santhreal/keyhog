//! PGP encrypted blocks within lookback infer Encrypted context.

use keyhog_scanner::context::{infer_context, CodeContext};

#[test]
fn context_encrypted_pgp_block() {
    let lines = vec![
        "-----BEGIN PGP MESSAGE-----",
        "Version: OpenPGP",
        "hQEMAw...",
    ];
    assert_eq!(
        infer_context(&lines, 2, None),
        CodeContext::Encrypted,
        "lines after PGP header must be encrypted context"
    );
}
