//! Regression: decoded provider-token matches inside a private-key block must
//! not displace the enclosing private-key finding during resolution.

mod support;

use keyhog_scanner::resolution::resolve_matches;
use support::contracts::{make_chunk, scanner};

const MIRROR_PGP_PRIVATE_KEY: &str =
    include_str!("../../../benchmarks/corpora/mirror/corpus/d7/mirror-pos-0001495.pem");
const DECODED_CHILD_GOOGLE_KEY: &str = "aIzaJBPI2n5UC64198Pt4qMGLqLHKvwsPonI4Lb";

#[test]
fn decoded_child_token_does_not_displace_enclosing_pgp_private_key() {
    let scanner = scanner();
    let chunk = make_chunk(
        MIRROR_PGP_PRIVATE_KEY,
        "filesystem",
        "/repo/private-key.pem",
    );
    scanner.clear_fragment_cache();
    let raw = scanner.scan(&chunk);

    assert!(
        raw.iter().any(|m| {
            m.detector_id.as_ref() == "private-key"
                && m.credential
                    .as_ref()
                    .starts_with("-----BEGIN PGP PRIVATE KEY BLOCK-----")
        }),
        "raw scanner output must include the enclosing private-key block: {raw:#?}"
    );

    let resolved = resolve_matches(raw);

    assert!(
        resolved.iter().any(|m| {
            m.detector_id.as_ref() == "private-key"
                && m.credential
                    .as_ref()
                    .starts_with("-----BEGIN PGP PRIVATE KEY BLOCK-----")
        }),
        "resolved output must keep the enclosing private-key block: {resolved:#?}"
    );
    assert!(
        !resolved.iter().any(|m| {
            m.detector_id.as_ref() == "google-api-key"
                && m.credential.as_ref() == DECODED_CHILD_GOOGLE_KEY
        }),
        "decoded child match inside the private-key block must not survive resolution: {resolved:#?}"
    );
}
