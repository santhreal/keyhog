//! Regression: decoded provider-token matches inside a private-key block must
//! not displace the enclosing private-key finding during resolution.

mod support;

use keyhog_scanner::resolution::resolve_matches;
use support::contracts::{make_chunk, scanner};

const DECODED_CHILD_GOOGLE_KEY: &str = "aIzaJBPI2n5UC64198Pt4qMGLqLHKvwsPonI4Lb";

/// Read a mirror-corpus fixture at RUNTIME rather than via `include_str!`. The
/// mirror corpus is gitignored and local-only, so `include_str!` made the whole
/// standalone test binary fail to COMPILE in CI (the Integration-test-aggregators
/// job builds every test target). Reading at runtime keeps full fidelity where
/// the corpus is checked out and degrades to a LOUD skip where it is absent —
/// never a silent pass, never a compile error that takes the binary down.
fn mirror_corpus_or_skip(rel: &str) -> Option<String> {
    let path = format!("{}/../../{rel}", env!("CARGO_MANIFEST_DIR"));
    match std::fs::read_to_string(&path) {
        Ok(body) => Some(body),
        Err(error) => {
            eprintln!(
                "SKIP {}: mirror corpus fixture {rel} absent ({error}); gitignored \
                 local-only corpus, so this regression runs only where it is present.",
                module_path!()
            );
            None
        }
    }
}

#[test]
fn decoded_child_token_does_not_displace_enclosing_pgp_private_key() {
    let Some(body) =
        mirror_corpus_or_skip("benchmarks/corpora/mirror/corpus/d7/mirror-pos-0001495.pem")
    else {
        return;
    };
    let scanner = scanner();
    let chunk = make_chunk(&body, "filesystem", "/repo/private-key.pem");
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
