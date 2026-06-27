//! Regression: Caesar decode must not manufacture provider-token findings out
//! of encoded private-key payloads.

mod support;

use keyhog_scanner::resolution::resolve_matches;
use support::contracts::{make_chunk, scanner};

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

fn resolved_for(body: &str, path: &str) -> Vec<keyhog_core::RawMatch> {
    let scanner = scanner();
    let chunk = make_chunk(body, "filesystem", path);
    scanner.clear_fragment_cache();
    resolve_matches(scanner.scan(&chunk))
}

#[test]
fn malformed_k8s_private_key_payload_does_not_emit_google_child() {
    let Some(body) =
        mirror_corpus_or_skip("benchmarks/corpora/mirror/corpus/98/mirror-pos-0000920.yaml")
    else {
        return;
    };
    let resolved = resolved_for(&body, "/repo/google-key-secret.yaml");

    assert!(
        resolved
            .iter()
            .any(|m| m.detector_id.as_ref() == "ssh-private-key"),
        "private-key finding must remain: {resolved:#?}"
    );
    assert!(
        !resolved
            .iter()
            .any(|m| m.detector_id.as_ref() == "google-api-key"),
        "Caesar over encoded private-key payload must not emit google-api-key: {resolved:#?}"
    );
}

#[test]
fn malformed_k8s_private_key_payload_does_not_emit_confluent_child() {
    let Some(body) =
        mirror_corpus_or_skip("benchmarks/corpora/mirror/corpus/9b/mirror-pos-0002971.yaml")
    else {
        return;
    };
    let resolved = resolved_for(&body, "/repo/confluent-key-secret.yaml");

    assert!(
        resolved
            .iter()
            .any(|m| m.detector_id.as_ref() == "ssh-private-key"),
        "private-key finding must remain: {resolved:#?}"
    );
    assert!(
        !resolved
            .iter()
            .any(|m| m.detector_id.as_ref() == "confluent-cloud-api-key"),
        "Caesar over encoded private-key payload must not emit confluent-cloud-api-key: {resolved:#?}"
    );
}
