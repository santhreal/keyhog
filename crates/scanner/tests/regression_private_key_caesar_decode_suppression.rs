//! Regression: Caesar decode must not manufacture provider-token findings out
//! of encoded private-key payloads.

mod support;

use keyhog_scanner::resolution::resolve_matches;
use support::contracts::{make_chunk, scanner};

const K8S_PRIVATE_KEY_GOOGLE_FP: &str =
    include_str!("../../../benchmarks/corpora/mirror/corpus/98/mirror-pos-0000920.yaml");
const K8S_PRIVATE_KEY_CONFLUENT_FP: &str =
    include_str!("../../../benchmarks/corpora/mirror/corpus/9b/mirror-pos-0002971.yaml");

fn resolved_for(body: &str, path: &str) -> Vec<keyhog_core::RawMatch> {
    let scanner = scanner();
    let chunk = make_chunk(body, "filesystem", path);
    scanner.clear_fragment_cache();
    resolve_matches(scanner.scan(&chunk))
}

#[test]
fn malformed_k8s_private_key_payload_does_not_emit_google_child() {
    let resolved = resolved_for(K8S_PRIVATE_KEY_GOOGLE_FP, "/repo/google-key-secret.yaml");

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
    let resolved = resolved_for(
        K8S_PRIVATE_KEY_CONFLUENT_FP,
        "/repo/confluent-key-secret.yaml",
    );

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
