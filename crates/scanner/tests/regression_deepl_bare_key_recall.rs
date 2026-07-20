//! Regression: DeepL `uuid:fx` API keys are credential-sufficient.
//!
//! DeepL free API keys have a documented UUID-like body with a `:fx` suffix.
//! The detector previously required a DeepL keyword beside the value, so the
//! canonical credential failed the target-spec sufficiency partition. The bare
//! pattern must stay narrower than "any UUID-ish value with punctuation": a
//! plain UUID and a UUID with a non-DeepL suffix are not DeepL keys.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::OnceLock;

const DEEPL_FREE_KEY: &str = "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d:fx";
const PLAIN_UUID: &str = "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d";
const NON_DEEPL_SUFFIX: &str = "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d:debug";

fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
        CompiledScanner::compile(detectors).expect("compile scanner")
    })
}

fn matches_for(scanner: &CompiledScanner, body: &str) -> Vec<(String, String)> {
    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata {
            source_type: "deepl-bare-regression".into(),
            path: Some("notes/sufficiency-probe.txt".into()),
            ..Default::default()
        },
    };
    scanner.clear_fragment_cache();
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .map(|m| (m.detector_id.to_string(), m.credential.as_str().to_string()))
        .collect()
}

fn deepl_caught(matches: &[(String, String)], value: &str) -> bool {
    matches
        .iter()
        .any(|(id, credential)| id == "deepl-api-key" && credential == value)
}

fn deepl_fired(matches: &[(String, String)]) -> bool {
    matches.iter().any(|(id, _)| id == "deepl-api-key")
}

#[test]
fn bare_deepl_free_key_surfaces_without_context_anchor() {
    let matches = matches_for(scanner(), DEEPL_FREE_KEY);
    assert!(
        deepl_caught(&matches, DEEPL_FREE_KEY),
        "bare DeepL uuid:fx key must be credential-sufficient; matches={matches:?}"
    );
}

#[test]
fn deepl_free_key_surfaces_inside_common_value_contexts() {
    let scanner = scanner();
    for body in [
        format!("DEEPL_API_KEY={DEEPL_FREE_KEY}\n"),
        format!("service:\n  api_token: {DEEPL_FREE_KEY}\n"),
        format!("const auth = {{ key: \"{DEEPL_FREE_KEY}\" }};\n"),
    ] {
        let matches = matches_for(scanner, &body);
        assert!(
            deepl_caught(&matches, DEEPL_FREE_KEY),
            "DeepL uuid:fx key must surface in realistic value context; body={body:?}; matches={matches:?}"
        );
    }
}

#[test]
fn deepl_standard_key_surfaces_only_with_deepl_context() {
    let scanner = scanner();
    for body in [
        format!("DEEPL_API_KEY={PLAIN_UUID}\n"),
        format!("DEEPL_AUTH_KEY='{PLAIN_UUID}'\n"),
        format!("DeepL-Auth-Key {PLAIN_UUID}\n"),
    ] {
        let matches = matches_for(scanner, &body);
        assert!(
            deepl_caught(&matches, PLAIN_UUID),
            "DeepL standard UUID key must surface with DeepL context; body={body:?}; matches={matches:?}"
        );
    }
}

#[test]
fn bare_uuid_and_non_deepl_suffix_do_not_fire_deepl() {
    let scanner = scanner();
    for value in [PLAIN_UUID, NON_DEEPL_SUFFIX] {
        let matches = matches_for(scanner, value);
        assert!(
            !deepl_fired(&matches),
            "DeepL detector must not claim non-DeepL UUID shapes; value={value}; matches={matches:?}"
        );
    }
}
