use super::support;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn scanner() -> CompiledScanner {
    let detectors =
        keyhog_core::load_detectors(&support::paths::detector_dir()).expect("detectors");
    CompiledScanner::compile(detectors).expect("compile")
}

#[test]
fn generic_bridge_does_not_echo_named_ml_pending_line() {
    let scanner = scanner();
    let secret = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
    let chunk = Chunk {
        data: format!("const api_key = \"{secret}\";\n").into(),
        metadata: ChunkMetadata {
            source_type: "unit".into(),
            path: Some("src/payments.rs".into()),
            base_offset: 0,
            ..Default::default()
        },
    };

    let matches = scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    assert!(
        matches.iter().any(|m| {
            m.detector_id.as_ref() == "stripe-secret-key" && m.credential.as_ref() == secret
        }),
        "named stripe detector must still surface; matches={matches:?}"
    );
    assert!(
        !matches.iter().any(|m| {
            m.detector_id.as_ref() == "generic-secret" && m.location.line == Some(1)
        }),
        "generic bridge must not echo a line already covered by a named detector; matches={matches:?}"
    );
}

#[test]
fn stripe_direct_prefix_path_preserves_same_line_multiple_tokens() {
    let scanner = scanner();
    let live = "sk_live_AbCdEfGhIjKlMnOpQrStUvWx";
    let restricted = "rk_live_ZyXwVuTsRqPoNmLkJiHgFeDc";
    let chunk = Chunk {
        data: format!("let live = \"{live}\"; let restricted = \"{restricted}\";\n").into(),
        metadata: ChunkMetadata {
            source_type: "unit".into(),
            path: Some("src/payments.rs".into()),
            base_offset: 0,
            ..Default::default()
        },
    };

    let matches = scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    let stripe_credentials: std::collections::HashSet<&str> = matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == "stripe-secret-key")
        .map(|m| m.credential.as_ref())
        .collect();
    assert!(
        stripe_credentials.contains(live) && stripe_credentials.contains(restricted),
        "same-line Stripe hot-prefix coverage must not hide either token; matches={matches:?}"
    );
}
