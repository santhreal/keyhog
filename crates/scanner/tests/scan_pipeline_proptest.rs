//! Property/fuzz over the full SCAN pipeline (#177/#184). The scanner runs on
//! attacker-controlled bytes, so the load-bearing invariants are: (1) it NEVER
//! panics on arbitrary input, (2) every finding's offset is within the scanned
//! text, and (3) a real secret planted in bounded random noise is always
//! recovered (recall robustness). The compiled scanner is built once per test
//! thread (thread_local) and reused across cases. ML-independent; run without
//! `ml` while the embedded weights are mid-retrain.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use proptest::prelude::*;
use std::sync::LazyLock;

// One shared compiled scanner for the whole test binary (CompiledScanner is Sync
//: its caches are Mutex/atomic-backed). Reused across all proptest cases.
static SCANNER: LazyLock<CompiledScanner> = LazyLock::new(|| {
    CompiledScanner::compile(keyhog_core::embedded_detector_specs().to_vec())
        .expect("scanner compile")
});

struct Hit {
    offset: usize,
    credential: String,
}

fn scan(text: &str) -> Vec<Hit> {
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "fuzz".into(),
            path: Some("s.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    SCANNER
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .iter()
        .flat_map(|per_chunk| per_chunk.iter())
        .map(|m| Hit {
            offset: m.location.offset,
            credential: m.credential.as_ref().to_string(),
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    /// The scan pipeline must never panic on arbitrary text.
    #[test]
    fn scan_never_panics_on_arbitrary_text(s in "\\PC{0,400}") {
        let _ = scan(&s);
    }

    /// Bias toward secret-shaped bytes (base64/hex alphabet, separators, unicode
    /// obfuscation) to reach deep into the detect/decode/normalize paths.
    #[test]
    fn scan_never_panics_on_secret_shaped_noise(
        s in "[A-Za-z0-9+/=_\\-.:@ \t\n\u{200B}\u{FF21}%]{0,400}"
    ) {
        let _ = scan(&s);
    }

    /// Every reported finding must sit within the scanned text.
    #[test]
    fn finding_offsets_are_within_bounds(s in "[A-Za-z0-9 _\\-=:/]{0,300}") {
        let len = s.len();
        for hit in scan(&s) {
            prop_assert!(hit.offset <= len, "offset {} exceeds text len {len}", hit.offset);
        }
    }

    /// A real AWS key planted in bounded random noise (space-delimited so it is a
    /// clean 20-char token) must always be recovered, recall robustness under
    /// arbitrary surrounding context.
    #[test]
    fn planted_aws_key_is_recovered_amid_noise(
        prefix in "[ -~]{0,80}",
        suffix in "[ -~]{0,80}",
    ) {
        let text = format!("{prefix} AKIAQYLPMN5HFIQR7BBB {suffix}");
        let hits = scan(&text);
        prop_assert!(
            hits.iter().any(|h| h.credential == "AKIAQYLPMN5HFIQR7BBB"),
            "planted AWS key not recovered in {text:?}; got: {:?}",
            hits.iter().map(|h| &h.credential).collect::<Vec<_>>()
        );
    }
}
