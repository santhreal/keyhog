//! KH-GAP-001: Megakernel and literal-set GPU paths must produce identical findings.
//! Fails until vyre per-pattern hit reporting closes the recall gap.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::path::PathBuf;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

fn chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

type Key = (String, String, usize);

fn keys(results: &[Vec<keyhog_core::RawMatch>]) -> std::collections::BTreeSet<Key> {
    results
        .iter()
        .flatten()
        .map(|m| {
            (
                m.credential.as_ref().to_string(),
                m.location
                    .file_path
                    .as_deref()
                    .unwrap_or("")
                    .to_string(),
                m.location.offset,
            )
        })
        .collect()
}

#[test]
fn megakernel_literal_set_parity() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors load");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    let chunks = vec![
        chunk(
            "const KEY = \"AKIAQYLPMN5HFIQR7XYA\";\nconst PAT = \"ghp_aBcD1234EFgh5678ijklMNop9012qrSTuvWX\";",
            "fixtures/aws_github.rs",
        ),
        chunk(
            "auth: \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"\npayload: \"AKIAQYLPMN5HFIQR7BBB\"",
            "fixtures/stripe_aws.yml",
        ),
    ];

    unsafe { std::env::remove_var("KEYHOG_USE_MEGAKERNEL") };
    let literal = keys(&scanner.scan_chunks_with_backend(&chunks, ScanBackend::Gpu));

    unsafe { std::env::set_var("KEYHOG_USE_MEGAKERNEL", "1") };
    let mega = keys(&scanner.scan_chunks_with_backend(&chunks, ScanBackend::Gpu));
    unsafe { std::env::remove_var("KEYHOG_USE_MEGAKERNEL") };

    assert!(
        !literal.is_empty(),
        "literal-set baseline must fire on fixture corpus"
    );

    if mega.is_empty() && !literal.is_empty() {
        panic!(
            "KH-GAP-001: megakernel returned zero findings vs {} literal-set keys — \
             GPU path must not silently lose recall",
            literal.len()
        );
    }

    assert_eq!(
        literal, mega,
        "KH-GAP-001: megakernel/literal-set divergence — only_literal={:?} only_mega={:?}",
        literal.difference(&mega).collect::<Vec<_>>(),
        mega.difference(&literal).collect::<Vec<_>>()
    );
}
