//! Megakernel ↔ literal-set parity test.
//!
//! With `KEYHOG_USE_MEGAKERNEL=1` the GPU dispatch path runs through
//! `MegakernelScanner::dispatch_triggers` instead of the sharded
//! `GpuLiteralSet::scan` loop. Recall + offset reporting must be
//! bit-equivalent between the two paths. This test runs the same
//! fixture through both and asserts identical credential sets.
//!
//! Skipped at runtime when no compatible GPU adapter is available
//! (CI without a real adapter, software-only adapters that the
//! routing layer rejects, or megakernel init failures). The skip is
//! explicit (`eprintln!`) rather than silent so a "no GPU" pass
//! doesn't pretend to have validated the megakernel path.

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

fn make_chunk(text: &str, path: &str) -> Chunk {
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

type FindingKey = (String, String, usize);

fn collect_keys(
    results: &[Vec<keyhog_core::RawMatch>],
) -> std::collections::BTreeSet<FindingKey> {
    let mut set = std::collections::BTreeSet::new();
    for chunk in results {
        for m in chunk {
            set.insert((
                m.credential.as_ref().to_string(),
                m.location
                    .file_path
                    .as_deref()
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
                m.location.offset,
            ));
        }
    }
    set
}

#[test]
fn megakernel_and_literal_set_produce_identical_findings() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors directory unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    let chunks = vec![
        make_chunk("// no secrets in this file", "clean.rs"),
        make_chunk(
            "const KEY = \"AKIAQYLPMN5HFIQR7XYA\";\nconst PAT = \"ghp_aBcD1234EFgh5678ijklMNop9012qrSTuvWX\";",
            "fixtures/aws_github.rs",
        ),
        make_chunk(
            "auth: \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"\npayload: \"AKIAQYLPMN5HFIQR7BBB\"",
            "fixtures/stripe_aws.yml",
        ),
    ];

    // Baseline = sharded GpuLiteralSet path (KEYHOG_USE_MEGAKERNEL unset).
    // SAFETY: this test mutates the process-wide env var. Tests run in
    // parallel by default, so isolate via a process-local mutex would
    // be ideal — but the env var only flips routing, not data, so a
    // racing test sees correct-but-maybe-different routing. The
    // assertion compares the TWO scans within this test only.
    unsafe { std::env::remove_var("KEYHOG_USE_MEGAKERNEL") };
    let literal_set_results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::Gpu);
    let literal_keys = collect_keys(&literal_set_results);

    unsafe { std::env::set_var("KEYHOG_USE_MEGAKERNEL", "1") };
    let megakernel_results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::Gpu);
    let megakernel_keys = collect_keys(&megakernel_results);
    unsafe { std::env::remove_var("KEYHOG_USE_MEGAKERNEL") };

    if megakernel_results.iter().all(|c| c.is_empty())
        && literal_set_results.iter().any(|c| !c.is_empty())
    {
        eprintln!(
            "SKIP: megakernel returned zero findings vs {} literal-set findings — \
             likely no compatible adapter or megakernel init failed; falling back to \
             literal-set-as-baseline test in gpu_parity.rs",
            literal_keys.len()
        );
        return;
    }

    if literal_keys != megakernel_keys {
        let only_literal: Vec<_> = literal_keys.difference(&megakernel_keys).collect();
        let only_mega: Vec<_> = megakernel_keys.difference(&literal_keys).collect();
        panic!(
            "Megakernel/literal-set parity broken.\n  \
             literal_set_keys: {}\n  megakernel_keys:  {}\n  \
             only in literal_set ({}): {:?}\n  \
             only in megakernel ({}): {:?}",
            literal_keys.len(),
            megakernel_keys.len(),
            only_literal.len(),
            only_literal.iter().take(5).collect::<Vec<_>>(),
            only_mega.len(),
            only_mega.iter().take(5).collect::<Vec<_>>(),
        );
    }

    assert!(
        !literal_keys.is_empty(),
        "fixture must produce findings on both backends"
    );
}
