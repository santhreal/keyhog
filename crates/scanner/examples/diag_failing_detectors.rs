use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;

fn main() {
    let specs = keyhog_core::embedded_detector_specs().to_vec();
    let scanner = CompiledScanner::compile(specs.clone()).expect("scanner compile");
    let mut runner = TestRunner::deterministic();

    for spec in specs.iter() {
        if format!("{:?}", spec.kind) != "Regex" { continue; }
        let Some(pat) = spec.patterns.first() else { continue; };

        // Try proptest generation
        let mut fired = false;
        if let Ok(strat) = proptest::string::string_regex(&pat.regex) {
            for _ in 0..8 {
                let Ok(tree) = strat.new_tree(&mut runner) else { continue; };
                let example = tree.current();
                let chunk = Chunk {
                    data: example.into(),
                    metadata: ChunkMetadata {
                        source_type: "corpus-ratchet".into(),
                        path: Some("s.txt".into()),
                        base_offset: 0,
                        ..Default::default()
                    },
                };
                if scanner.scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
                    .expect("scan").iter().flat_map(|c| c.iter()).any(|m| m.detector_id.as_ref() == spec.id.as_str()) {
                    fired = true;
                    break;
                }
            }
        }
        if fired { continue; }

        // Try test_positive fallback
        for test in &spec.tests {
            if let Some(positive) = &test.test_positive {
                let chunk = Chunk {
                    data: positive.clone().into(),
                    metadata: ChunkMetadata {
                        source_type: "corpus-ratchet".into(),
                        path: Some("s.txt".into()),
                        base_offset: 0,
                        ..Default::default()
                    },
                };
                if scanner.scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
                    .expect("scan").iter().flat_map(|c| c.iter()).any(|m| m.detector_id.as_ref() == spec.id.as_str()) {
                    fired = true;
                    break;
                }
            }
        }
        if !fired {
            eprintln!("STILL FAILING: {} regex={}", spec.id, pat.regex);
            if let Some(t) = spec.tests.first() {
                eprintln!("  test_positive: {:?}", t.test_positive);
            } else {
                eprintln!("  no test_positive");
            }
        }
    }
}
