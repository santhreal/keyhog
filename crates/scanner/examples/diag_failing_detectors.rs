use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;

fn main() {
    let specs = keyhog_core::embedded_detector_specs().to_vec();
    let scanner = CompiledScanner::compile(specs.clone()).expect("scanner compile");
    let mut runner = TestRunner::deterministic();

    for spec in &specs {
        if format!("{:?}", spec.kind) != "Regex" {
            continue;
        }
        let Some(pattern) = spec.patterns.first() else {
            continue;
        };

        let mut fired = false;
        if let Ok(strategy) = proptest::string::string_regex(&pattern.regex) {
            for _ in 0..8 {
                let Ok(tree) = strategy.new_tree(&mut runner) else {
                    continue;
                };
                if detector_fires(&scanner, &spec.id, &tree.current(), "s.txt") {
                    fired = true;
                    break;
                }
            }
        }
        if fired {
            continue;
        }

        for test in &spec.tests {
            let Some(positive) = &test.test_positive else {
                continue;
            };
            let path = test.test_path.as_deref().unwrap_or("s.txt");
            if detector_fires(&scanner, &spec.id, positive, path) {
                fired = true;
                break;
            }
        }
        if !fired {
            eprintln!("STILL FAILING: detector_id={}", spec.id);
        }
    }
}

fn detector_fires(scanner: &CompiledScanner, detector_id: &str, data: &str, path: &str) -> bool {
    let chunk = Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            source_type: "corpus-ratchet".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .expect("scan")
        .iter()
        .flat_map(|chunks| chunks.iter())
        .any(|matched| matched.detector_id.as_ref() == detector_id)
}
