#![cfg(feature = "simd")]

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::hw_probe::ScanBackend;
use keyhog_scanner::CompiledScanner;

const CHILD_ENV: &str = "KEYHOG_COALESCED_TELEMETRY_CHILD";
const TEST_NAME: &str =
    "regression_coalesced_telemetry::coalesced_simd_records_each_input_file_and_byte_once";

fn run_isolated_counter_oracle() {
    let scanner = CompiledScanner::compile(keyhog_core::embedded_detector_specs().to_vec())
        .expect("compile embedded detectors");
    let chunks = ["ordinary source text", "another plain source"]
        .into_iter()
        .enumerate()
        .map(|(index, data)| Chunk {
            data: data.into(),
            metadata: ChunkMetadata {
                source_type: "telemetry-test".into(),
                path: Some(format!("input-{index}.txt").into()),
                ..Default::default()
            },
        })
        .collect::<Vec<_>>();
    let expected_bytes = chunks.iter().map(|chunk| chunk.data.len()).sum::<usize>();

    keyhog_scanner::telemetry::reset_for_scan();
    let results = scanner.scan_coalesced_with_backend(&chunks, ScanBackend::SimdCpu);

    assert_eq!(results.len(), chunks.len());
    assert_eq!(
        keyhog_scanner::testing::telemetry_scan_counts(),
        (chunks.len(), expected_bytes)
    );
}

#[test]
fn coalesced_simd_records_each_input_file_and_byte_once() {
    if std::env::var_os(CHILD_ENV).is_some() {
        run_isolated_counter_oracle();
        return;
    }

    let output = std::process::Command::new(
        std::env::current_exe().expect("current scanner test executable is available"),
    )
    .env(CHILD_ENV, "1")
    .arg(TEST_NAME)
    .arg("--exact")
    .arg("--test-threads=1")
    .arg("--nocapture")
    .output()
    .expect("isolated telemetry test process starts");
    assert!(
        output.status.success(),
        "isolated telemetry test failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
