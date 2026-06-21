//! Law 10 regression: a file that MATCHES a structured format but fails to parse
//! must be COUNTED (not just `tracing::debug!`-logged, which is filtered out at
//! default verbosity) so the scan can surface the lost decode-through at
//! completion. Before this, a malformed k8s Secret / tfstate / notebook /
//! docker-compose silently dropped the secrets encoded inside it with no
//! operator-visible trace.
//!
//! Own test binary so the process-global telemetry counter is isolated from the
//! parallel `all_tests` pool - the assertions are exact counts, not deltas.

mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::telemetry::{reset_for_scan, structured_parse_failure_count};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use support::paths::detector_dir;

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    CompiledScanner::compile(detectors).expect("compile scanner")
}

fn scan(scanner: &CompiledScanner, body: &str, path: &str) {
    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some(path.into()),
            ..Default::default()
        },
    };
    scanner.clear_fragment_cache();
    let _ =
        scanner.scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback);
}

#[test]
fn malformed_structured_files_are_counted_valid_ones_are_not() {
    reset_for_scan();
    assert_eq!(
        structured_parse_failure_count(),
        0,
        "a fresh telemetry state has counted no parse failures"
    );
    let scanner = scanner();

    // Malformed YAML (unclosed flow sequence) routed through the k8s Secret
    // parser: must fail AND bump the failure counter.
    let bad_k8s = "apiVersion: v1\nkind: Secret\ndata:\n  api-key: [unclosed\n";
    scan(&scanner, bad_k8s, "/repo/bad-secret.yaml");
    assert_eq!(
        structured_parse_failure_count(),
        1,
        "the malformed k8s Secret must be counted as a parse failure (Law 10 \
         decode-through coverage gap)"
    );

    // Malformed tfstate JSON and docker-compose YAML each add one more.
    scan(&scanner, "{ not valid json ,, }", "/repo/terraform.tfstate");
    assert_eq!(
        structured_parse_failure_count(),
        2,
        "a malformed tfstate JSON must also be counted"
    );
    scan(
        &scanner,
        "services:\n  web:\n    environment: [oops\n",
        "/repo/docker-compose.yaml",
    );
    assert_eq!(
        structured_parse_failure_count(),
        3,
        "a malformed docker-compose YAML must also be counted"
    );

    let mixed_jupyter = r#"{"cells":[{"cell_type":"code","source":["token = ","ghp_abcdefghij0123456789",{"bad":true}]}]}"#;
    scan(&scanner, mixed_jupyter, "/repo/notebook.ipynb");
    assert_eq!(
        structured_parse_failure_count(),
        4,
        "a mixed-type Jupyter source array loses one decode-through fragment and must be counted"
    );

    // A VALID k8s Secret parses cleanly: the counter must NOT move, so the
    // warning only fires on genuine coverage gaps, never on healthy files.
    let good_k8s =
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\ndata:\n  api-key: YWJjMTIz\n";
    scan(&scanner, good_k8s, "/repo/good-secret.yaml");
    assert_eq!(
        structured_parse_failure_count(),
        4,
        "a successfully-parsed structured file must NOT increment the failure \
         counter (no false coverage-gap warning)"
    );
}
