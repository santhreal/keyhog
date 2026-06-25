mod support;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::telemetry::{reset_for_scan, structured_parse_failure_count};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use support::paths::detector_dir;

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    CompiledScanner::compile(detectors).expect("compile scanner")
}

fn scan(scanner: &CompiledScanner, body: &str, path: &str) -> Vec<RawMatch> {
    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some(path.into()),
            ..Default::default()
        },
    };
    scanner.clear_fragment_cache();
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .collect()
}

#[test]
fn docker_compose_cyclic_alias_yaml_is_bounded() {
    reset_for_scan();
    let scanner = scanner();
    let text = "\
services:
  web:
    environment: &env_anchor
      - *env_anchor
";
    let matches = scan(&scanner, text, "/repo/docker-compose.yaml");
    assert!(
        matches.is_empty(),
        "cyclic compose YAML aliases must fail closed without findings"
    );
    assert!(
        structured_parse_failure_count() > 0,
        "cyclic compose YAML rejection must be operator-visible as a structured parse failure"
    );
}

#[test]
fn docker_compose_alias_expansion_yaml_is_bounded() {
    reset_for_scan();
    let scanner = scanner();
    let text = "\
services:
  web:
    x0: &x0 [lol,lol,lol,lol,lol,lol,lol,lol,lol]
    x1: &x1 [*x0,*x0,*x0,*x0,*x0,*x0,*x0,*x0,*x0]
    x2: &x2 [*x1,*x1,*x1,*x1,*x1,*x1,*x1,*x1,*x1]
    x3: &x3 [*x2,*x2,*x2,*x2,*x2,*x2,*x2,*x2,*x2]
    x4: &x4 [*x3,*x3,*x3,*x3,*x3,*x3,*x3,*x3,*x3]
    environment: *x4
";
    let matches = scan(&scanner, text, "/repo/docker-compose.yaml");
    assert!(
        matches.is_empty(),
        "alias-expanded compose YAML must not exhaust parser traversal"
    );
    assert!(
        structured_parse_failure_count() > 0,
        "alias expansion rejection must be operator-visible as a structured parse failure"
    );
}

#[test]
fn k8s_secret_cyclic_alias_yaml_is_bounded() {
    reset_for_scan();
    let scanner = scanner();
    let text = "\
apiVersion: v1
kind: Secret
data: &data_anchor
  token: *data_anchor
";
    let matches = scan(&scanner, text, "/repo/secret.yaml");
    assert!(
        matches.is_empty(),
        "cyclic k8s Secret YAML aliases must fail closed without findings"
    );
    assert!(
        structured_parse_failure_count() > 0,
        "cyclic k8s Secret YAML rejection must be operator-visible as a structured parse failure"
    );
}
