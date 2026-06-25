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

fn assert_alias_yaml_is_bounded_and_visible(
    scanner: &CompiledScanner,
    body: &str,
    path: &str,
    description: &str,
) {
    reset_for_scan();
    let matches = scan(scanner, body, path);
    assert!(
        matches.is_empty(),
        "{description} must fail closed without findings"
    );
    assert!(
        structured_parse_failure_count() > 0,
        "{description} rejection must be operator-visible as a structured parse failure"
    );
}

#[test]
fn structured_yaml_alias_rejections_are_bounded_and_visible() {
    let scanner = scanner();
    let compose_cycle = "\
services:
  web:
    environment: &env_anchor
      - *env_anchor
";
    assert_alias_yaml_is_bounded_and_visible(
        &scanner,
        compose_cycle,
        "/repo/docker-compose.yaml",
        "cyclic compose YAML aliases",
    );

    let compose_expansion = "\
services:
  web:
    x0: &x0 [lol,lol,lol,lol,lol,lol,lol,lol,lol]
    x1: &x1 [*x0,*x0,*x0,*x0,*x0,*x0,*x0,*x0,*x0]
    x2: &x2 [*x1,*x1,*x1,*x1,*x1,*x1,*x1,*x1,*x1]
    x3: &x3 [*x2,*x2,*x2,*x2,*x2,*x2,*x2,*x2,*x2]
    x4: &x4 [*x3,*x3,*x3,*x3,*x3,*x3,*x3,*x3,*x3]
    environment: *x4
";
    assert_alias_yaml_is_bounded_and_visible(
        &scanner,
        compose_expansion,
        "/repo/docker-compose.yaml",
        "alias-expanded compose YAML",
    );

    let k8s_cycle = "\
apiVersion: v1
kind: Secret
data: &data_anchor
  token: *data_anchor
";
    assert_alias_yaml_is_bounded_and_visible(
        &scanner,
        k8s_cycle,
        "/repo/secret.yaml",
        "cyclic k8s Secret YAML aliases",
    );
}
