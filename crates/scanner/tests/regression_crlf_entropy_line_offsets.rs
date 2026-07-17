//! Regression: source credential offsets must stay byte-accurate on CRLF input
//! after generic and entropy candidates resolve to one finding.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};

const SECRET: &str = "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL";

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    CompiledScanner::compile(detectors)
        .expect("compile scanner")
        .with_config(ScannerConfig::default().min_confidence(0.40))
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

fn credential_hit<'a>(matches: &'a [RawMatch], credential: &str) -> &'a RawMatch {
    let hits: Vec<&RawMatch> = matches
        .iter()
        .filter(|m| m.credential.as_ref() == credential)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one resolved finding for {credential:?}, matches={matches:#?}"
    );
    hits[0]
}

#[test]
fn crlf_source_credential_reports_exact_byte_offset() {
    let body = format!("# header\r\nAPI_KEY = \"{SECRET}\"\r\n");
    let scanner = scanner();
    let matches = scan(&scanner, &body, "/repo/app.py");
    let hit = credential_hit(&matches, SECRET);

    assert_eq!(hit.location.line, Some(2));
    assert_eq!(
        hit.location.offset,
        body.find(SECRET).expect("fixture contains credential"),
        "resolved finding offset must be the credential's CRLF byte position"
    );
}

#[test]
fn lf_and_crlf_entropy_hits_preserve_equivalent_line_identity() {
    let scanner = scanner();
    let lf_body = format!("# header\nAPI_KEY = \"{SECRET}\"\n");
    let crlf_body = format!("# header\r\nAPI_KEY = \"{SECRET}\"\r\n");

    let lf_matches = scan(&scanner, &lf_body, "/repo/app.py");
    let crlf_matches = scan(&scanner, &crlf_body, "/repo/app.py");
    let lf_hit = credential_hit(&lf_matches, SECRET);
    let crlf_hit = credential_hit(&crlf_matches, SECRET);

    assert_eq!(lf_hit.location.line, Some(2));
    assert_eq!(crlf_hit.location.line, Some(2));
    assert_eq!(
        lf_hit.location.offset,
        lf_body.find(SECRET).expect("LF fixture contains credential")
    );
    assert_eq!(
        crlf_hit.location.offset,
        crlf_body
            .find(SECRET)
            .expect("CRLF fixture contains credential")
    );
}

#[test]
fn crlf_multibyte_source_entropy_scan_does_not_panic() {
    let body = format!("設定 = \"値\"\r\nemoji = \"😀\"\r\nAPI_KEY = \"{SECRET}\"\r\n");
    let scanner = scanner();
    let matches = scan(&scanner, &body, "/repo/app.py");
    let hit = credential_hit(&matches, SECRET);

    assert_eq!(hit.location.line, Some(3));
    assert_eq!(
        hit.location.offset,
        body.find(SECRET).expect("fixture contains credential")
    );
}
