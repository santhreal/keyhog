//! Regression: base64-of-random-bytes decoys must not survive through entropy or
//! generic fallback paths as reported findings.
//!
//! The mirror corpus plants protobuf/random-byte base64 strings under ordinary
//! credential-looking keys (`API_KEY`, `secret`) to catch split-path scoring bugs.
//! One path recorded `base64_blob` / `random_byte_blob` dogfood suppressions while
//! another still emitted the same value at high confidence.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};

const GITHUB_ACTIONS_PLUS_ONLY: &str =
    "L18a82PXh+jOWYsivVaFfDj0QIe+Qc3azWsdDJEIaUSlc2kpt2+TrRcKopIG";
const GITHUB_ACTIONS_PLUS_SLASH: &str =
    "5OcKQwtmHw+SRJZ76bc4vwBhnVsM1ksLmOGTaHamLo6+MIF3IlZcNaWD3vhW7+3ID7UwSS6whDRWERI6756fzh06";
const PROPERTIES_PURE_ALNUM: &str = "VqsjpzT2Jauz6vo76xb5vNB8XXxfBTQyNX6G5Kx1AEEk";
const SLASH_BEARING_API_KEY: &str = "PvgsQdw6b5r9JqFzmaVkh/PBOtxkvFtq3OLNhcdqlOcoSqgnQx";
const REPORT_FLOOR: f64 = 0.40;

fn scanner(ml_enabled: bool) -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let mut cfg = ScannerConfig::default();
    cfg.min_confidence = REPORT_FLOOR;
    cfg.ml_enabled = ml_enabled;
    CompiledScanner::compile(detectors)
        .expect("compile scanner")
        .with_config(cfg)
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

fn reported(matches: &[RawMatch], credential: &str) -> Vec<(String, f64, Option<usize>)> {
    matches
        .iter()
        .filter(|m| {
            m.credential.as_ref() == credential && m.confidence.unwrap_or(0.0) >= REPORT_FLOOR
        })
        .map(|m| {
            (
                m.detector_id.as_ref().to_string(),
                m.confidence.unwrap_or(0.0),
                m.location.line,
            )
        })
        .collect()
}

#[test]
fn github_actions_plus_only_base64_protobuf_is_not_reported_with_ml() {
    let body = format!(
        "name: deploy\non: [push]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    env:\n      API_KEY: {GITHUB_ACTIONS_PLUS_ONLY}\n    steps:\n      - run: ./deploy.sh\n"
    );
    let matches = scan(
        &scanner(true),
        &body,
        "/repo/benchmarks/corpora/mirror/corpus/cf/mirror-neg-0005655.yaml",
    );
    let hits = reported(&matches, GITHUB_ACTIONS_PLUS_ONLY);
    assert!(
        hits.is_empty(),
        "plus-only base64 protobuf decoy must not reach the report floor; hits={hits:?}"
    );
}

#[test]
fn github_actions_plus_only_base64_protobuf_is_not_reported_without_ml() {
    let body = format!(
        "name: deploy\non: [push]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    env:\n      API_KEY: {GITHUB_ACTIONS_PLUS_ONLY}\n    steps:\n      - run: ./deploy.sh\n"
    );
    let matches = scan(
        &scanner(false),
        &body,
        "/repo/benchmarks/corpora/mirror/corpus/cf/mirror-neg-0005655.yaml",
    );
    let hits = reported(&matches, GITHUB_ACTIONS_PLUS_ONLY);
    assert!(
        hits.is_empty(),
        "no-ML generic scoring must keep base64 blob decoys below the report floor; hits={hits:?}"
    );
}

#[test]
fn properties_pure_alnum_random_byte_base64_is_not_reported_with_ml() {
    let body = format!("# Application configuration\nsecret={PROPERTIES_PURE_ALNUM}\n");
    let matches = scan(&scanner(true), &body, "/repo/pkg/auth/service.properties");
    let hits = reported(&matches, PROPERTIES_PURE_ALNUM);
    assert!(
        hits.is_empty(),
        "pure-alnum random-byte base64 decoy must not reach the report floor; hits={hits:?}"
    );
}

#[test]
fn github_actions_plus_slash_base64_protobuf_is_not_reported_with_ml() {
    let body = format!(
        "name: deploy\non: [push]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    env:\n      DEPLOY_TOKEN: {GITHUB_ACTIONS_PLUS_SLASH}\n    steps:\n      - run: ./deploy.sh\n"
    );
    let matches = scan(
        &scanner(true),
        &body,
        "/repo/benchmarks/corpora/mirror/corpus/3c/mirror-neg-0000644.yaml",
    );
    let hits = reported(&matches, GITHUB_ACTIONS_PLUS_SLASH);
    assert!(
        hits.is_empty(),
        "plus/slash base64 protobuf decoy must not reach the report floor; hits={hits:?}"
    );
}

#[test]
fn strong_assignment_random_looking_base64_tokens_remain_reported() {
    let scanner = scanner(true);
    let cases = [
        (
            "N3QeSSnj9nOo7n8J27dHS8ZTc6ittoTJtrcTR7eo",
            "name: deploy\non: [push]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    env:\n      API_KEY: N3QeSSnj9nOo7n8J27dHS8ZTc6ittoTJtrcTR7eo\n    steps:\n      - run: ./deploy.sh\n",
            "/repo/benchmarks/corpora/mirror/corpus/19/mirror-pos-0001305.yaml",
        ),
        (
            "xdwZInwvHd5C9TaRI6r5cSx2iNALXTozPV6xCR0WZhdL",
            "name: deploy\non: [push]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    env:\n      DEPLOY_TOKEN: xdwZInwvHd5C9TaRI6r5cSx2iNALXTozPV6xCR0WZhdL\n    steps:\n      - run: ./deploy.sh\n",
            "/repo/benchmarks/corpora/mirror/corpus/46/mirror-pos-0001606.yaml",
        ),
        (
            "UUL84UAGUDgNJ1cyU3awoYPSpLlhkJC3CcJPI4TJ",
            "TOKEN=UUL84UAGUDgNJ1cyU3awoYPSpLlhkJC3CcJPI4TJ\n",
            "/repo/benchmarks/corpora/mirror/corpus/4b/mirror-pos-0000587.env",
        ),
        (
            "Xoxu5sLLXXgTPZyXF1tCcA3jFUIT0DtcRWA9fpF0",
            "TOKEN=Xoxu5sLLXXgTPZyXF1tCcA3jFUIT0DtcRWA9fpF0\n",
            "/repo/benchmarks/corpora/mirror/corpus/cc/mirror-pos-0001484.env",
        ),
        (
            SLASH_BEARING_API_KEY,
            "export API_KEY=\"PvgsQdw6b5r9JqFzmaVkh/PBOtxkvFtq3OLNhcdqlOcoSqgnQx\"\n",
            "/repo/benchmarks/corpora/mirror/corpus/29/mirror-pos-0000553.sh",
        ),
    ];

    for (credential, body, path) in cases {
        let matches = scan(&scanner, body, path);
        let hits = reported(&matches, credential);
        assert!(
            !hits.is_empty(),
            "strong assignment token must remain reportable for {path}; matches={matches:?}"
        );
    }
}
