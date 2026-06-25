//! Regression: reverse decode must not turn package integrity strings into
//! credential-shaped noise.
//!
//! `sha512-<base64>` package integrity values are already suppressed on the
//! forward path as labelled hashes. Some bodies contain incidental provider
//! prefixes after reversal (`eyJ`, `sk-`, etc.), which used to admit them into
//! the reverse decoder and re-emit a high-confidence generic-secret.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};

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
fn npm_integrity_values_do_not_surface_through_reverse_decode() {
    let scanner = scanner();
    for (body, path) in [
        (
            r#"import requests

SECRET = "sha512-1msyKcoKgxiewdylfpoWNSrFFW3ojqO5LKa5wDu1Ivsn9KJyenY5VvFVFvg3LtJWzI3b3d8GNNngKmP1Zdzpfy=="
def call():
    return requests.get("https://api.example.org", headers={"auth": SECRET})
"#,
            "/repo/service.py",
        ),
        (
            r#"name: deploy
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      DEPLOY_TOKEN: sha512-Ke40vKcybWUrnCpImcW1t0Ht27Xbp66rg85PkxZj05YhWC2KCEVN/EfPysZ4UY+1QshOWTgKOJyes/4Jl4eZoV==
    steps:
      - run: ./deploy.sh
"#,
            "/repo/workflow.yaml",
        ),
    ] {
        let matches = scan(&scanner, body, path);
        assert!(
            matches.is_empty(),
            "labelled package integrity decoy must stay silent: {matches:#?}"
        );
    }
}

#[test]
fn real_reversed_provider_token_still_surfaces() {
    let scanner = scanner();
    // A real, checksum-valid github classic PAT (36 chars after `ghp_`); the
    // reverse decoder must restore the exact token so `github-classic-pat`
    // (length + checksum gated) fires rather than a generic entropy match.
    let secret = "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";
    let reversed: String = secret.chars().rev().collect();
    let body = format!(r#"token = "{reversed}""#);
    let matches = scan(&scanner, &body, "/repo/reversed.txt");
    assert!(
        matches.iter().any(|m| {
            m.detector_id.as_ref() == "github-classic-pat" && m.credential.as_ref() == secret
        }),
        "reverse decoder must still surface real provider tokens: {matches:#?}"
    );
}
