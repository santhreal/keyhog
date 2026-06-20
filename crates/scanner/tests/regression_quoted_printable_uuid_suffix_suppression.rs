//! Regression: quoted-printable decode must not turn UUID assignments into
//! credential-looking suffixes.
//!
//! `secret=3d<uuid-tail>` is a normal key/value assignment whose first value
//! bytes happen to look like a quoted-printable escape. Decoding the whole line
//! drops those bytes and leaves a `6-4-4-4-12` UUID suffix. The suffix is still
//! a resource identifier, not a secret. A real quoted-printable provider token
//! must continue to surface.

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
fn quoted_printable_uuid_assignment_suffixes_stay_silent() {
    let scanner = scanner();
    for (body, path, suffix) in [
        (
            "secret=3d74efb5-6574-4a18-9901-9a4eb88fc428",
            "/repo/settings.properties",
            "74efb5-6574-4a18-9901-9a4eb88fc428",
        ),
        (
            "ENV API_KEY=3acc7f73-e3f8-4a30-b0d8-1d6ede63c16e",
            "/repo/Dockerfile",
            "cc7f73-e3f8-4a30-b0d8-1d6ede63c16e",
        ),
    ] {
        let matches = scan(&scanner, body, path);
        assert!(
            !matches
                .iter()
                .any(|m| m.detector_id.as_ref() == "generic-secret"
                    && m.credential.as_ref() == suffix),
            "quoted-printable UUID suffix must be suppressed: {matches:#?}"
        );
    }
}

#[test]
fn quoted_printable_provider_token_still_surfaces() {
    let scanner = scanner();
    let secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890AB";
    let body = "X-Token: ghp=5Fabcdefghijklmnopqrstuvwxyz1234567890AB";
    let matches = scan(&scanner, body, "/repo/token.txt");
    assert!(
        matches.iter().any(|m| {
            m.detector_id.as_ref() == "github-classic-pat" && m.credential.as_ref() == secret
        }),
        "quoted-printable decode must still surface real provider tokens: {matches:#?}"
    );
}
