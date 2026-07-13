//! Regression: base64-wrapped text is not automatically a secret.
//!
//! Kubernetes Secret `data:` values are common on both sides of the corpus:
//! real secrets can be base64-wrapped printable text, while benign resource
//! identifiers and package hashes are also base64-wrapped printable text. The
//! suppression contract therefore targets only decoded forms that are
//! structurally non-secret. Base64-wrapped SHA-1/SHA-256-style hex digests stay
//! non-secret, while encoded hex32/hex48 key material under API-key anchors
//! remains recall-owned.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    CompiledScanner::compile(detectors).expect("compile scanner")
}

fn k8s_secret(key: &str, encoded: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: {key}-secret\ntype: Opaque\ndata:\n  {key}: {encoded}\n"
    )
}

fn scan(scanner: &CompiledScanner, body: &str) -> Vec<RawMatch> {
    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("/repo/secret.yaml".into()),
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

fn has_generic(matches: &[RawMatch], credential: &str) -> bool {
    matches
        .iter()
        .any(|m| m.detector_id.starts_with("generic-") && m.credential.as_ref() == credential)
}

#[test]
fn decoded_iam_arn_license_hash_and_prose_do_not_surface_as_outer_base64_secret() {
    let scanner = scanner();
    for (key, encoded, label) in [
        (
            "token",
            "YXJuOmF3czppYW06OjkxNDkzNDQ5OTMzMjpyb2xlL0FkbWluUm9sZQ==",
            "decoded IAM ARN",
        ),
        (
            "api-key",
            "Nk5VU0EtU1dBUUMtRTAyMVAtRzU0TkYtREo2MzQ=",
            "decoded 5x5 license serial",
        ),
        (
            "integrity",
            "c2hhNTEyLUdFekcvU0dub3FjdXJ1NC9xNFZKblUrdHluMUlGSmg0WmowRERw",
            "decoded npm integrity hash",
        ),
        (
            "token",
            "ZTk5YjJlZjktM2I5ZS00ZTRjLWIwOWItMmY5OWVlZTYxZjU2",
            "decoded UUID v4",
        ),
        (
            "secret-key",
            "YjBhNTFiZGZkZmU0MWVlNWY1YjBhOWI2Y2EyNWNiMmMwNWJhNWI5Y2ExYTZlOGFlYjFhMGI5YzZmZmZmOGY0MA==",
            "decoded sha256 digest",
        ),
        (
            "token",
            "MDYxY2FhNWFiYThmYWEyZmNkY2FjYWM2OGQ3MDBmZGU4ZmFjZWI4Yg==",
            "decoded sha1 digest",
        ),
        (
            "session",
            "U2Vzc2lvbiBvcGVuZWQgd2l0aCBoYW5kbGUgdU9MTEEzbVg2UWxLVG10ekVS",
            "decoded audit prose",
        ),
    ] {
        let body = k8s_secret(key, encoded);
        let matches = scan(&scanner, &body);
        assert!(
            matches.is_empty(),
            "{label} must not surface in encoded or decoded form: {matches:#?}"
        );
    }
}

#[test]
fn decoded_real_secret_text_and_canonical_hex_keys_still_surface() {
    let scanner = scanner();
    for (key, encoded, expected, label) in [
        (
            "api-key",
            "c3VwZXItc2VjcmV0LWt1YmVybmV0ZXMtYXBpLWtleS12YWx1ZQ==",
            "c3VwZXItc2VjcmV0LWt1YmVybmV0ZXMtYXBpLWtleS12YWx1ZQ==",
            "decoded real secret text",
        ),
        (
            "api-key",
            "M2Y4YTljMmUxYjdkNGY2YThjMGUyZDRmNmE4YjBjMWU=",
            "3f8a9c2e1b7d4f6a8c0e2d4f6a8b0c1e",
            "decoded hex32 key",
        ),
        (
            "encryption-key",
            "OGYzYTkxYzdkMmU0MGI2ZmE1YzE4Mzc5ZGU0MmI2MGY5YTdjMzFlNWQ4MDQyYmY2",
            "8f3a91c7d2e40b6fa5c18379de42b60f9a7c31e5d8042bf6",
            "decoded hex48 key",
        ),
    ] {
        let body = k8s_secret(key, encoded);
        let matches = scan(&scanner, &body);
        assert!(
            has_generic(&matches, expected),
            "{label} must surface with source attribution: {matches:#?}"
        );
    }
}
