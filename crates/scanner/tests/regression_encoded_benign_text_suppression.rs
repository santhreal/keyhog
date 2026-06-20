//! Regression: base64-wrapped text is not automatically a secret.
//!
//! Kubernetes Secret `data:` values are common on both sides of the corpus:
//! real secrets can be base64-wrapped printable text, while benign resource
//! identifiers and package hashes are also base64-wrapped printable text. The
//! suppression contract therefore targets only decoded forms that are
//! structurally non-secret and leaves ambiguous decoded hex/UUID-style values
//! to recall-oriented gates.

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
        .any(|m| m.detector_id.as_ref() == "generic-secret" && m.credential.as_ref() == credential)
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
            "session",
            "U2Vzc2lvbiBvcGVuZWQgd2l0aCBoYW5kbGUgdU9MTEEzbVg2UWxLVG10ekVS",
            "decoded audit prose",
        ),
    ] {
        let body = k8s_secret(key, encoded);
        let matches = scan(&scanner, &body);
        assert!(
            !has_generic(&matches, encoded),
            "{label} must not surface as an outer generic-secret finding: {matches:#?}"
        );
    }
}

#[test]
fn decoded_real_secret_text_and_ambiguous_hex_still_surface() {
    let scanner = scanner();
    for (key, encoded, label) in [
        (
            "api-key",
            "c3VwZXItc2VjcmV0LWt1YmVybmV0ZXMtYXBpLWtleS12YWx1ZQ==",
            "decoded real secret text",
        ),
        (
            "token",
            "MDYxY2FhNWFiYThmYWEyZmNkY2FjYWM2OGQ3MDBmZGU4ZmFjZWI4Yg==",
            "decoded ambiguous hex text",
        ),
    ] {
        let body = k8s_secret(key, encoded);
        let matches = scan(&scanner, &body);
        assert!(
            has_generic(&matches, encoded),
            "{label} must keep the outer generic-secret finding: {matches:#?}"
        );
    }
}
