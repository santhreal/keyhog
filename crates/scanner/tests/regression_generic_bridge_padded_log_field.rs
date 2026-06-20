//! Regression: padded base64 log values must not make the generic bridge emit
//! the following `status=200` field as a credential.
//!
//! Root cause: the generic assignment regex allowed an optional nested
//! `name = value` segment after both `:` and `=`. On a log line like
//! `auth_token=<base64=> status=200`, the trailing base64 padding `=` was parsed
//! as that nested assignment delimiter, so the bridge skipped the real token and
//! reported `status=200`. Type annotations such as `api_key: &str = "value"`
//! still need the nested segment, but only on colon assignments.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let mut cfg = ScannerConfig::default();
    cfg.min_confidence = 0.0;
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

fn has_credential(matches: &[RawMatch], credential: &str) -> bool {
    matches.iter().any(|m| m.credential.as_ref() == credential)
}

#[test]
fn padded_base64_log_field_does_not_emit_following_status_assignment() {
    let scanner = scanner();
    let body = concat!(
        "2026-05-23T10:00:42.137Z INFO outbound_request ",
        "endpoint=/api/v1/charge ",
        "auth_token=OieCWma1ETUbEK4NvfPeCfogiWn3Vs0UwuRVLC1rfrvz82II9vYrA23aWxTTbE8= ",
        "status=200 latency_ms=83\n",
    );
    let matches = scan(&scanner, body, "/repo/logs/access.log");
    assert!(
        !has_credential(&matches, "status=200"),
        "generic bridge must not reinterpret padded base64 as a nested assignment \
         and emit the next log field; matches: {matches:#?}"
    );
}

#[test]
fn colon_type_annotation_still_surfaces_real_credential() {
    let scanner = scanner();
    let credential = "HVupsQnTMKFMuM199OtdO";
    let matches = scan(
        &scanner,
        &format!("const API_KEY: &str = \"{credential}\";\n"),
        "/repo/src/config.rs",
    );
    assert!(
        has_credential(&matches, credential),
        "colon type annotation must still bridge to the real value; matches: {matches:#?}"
    );
}
