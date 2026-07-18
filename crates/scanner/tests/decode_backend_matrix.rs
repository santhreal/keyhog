//! Decoder × backend matrix.
//!
//! Asserts every supported decode layer (base64, hex, url, json-string,
//! unicode-escape) finds a planted secret through every backend
//! (SimdCpu, CpuFallback, Gpu). N decode-layers × M backends
//! is the surface area where prior incidents have lived:
//!
//!   * decode/pipeline.rs `base_offset:0` regression that reported
//!     bogus offsets on decoded chunks (task #80).
//!   * caesar/reverse decoders hallucinating credentials from source-
//!     code comments (task #78).
//!   * The backend-specific path for re-scanning decoded sub-chunks
//!     that the original GPU-batched-dispatch refactor broke (task #16).
//!
//! Each (decoder, backend) cell scans a small chunk that embeds the encoded
//! form of a known AKIA secret and asserts the decoded credential surfaces.
//! GPU cells must fail loudly or take a recall-preserving path before
//! this assertion; an empty secret-bearing result is a failure.

mod support;
use support::paths::detector_dir;

use base64::Engine;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::OnceLock;

fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors loadable");
        CompiledScanner::compile(detectors).expect("scanner compile")
    })
}

fn make_chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "decode-test".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

const ALL_BACKENDS: &[ScanBackend] = &[
    ScanBackend::SimdCpu,
    ScanBackend::CpuFallback,
    ScanBackend::GpuWgpu,
];

// The canonical secret we plant in every encoded fixture. AWS access
// key, recognized by the aws-access-key-id detector.
const SECRET: &str = concat!("AK", "IAQYLPMN5HFIQR7XYA");

fn canonical(results: &[Vec<keyhog_core::RawMatch>]) -> Vec<keyhog_core::RawMatch> {
    let mut findings = results.iter().flatten().cloned().collect::<Vec<_>>();
    findings.sort();
    findings
}

/// Require every backend to surface the decoded secret for this layer.
fn check_decoder_cells(decoder_label: &str, fixture: &Chunk) {
    let scanner = scanner();
    let mut failed = Vec::new();
    scanner.clear_fragment_cache();
    let reference_results =
        scanner.scan_chunks_with_backend(std::slice::from_ref(fixture), ScanBackend::CpuFallback);
    let reference = canonical(&reference_results);

    for backend in ALL_BACKENDS {
        let expected_decode_backend = if backend.is_gpu() {
            ScanBackend::CpuFallback
        } else {
            *backend
        };
        assert_eq!(
            scanner.execution_route_for_backend(*backend).decode_backend,
            expected_decode_backend,
            "decoded rescans must remain attributed to the measured route"
        );
        scanner.clear_fragment_cache();
        let degrade_before = scanner.runtime_status().gpu_degrade_count;
        let results = scanner.scan_chunks_with_backend(std::slice::from_ref(fixture), *backend);
        let degrade_after = scanner.runtime_status().gpu_degrade_count;
        let found = results
            .iter()
            .flatten()
            .any(|m| m.credential.as_ref().contains(SECRET));

        if !found || canonical(&results) != reference || degrade_after != degrade_before {
            let credentials: Vec<String> = results
                .iter()
                .flatten()
                .map(|m| m.credential.as_ref().to_string())
                .collect();
            failed.push(format!(
                "{backend:?}: found={found} exact_parity={} degraded={} saw={credentials:?}",
                canonical(&results) == reference,
                degrade_after != degrade_before,
            ));
        }
    }

    eprintln!(
        "[decode_backend_matrix:{decoder_label}] backends={} failed={}",
        ALL_BACKENDS.len(),
        failed.len()
    );
    assert!(
        failed.is_empty(),
        "decoder {decoder_label} missed the planted secret on:\n  - {}",
        failed.join("\n  - ")
    );
}

#[test]
fn base64_decode_finds_aws_key_on_every_backend() {
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(format!("AWS_ACCESS_KEY_ID={SECRET}\n").as_bytes());
    // A YAML-shaped fixture so the scanner's structural preprocessor
    // (which decodes `data:` blocks) picks it up the same way real
    // Kubernetes Secret manifests look.
    let text = format!(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: aws\ndata:\n  cred.env: {encoded}\n"
    );
    check_decoder_cells("base64", &make_chunk(&text, "secret.yml"));
}

#[test]
fn hex_decode_finds_aws_key_on_every_backend() {
    let plain = format!("AWS_ACCESS_KEY_ID={SECRET}");
    let mut hex = String::with_capacity(plain.len() * 2);
    for b in plain.bytes() {
        hex.push_str(&format!("{b:02x}"));
    }
    let text = format!("// hex-encoded credential blob\nconst BLOB = \"{hex}\";\n");
    check_decoder_cells("hex", &make_chunk(&text, "blob.js"));
}

#[test]
fn url_percent_decode_finds_aws_key_on_every_backend() {
    // URL-encode the secret with %XX byte escapes. The url decoder
    // canonicalizes the body and re-feeds it to the scanner.
    let plain = format!("AWS_ACCESS_KEY_ID={SECRET}");
    let mut url_enc = String::with_capacity(plain.len() * 3);
    for b in plain.bytes() {
        url_enc.push_str(&format!("%{b:02X}"));
    }
    let text = format!("/api/login?body={url_enc}\n");
    check_decoder_cells("url", &make_chunk(&text, "request.log"));
}

#[test]
fn unicode_escape_decode_finds_aws_key_on_every_backend() {
    // \uXXXX escape per character. Common in minified JS literals
    // that hide credentials behind escape sequences.
    let plain = format!("AWS_ACCESS_KEY_ID={SECRET}");
    let mut esc = String::with_capacity(plain.len() * 6);
    for c in plain.chars() {
        esc.push_str(&format!("\\u{:04X}", c as u32));
    }
    let text = format!("var x = \"{esc}\";\n");
    check_decoder_cells("unicode-escape", &make_chunk(&text, "min.js"));
}

#[test]
fn json_string_escape_decode_finds_aws_key_on_every_backend() {
    // JSON-escaped credential - \", \\ inside a JSON string literal.
    let plain = format!("AWS_ACCESS_KEY_ID={SECRET}");
    let text = format!("{{\"cred\":\"{plain}\"}}\n");
    check_decoder_cells("json-string", &make_chunk(&text, "payload.json"));
}
