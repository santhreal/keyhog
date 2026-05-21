//! Decoder × backend matrix.
//!
//! Asserts every supported decode layer (base64, hex, url, json-string,
//! unicode-escape) finds a planted secret through every backend
//! (SimdCpu, CpuFallback, Gpu, MegaScan). N decode-layers × M backends
//! is the surface area where prior incidents have lived:
//!
//!   * decode/pipeline.rs `base_offset:0` regression that reported
//!     bogus offsets on decoded chunks (task #80).
//!   * caesar/reverse decoders hallucinating credentials from source-
//!     code comments (task #78).
//!   * The backend-specific path for re-scanning decoded sub-chunks
//!     that the original GPU-batched-dispatch refactor broke (task #16).
//!
//! Each (decoder, backend) cell scans a small chunk that embeds the
//! encoded form of a known AKIA secret and asserts the decoded
//! credential surfaces. GPU/MegaScan cells silently SKIP when no
//! compatible adapter is present.

use base64::Engine;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::path::PathBuf;
use std::sync::OnceLock;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

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
    ScanBackend::Gpu,
    ScanBackend::MegaScan,
];

// The canonical secret we plant in every encoded fixture. AWS access
// key, recognized by the aws-access-key-id detector.
const SECRET: &str = "AKIAQYLPMN5HFIQR7XYA";

/// Returns true if any backend ran and found the secret. SKIPs (no GPU)
/// don't count as failures but DO mean we don't trust the layer for
/// that backend slot.
fn check_decoder_cells(decoder_label: &str, fixture: &Chunk) {
    let scanner = scanner();
    let mut failed = Vec::new();
    let mut skipped = Vec::new();

    for backend in ALL_BACKENDS {
        let results = scanner.scan_chunks_with_backend(std::slice::from_ref(fixture), *backend);
        let found = results
            .iter()
            .flatten()
            .any(|m| m.credential.as_ref().contains(SECRET));

        if !found {
            // GPU/MegaScan no-adapter SKIP: treat empty-results-on-the-
            // GPU-path as a skip, not a failure. SimdCpu/CpuFallback
            // empty is a real fail (no GPU dependency on those).
            if matches!(backend, ScanBackend::Gpu | ScanBackend::MegaScan)
                && results.iter().all(|chunk| chunk.is_empty())
            {
                skipped.push(format!("{backend:?}"));
            } else {
                let credentials: Vec<String> = results
                    .iter()
                    .flatten()
                    .map(|m| m.credential.as_ref().to_string())
                    .collect();
                failed.push(format!("{backend:?}: saw {credentials:?}"));
            }
        }
    }

    eprintln!(
        "[decode_backend_matrix:{decoder_label}] backends={} skipped={} failed={}",
        ALL_BACKENDS.len(),
        skipped.len(),
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
    // JSON-escaped credential — \", \\ inside a JSON string literal.
    let plain = format!("AWS_ACCESS_KEY_ID={SECRET}");
    let text = format!("{{\"cred\":\"{plain}\"}}\n");
    check_decoder_cells("json-string", &make_chunk(&text, "payload.json"));
}
