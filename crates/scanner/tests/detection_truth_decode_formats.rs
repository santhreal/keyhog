//! Detection-truth: DECODE-path file formats (#177/#184). Kubernetes Secrets,
//! base64-in-JSON, and URL basic-auth hide the real credential behind an
//! encoding layer; the scanner's decode→rescan pass must recover the CLEAN value
//! (not the base64 blob). Each plants a known-firing secret behind a real-world
//! encoding and asserts the decoded value is found (Law 6). ML-independent
//! (decode runs before scoring); run without `ml` while weights are mid-retrain.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn scan_credentials(text: &str, path: &str) -> Vec<String> {
    let detectors = keyhog_core::embedded_detector_specs().to_vec();
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "decode-format-test".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .iter()
        .flat_map(|per_chunk| per_chunk.iter())
        .map(|m| m.credential.as_ref().to_string())
        .collect()
}

fn assert_found(text: &str, path: &str, expected: &str) {
    let creds = scan_credentials(text, path);
    assert!(
        creds.iter().any(|c| c == expected),
        "expected decoded `{expected}` in {path}; found: {creds:?}\n--- input ---\n{text}"
    );
}

#[test]
fn k8s_secret_base64_aws_key() {
    // Kubernetes Secret `data:` values are base64. QUtJ... = AKIAQYLPMN5HFIQR7BBB.
    assert_found(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: aws\ntype: Opaque\ndata:\n  \
         access-key: QUtJQVFZTFBNTjVIRklRUjdCQkI=\n",
        "secret.yaml",
        "AKIAQYLPMN5HFIQR7BBB",
    );
}

#[test]
fn k8s_secret_base64_gitlab_token() {
    // Z2xwYXQt... = glpat-ABCDEF1234567890abcd
    assert_found(
        "kind: Secret\ndata:\n  token: Z2xwYXQtQUJDREVGMTIzNDU2Nzg5MGFiY2Q=\n",
        "secret.yaml",
        "glpat-ABCDEF1234567890abcd",
    );
}

#[test]
fn k8s_secret_base64_slack_token() {
    assert_found(
        "kind: Secret\ndata:\n  slack: \
         eG94Yi0yMzQ1Njc4OTAxMjM0LTIzNDU2Nzg5MDEyMzQtQWJDZEVmR2hJaktsTW5PcFFyU3RVdld4\n",
        "secret.yaml",
        "xoxb-2345678901234-2345678901234-AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn base64_encoded_secret_in_json() {
    // A config that stores the token base64-encoded in a JSON string value.
    assert_found(
        "{\n  \"encodedToken\": \"Z2xwYXQtQUJDREVGMTIzNDU2Nzg5MGFiY2Q=\"\n}",
        "config.json",
        "glpat-ABCDEF1234567890abcd",
    );
}

#[test]
fn url_basic_auth_embedded_stripe_key() {
    // Credentials embedded in a URL userinfo component.
    assert_found(
        "backend = https://apiuser:sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000@api.example.com/v1\n",
        "config.toml",
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000",
    );
}
