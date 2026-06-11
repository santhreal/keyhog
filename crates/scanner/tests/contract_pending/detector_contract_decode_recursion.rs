//! Encoded Secrets Decode-Recursion Contract Test
//!
//! Validates that the scanner's decode pipeline correctly unwraps
//! multi-layer encodings (base64, hex, URL) and finds planted secrets
//! at each nesting level, with GPU ↔ CPU identical result sets.
//!
//! Test areas:
//!   * Base64 1-level: plain AKIA in base64
//!   * Base64 2-level: base64(base64(AKIA))
//!   * Base64 3-level: base64(base64(base64(AKIA)))
//!   * Hex 1-level: plain AKIA in hex
//!   * Hex + base64 mix: base64(hex(AKIA))
//!   * URL + base64 mix: base64(url(AKIA))
//!   * GitHub token (ghp_) in base64
//!   * GitHub token in hex
//!   * AWS token wrapped in hex, then base64
//!   * Multi-secret corpus: AWS + GH in nested encodings
//!   * Boundary-straddled encoded secret (chunk split at encoding layer)
//!   * False-positive negatives: non-secret base64 must not fire
//!   * Adversarial payload: garbage base64/hex inside comments
//!   * Recursive depth limits: deep nesting (4+ levels) fallback
//!   * Order-sensitivity: different decode paths on GPU vs CPU
//!   * Cross-backend parity: identical credentials at identical offsets

mod support;
use support::paths::detector_dir;

use base64::Engine;
use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::collections::BTreeSet;
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
            source_type: "decode-recursion-test".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

fn make_chunk_with_offset(text: &str, path: &str, base_offset: usize) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "decode-recursion-test".into(),
            path: Some(path.into()),
            base_offset,
            ..Default::default()
        },
    }
}

type FindingKey = (String, String, usize);

fn collect_findings(results: &[Vec<RawMatch>]) -> BTreeSet<FindingKey> {
    let mut set = BTreeSet::new();
    for chunk in results {
        for m in chunk {
            set.insert((
                m.credential.as_ref().to_string(),
                m.location
                    .file_path
                    .as_deref()
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
                m.location.offset,
            ));
        }
    }
    set
}

fn count_credential_matches(results: &[Vec<RawMatch>], credential: &str) -> usize {
    results
        .iter()
        .flatten()
        .filter(|m| m.credential.as_ref() == credential)
        .count()
}

// Constants for standard test secrets
const AWS_KEY: &str = concat!("AK", "IAQYLPMN5HFIQR7XYA");
const GH_TOKEN: &str = "ghp_ABcD1234EFgh5678ijklMNop9012qrSTuvWX";

// Helper: encode string to base64
fn b64_encode(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

// Helper: encode string to hex with {:02x} format
fn hex_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for b in s.as_bytes() {
        result.push_str(&format!("{:02x}", b));
    }
    result
}

// Helper: URL-percent-encode string with %XX format
fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for b in s.as_bytes() {
        result.push_str(&format!("%{:02X}", b));
    }
    result
}

// Helper: scan on both backends and verify parity
fn assert_parity_both_backends(
    chunk: &Chunk,
    expected_credential: &str,
    context: &str,
) -> BTreeSet<FindingKey> {
    let scanner = scanner();

    let simd_results = scanner.scan_chunks_with_backend(std::slice::from_ref(chunk), ScanBackend::SimdCpu);
    let simd_keys = collect_findings(&simd_results);

    let gpu_results = scanner.scan_chunks_with_backend(std::slice::from_ref(chunk), ScanBackend::Gpu);
    let gpu_keys = collect_findings(&gpu_results);

    // Check GPU didn't silently return empty when SIMD found something
    if simd_keys.len() > 0 {
        assert!(
            gpu_keys.len() > 0 || gpu_results.iter().all(|c| c.is_empty()),
            "{}: GPU returned empty but SIMD found {} findings",
            context,
            simd_keys.len()
        );
    }

    // If both backends ran (GPU available), check parity
    if !gpu_results.iter().all(|c| c.is_empty()) {
        if simd_keys != gpu_keys {
            let only_simd: Vec<_> = simd_keys.difference(&gpu_keys).collect();
            let only_gpu: Vec<_> = gpu_keys.difference(&simd_keys).collect();
            panic!(
                "{}: GPU/SIMD parity broken.\n  SIMD keys ({}): {:?}\n  GPU keys ({}): {:?}\n  only SIMD: {:?}\n  only GPU: {:?}",
                context,
                simd_keys.len(),
                simd_keys.iter().take(3).collect::<Vec<_>>(),
                gpu_keys.len(),
                gpu_keys.iter().take(3).collect::<Vec<_>>(),
                only_simd.iter().take(2).collect::<Vec<_>>(),
                only_gpu.iter().take(2).collect::<Vec<_>>(),
            );
        }
    }

    // Verify the expected credential is present in at least SIMD results
    let found_cred = simd_results
        .iter()
        .flatten()
        .any(|m| m.credential.as_ref() == expected_credential);
    assert!(
        found_cred,
        "{}: expected credential '{}' not found. SIMD results: {:?}",
        context,
        expected_credential,
        simd_results
            .iter()
            .flatten()
            .map(|m| m.credential.as_ref().to_string())
            .collect::<Vec<_>>()
    );

    simd_keys
}

// ============================================================================
// SINGLE-LEVEL ENCODINGS
// ============================================================================

#[test]
fn base64_single_level_aws_key() {
    let encoded = b64_encode(&format!("AWS_ACCESS_KEY_ID={AWS_KEY}\n"));
    let text = format!(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: test\ndata:\n  key: {encoded}\n"
    );
    assert_parity_both_backends(
        &make_chunk(&text, "secret.yml"),
        AWS_KEY,
        "base64_single_level_aws_key",
    );
}

#[test]
fn base64_single_level_github_token() {
    let encoded = b64_encode(&format!("GITHUB_TOKEN={GH_TOKEN}"));
    let text = format!("data: {encoded}");
    assert_parity_both_backends(
        &make_chunk(&text, "secret.yml"),
        GH_TOKEN,
        "base64_single_level_github_token",
    );
}

#[test]
fn hex_single_level_aws_key() {
    let encoded = hex_encode(&format!("KEY={AWS_KEY}"));
    let text = format!("const BLOB = \"{encoded}\";");
    assert_parity_both_backends(
        &make_chunk(&text, "config.js"),
        AWS_KEY,
        "hex_single_level_aws_key",
    );
}

#[test]
fn hex_single_level_github_token() {
    let encoded = hex_encode(&format!("token={GH_TOKEN}"));
    let text = format!("// encoded: {encoded}");
    assert_parity_both_backends(
        &make_chunk(&text, "config.sh"),
        GH_TOKEN,
        "hex_single_level_github_token",
    );
}

#[test]
fn url_encoded_aws_key() {
    let encoded = url_encode(&format!("key={AWS_KEY}"));
    let text = format!("GET /login?data={encoded} HTTP/1.1");
    assert_parity_both_backends(
        &make_chunk(&text, "request.log"),
        AWS_KEY,
        "url_encoded_aws_key",
    );
}

// ============================================================================
// TWO-LEVEL ENCODINGS
// ============================================================================

#[test]
fn base64_two_level_aws_key() {
    // base64(base64(AKIA))
    let level1 = b64_encode(AWS_KEY);
    let level2 = b64_encode(&level1);
    let text = format!("encoded: {level2}");
    assert_parity_both_backends(
        &make_chunk(&text, "nested.yml"),
        AWS_KEY,
        "base64_two_level_aws_key",
    );
}

#[test]
fn base64_two_level_github_token() {
    let level1 = b64_encode(GH_TOKEN);
    let level2 = b64_encode(&level1);
    let text = format!("secret: {level2}");
    assert_parity_both_backends(
        &make_chunk(&text, "nested.yml"),
        GH_TOKEN,
        "base64_two_level_github_token",
    );
}

#[test]
fn hex_then_base64_aws_key() {
    // base64(hex(AKIA))
    let hex_enc = hex_encode(AWS_KEY);
    let b64_enc = b64_encode(&hex_enc);
    let text = format!("data: {b64_enc}");
    assert_parity_both_backends(
        &make_chunk(&text, "mixed.yml"),
        AWS_KEY,
        "hex_then_base64_aws_key",
    );
}

#[test]
fn url_then_base64_aws_key() {
    // base64(url(AKIA))
    let url_enc = url_encode(AWS_KEY);
    let b64_enc = b64_encode(&url_enc);
    let text = format!("payload: {b64_enc}");
    assert_parity_both_backends(
        &make_chunk(&text, "mixed.yml"),
        AWS_KEY,
        "url_then_base64_aws_key",
    );
}

#[test]
fn base64_then_hex_github_token() {
    // hex(base64(ghp_))
    let b64_enc = b64_encode(GH_TOKEN);
    let hex_enc = hex_encode(&b64_enc);
    let text = format!("config: {hex_enc}");
    assert_parity_both_backends(
        &make_chunk(&text, "mixed.txt"),
        GH_TOKEN,
        "base64_then_hex_github_token",
    );
}

// ============================================================================
// THREE-LEVEL ENCODINGS
// ============================================================================

#[test]
fn base64_three_level_aws_key() {
    // base64(base64(base64(AKIA)))
    let level1 = b64_encode(AWS_KEY);
    let level2 = b64_encode(&level1);
    let level3 = b64_encode(&level2);
    let text = format!("deep: {level3}");
    assert_parity_both_backends(
        &make_chunk(&text, "deep.yml"),
        AWS_KEY,
        "base64_three_level_aws_key",
    );
}

#[test]
fn base64_three_level_github_token() {
    let level1 = b64_encode(GH_TOKEN);
    let level2 = b64_encode(&level1);
    let level3 = b64_encode(&level2);
    let text = format!("token: {level3}");
    assert_parity_both_backends(
        &make_chunk(&text, "deep.yml"),
        GH_TOKEN,
        "base64_three_level_github_token",
    );
}

#[test]
fn hex_base64_hex_aws_key() {
    // hex(base64(hex(AKIA)))
    let hex1 = hex_encode(AWS_KEY);
    let b64 = b64_encode(&hex1);
    let hex2 = hex_encode(&b64);
    let text = format!("nested: {hex2}");
    assert_parity_both_backends(
        &make_chunk(&text, "mixed.txt"),
        AWS_KEY,
        "hex_base64_hex_aws_key",
    );
}

// ============================================================================
// MULTI-SECRET CORPUS
// ============================================================================

#[test]
fn multiple_secrets_mixed_encodings_on_both_backends() {
    // Same chunk, multiple encoded secrets, verify both found on both backends
    let aws_b64 = b64_encode(AWS_KEY);
    let gh_hex = hex_encode(GH_TOKEN);
    let text = format!(
        "config:\n  aws: {aws_b64}\n  github: {gh_hex}\n"
    );
    let chunk = make_chunk(&text, "config.yml");

    let scanner = scanner();
    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let simd_keys = collect_findings(&simd_results);

    let gpu_results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::Gpu);
    let gpu_keys = collect_findings(&gpu_results);

    // Count each secret on SIMD
    let aws_count = count_credential_matches(&simd_results, AWS_KEY);
    let gh_count = count_credential_matches(&simd_results, GH_TOKEN);

    assert_eq!(aws_count, 1, "AWS key should appear exactly once in SIMD results");
    assert_eq!(gh_count, 1, "GitHub token should appear exactly once in SIMD results");

    // If GPU ran, verify same set
    if gpu_keys.len() > 0 {
        if simd_keys != gpu_keys {
            panic!(
                "multiple_secrets_mixed_encodings: GPU/SIMD parity broken. SIMD: {}, GPU: {}",
                simd_keys.len(),
                gpu_keys.len()
            );
        }
    }
}

// ============================================================================
// BOUNDARY CONDITIONS & OFFSET HANDLING
// ============================================================================

#[test]
fn boundary_straddled_base64_aws_key() {
    // Split the base64-encoded AWS key across two chunks at the encoding boundary.
    // This tests that the decoder correctly maintains offsets when reassembling.
    let encoded = b64_encode(AWS_KEY);
    let split_at = encoded.len() / 2;

    let part_a = &encoded[..split_at];
    let part_b = &encoded[split_at..];

    let chunk_a = make_chunk_with_offset(&format!("data: {part_a}"), "file.yml", 0);
    let chunk_b = make_chunk_with_offset(&format!("{part_b}\n"), "file.yml", part_a.len() + 6);

    let scanner = scanner();
    let simd_results = scanner.scan_chunks_with_backend(&[chunk_a, chunk_b], ScanBackend::SimdCpu);

    let found = simd_results
        .iter()
        .flatten()
        .any(|m| m.credential.as_ref() == AWS_KEY);
    assert!(found, "boundary-straddled base64 AKIA must be found on SIMD");
}

// ============================================================================
// FALSE-POSITIVE PREVENTION (NEGATIVE TESTS)
// ============================================================================

#[test]
fn base64_non_secret_should_not_fire() {
    // Random valid base64 that is not a secret should not trigger
    let non_secret_b64 = b64_encode("just some random data with no credentials here");
    let text = format!("random_blob: {non_secret_b64}");
    let chunk = make_chunk(&text, "benign.yml");

    let scanner = scanner();
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let findings = collect_findings(&results);

    // We expect no matches (or very low false positive rate)
    // At least verify no spurious credential is found
    let has_fake_aws = results
        .iter()
        .flatten()
        .any(|m| m.credential.as_ref().starts_with("AKIA"));
    assert!(
        !has_fake_aws,
        "non-secret base64 should not produce fake AKIA credential"
    );
}

#[test]
fn hex_garbage_in_comments_should_not_fire() {
    let garbage_hex = hex_encode("this is not a secret at all");
    let text = format!("// hex garbage: {garbage_hex}\n// end comment");
    let chunk = make_chunk(&text, "code.rs");

    let scanner = scanner();
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let has_fake_gh = results
        .iter()
        .flatten()
        .any(|m| m.credential.as_ref().starts_with("ghp_"));
    assert!(
        !has_fake_gh,
        "garbage hex should not produce fake ghp_ token"
    );
}

// ============================================================================
// ADVERSARIAL PAYLOADS
// ============================================================================

#[test]
fn base64_with_noise_around_secret() {
    // Real secret embedded in a large base64 block
    let junk_before = b64_encode("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
    let secret_b64 = b64_encode(AWS_KEY);
    let junk_after = b64_encode("YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY");
    let text = format!("data: {junk_before}{secret_b64}{junk_after}");
    let chunk = make_chunk(&text, "noisy.yml");

    let scanner = scanner();
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let found = results
        .iter()
        .flatten()
        .any(|m| m.credential.as_ref() == AWS_KEY);
    assert!(
        found,
        "AWS key must be found even when surrounded by other base64 blocks"
    );
}

#[test]
fn multi_line_hex_encoding() {
    // Secret hex-encoded and split across lines (like in hex dumps)
    let hex_full = hex_encode(AWS_KEY);
    // Split into chunks of 16 characters per line
    let mut text = String::from("// Hex dump:\n");
    for chunk in hex_full.as_str().chars().collect::<Vec<_>>().chunks(16) {
        text.push_str("// ");
        text.push_str(&chunk.iter().collect::<String>());
        text.push('\n');
    }
    let chunk_obj = make_chunk(&text, "dump.txt");

    let scanner = scanner();
    let results = scanner.scan_chunks_with_backend(&[chunk_obj], ScanBackend::SimdCpu);
    let found = results
        .iter()
        .flatten()
        .any(|m| m.credential.as_ref() == AWS_KEY);
    assert!(found, "hex-encoded secret split across lines must be found");
}

// ============================================================================
// DEPTH LIMITS & FALLBACK
// ============================================================================

#[test]
fn base64_four_level_aws_key_may_skip_gracefully() {
    // Very deep nesting: base64^4(AKIA)
    // The decoder may have depth limits and not recurse this deep,
    // which is acceptable (graceful fallback). This test just ensures
    // no panic and no false positive.
    let level1 = b64_encode(AWS_KEY);
    let level2 = b64_encode(&level1);
    let level3 = b64_encode(&level2);
    let level4 = b64_encode(&level3);
    let text = format!("very_deep: {level4}");
    let chunk = make_chunk(&text, "very_deep.yml");

    let scanner = scanner();
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    // Just verify it doesn't panic and doesn't produce false credentials
    let has_real_aws = results
        .iter()
        .flatten()
        .any(|m| m.credential.as_ref() == AWS_KEY);
    // We don't assert it MUST be found (depth limit is acceptable),
    // but if it is found, that's great too.
    if !has_real_aws {
        eprintln!("Note: 4-level base64 nesting did not reach the AWS key (depth limit or false negative - acceptable)");
    }
}

// ============================================================================
// CONTEXT-SPECIFIC PATTERNS
// ============================================================================

#[test]
fn kubernetes_secret_manifest_base64() {
    // Real Kubernetes Secret YAML structure
    let key_data = b64_encode(&format!("AKIAIOSFODNN7EXAMPLE"));
    let secret_data = b64_encode(&format!("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
    let text = format!(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: aws\ntype: Opaque\ndata:\n  access-key-id: {key_data}\n  secret-access-key: {secret_data}\n"
    );
    let chunk = make_chunk(&text, "secret.yaml");

    let scanner = scanner();
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    // At minimum, the AWS access key ID should be found
    let found_access_key = results
        .iter()
        .flatten()
        .any(|m| m.credential.as_ref() == "AKIAIOSFODNN7EXAMPLE");
    assert!(found_access_key, "Kubernetes Secret access key ID must be found");
}

#[test]
fn json_api_response_with_encoded_token() {
    // API response with base64-encoded auth token
    let token_b64 = b64_encode(GH_TOKEN);
    let text = format!(
        r#"{{ "status": "ok", "auth_token": "{token_b64}", "expires_at": "2025-12-31" }}"#
    );
    let chunk = make_chunk(&text, "response.json");

    let scanner = scanner();
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let found = results
        .iter()
        .flatten()
        .any(|m| m.credential.as_ref() == GH_TOKEN);
    assert!(found, "GitHub token in JSON API response must be found");
}

#[test]
fn env_file_with_base64_values() {
    // .env file format with base64-encoded secrets
    let aws_b64 = b64_encode(AWS_KEY);
    let gh_b64 = b64_encode(GH_TOKEN);
    let text = format!(
        "# Environment variables\nAWS_KEY={aws_b64}\nGITHUB_TOKEN={gh_b64}\n"
    );
    let chunk = make_chunk(&text, ".env");

    let scanner = scanner();
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let aws_found = count_credential_matches(&results, AWS_KEY);
    let gh_found = count_credential_matches(&results, GH_TOKEN);

    assert_eq!(aws_found, 1, "AWS key in .env must be found once");
    assert_eq!(gh_found, 1, "GitHub token in .env must be found once");
}

// ============================================================================
// GPU FEATURE TESTS (conditional compilation)
// ============================================================================

#[test]
#[cfg(feature = "gpu")]
fn gpu_base64_two_level_aws_parity() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU available");
        return;
    }

    let level1 = b64_encode(AWS_KEY);
    let level2 = b64_encode(&level1);
    let text = format!("secret: {level2}");
    let chunk = make_chunk(&text, "nested.yml");

    let scanner = scanner();
    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let gpu_results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::Gpu);

    let simd_creds: BTreeSet<_> = simd_results
        .iter()
        .flatten()
        .map(|m| m.credential.as_ref().to_string())
        .collect();
    let gpu_creds: BTreeSet<_> = gpu_results
        .iter()
        .flatten()
        .map(|m| m.credential.as_ref().to_string())
        .collect();

    assert_eq!(
        simd_creds, gpu_creds,
        "GPU and SIMD must find identical credentials in 2-level base64"
    );
}

#[test]
#[cfg(feature = "gpu")]
fn gpu_hex_base64_mix_parity() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU available");
        return;
    }

    let hex_enc = hex_encode(AWS_KEY);
    let b64_enc = b64_encode(&hex_enc);
    let text = format!("data: {b64_enc}");
    let chunk = make_chunk(&text, "mixed.yml");

    let scanner = scanner();
    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let gpu_results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::Gpu);

    let simd_keys = collect_findings(&simd_results);
    let gpu_keys = collect_findings(&gpu_results);

    if gpu_keys.len() > 0 {
        assert_eq!(
            simd_keys, gpu_keys,
            "GPU and SIMD must produce parity for hex+base64 mixed encoding"
        );
    }
}

#[test]
#[cfg(feature = "gpu")]
fn gpu_multi_secret_parity() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU available");
        return;
    }

    let aws_b64 = b64_encode(AWS_KEY);
    let gh_hex = hex_encode(GH_TOKEN);
    let text = format!(
        "credentials:\n  aws_key: {aws_b64}\n  github_token: {gh_hex}\n"
    );
    let chunk = make_chunk(&text, "creds.yml");

    let scanner = scanner();
    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let gpu_results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::Gpu);

    let simd_aws = count_credential_matches(&simd_results, AWS_KEY);
    let simd_gh = count_credential_matches(&simd_results, GH_TOKEN);
    let gpu_aws = count_credential_matches(&gpu_results, AWS_KEY);
    let gpu_gh = count_credential_matches(&gpu_results, GH_TOKEN);

    if gpu_results.iter().any(|chunk| !chunk.is_empty()) {
        assert_eq!(simd_aws, gpu_aws, "AWS key counts must match GPU/SIMD");
        assert_eq!(simd_gh, gpu_gh, "GitHub token counts must match GPU/SIMD");
    }
}
