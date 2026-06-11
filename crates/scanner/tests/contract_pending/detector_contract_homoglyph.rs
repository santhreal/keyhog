//! Integration test: homoglyph/unicode-evasion detector contract.
//!
//! Credentials with Cyrillic/Greek lookalikes, zero-width characters, and
//! RTL marks must be detected with exact parity between CPU and GPU backends.
//! Corresponding ASCII twins must also fire to ensure base detection is not
//! weakened by homoglyph variants.

#[path = "support/mod.rs"]
mod support;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use support::paths::detector_dir;

fn make_chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

type FindingKey = (String, String, usize);

fn collect_keys(results: &[Vec<RawMatch>]) -> std::collections::BTreeSet<FindingKey> {
    let mut set = std::collections::BTreeSet::new();
    for chunk in results {
        for m in chunk {
            set.insert((
                m.credential.as_ref().to_string(),
                m.detector_id.as_ref().to_string(),
                m.location.offset,
            ));
        }
    }
    set
}

fn scan_both_backends(
    scanner: &CompiledScanner,
    chunk: &Chunk,
) -> (std::collections::BTreeSet<FindingKey>, std::collections::BTreeSet<FindingKey>) {
    let simd = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let simd_keys = collect_keys(&simd);

    let gpu = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::Gpu);
    let gpu_keys = collect_keys(&gpu);

    (simd_keys, gpu_keys)
}

// ============================================================================
// POSITIVE TESTS: homoglyphs must fire
// ============================================================================

#[test]
fn homoglyph_cyrillic_a_in_aws_key() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // AKIA with Cyrillic 'а' (U+0430) at the start: "АKIAiosfodnn7example"
    // The homoglyph variant should match this despite the non-ASCII byte.
    let chunk = make_chunk(
        "aws_key = \"АKIAiosfodnn7example\"",
        "cyrillic_aws.rs",
    );

    let simd_keys = scanner
        .scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu)
        .into_iter()
        .flat_map(|v| v.into_iter())
        .collect::<Vec<_>>();

    let found_homoglyph = simd_keys
        .iter()
        .any(|m| m.credential.as_ref().contains("АKIAiosfodnn7example"));

    assert!(
        found_homoglyph,
        "homoglyph Cyrillic 'а' variant must match (SIMD found: {:?})",
        simd_keys.iter().map(|m| m.credential.as_ref()).collect::<Vec<_>>()
    );
}

#[test]
fn homoglyph_greek_rho_in_stripe_key() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // Greek 'ρ' (U+03C1) looks like 'p': "sk_live_ρ123456789abcdefghij"
    let chunk = make_chunk(
        "stripe_key: \"sk_live_ρ123456789abcdefghij\"",
        "greek_stripe.rs",
    );

    let simd_keys = scanner
        .scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu)
        .into_iter()
        .flat_map(|v| v.into_iter())
        .collect::<Vec<_>>();

    let found = simd_keys
        .iter()
        .any(|m| m.credential.as_ref().contains("sk_live_ρ123456789abcdefghij"));

    assert!(
        found,
        "Greek rho homoglyph in Stripe key must match (SIMD found: {:?})",
        simd_keys.iter().map(|m| m.credential.as_ref()).collect::<Vec<_>>()
    );
}

#[test]
fn homoglyph_zero_width_space_in_github_pat() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // "ghp_" + zero-width space (U+200B) + "aBcD1234EFgh5678ijklMNop9012qrSTuvWX"
    // Zero-width chars don't render but are part of the credential.
    let chunk = make_chunk(
        "token = \"ghp_\u{200B}aBcD1234EFgh5678ijklMNop9012qrSTuvWX\"",
        "github_zwsp.rs",
    );

    let simd_keys = scanner
        .scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu)
        .into_iter()
        .flat_map(|v| v.into_iter())
        .collect::<Vec<_>>();

    let found = simd_keys
        .iter()
        .any(|m| m.credential.as_ref().contains("\u{200B}"));

    assert!(
        found,
        "zero-width space in GitHub PAT must be detected (SIMD found: {:?})",
        simd_keys.iter().map(|m| m.credential.as_ref()).collect::<Vec<_>>()
    );
}

#[test]
fn homoglyph_rtl_mark_in_api_key() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // "api_key=" + right-to-left mark (U+200F) + ASCII key
    // RTL marks are invisible but create homoglyphs of familiar patterns.
    let chunk = make_chunk(
        "api_key=\"\u{200F}sk_live_4eC39HqLyjWDarjtT1zdp7dc\"",
        "rtl_stripe.rs",
    );

    let simd_keys = scanner
        .scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu)
        .into_iter()
        .flat_map(|v| v.into_iter())
        .collect::<Vec<_>>();

    let found = simd_keys.iter().any(|m| m.credential.as_ref().contains("sk_live_"));

    assert!(
        found,
        "RTL mark homoglyph must not block detection (SIMD found: {:?})",
        simd_keys.iter().map(|m| m.credential.as_ref()).collect::<Vec<_>>()
    );
}

// ============================================================================
// ASCII TWIN TESTS: ASCII forms must also fire
// ============================================================================

#[test]
fn ascii_twin_akia_fires_when_homoglyph_cyrillic_fires() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // Both forms in one chunk: Cyrillic 'а' homoglyph AND plain ASCII.
    let chunk = make_chunk(
        "key1 = \"AKIAIOSFODNN7EXAMPLE\"\nkey2 = \"АKIAiosfodnn7example\"",
        "aws_both_forms.rs",
    );

    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let all_creds: Vec<String> = simd_results
        .iter()
        .flat_map(|v| v.iter().map(|m| m.credential.as_ref().to_string()))
        .collect();

    let has_ascii = all_creds.iter().any(|c| c == "AKIAIOSFODNN7EXAMPLE");
    let has_homoglyph = all_creds.iter().any(|c| c.contains('А'));

    assert!(
        has_ascii && has_homoglyph,
        "both ASCII AKIA and Cyrillic homoglyph must fire (found: {:?})",
        all_creds
    );
}

#[test]
fn ascii_twin_stripe_fires_with_greek_rho() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // ASCII plain form: "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
    // Greek rho form: "sk_live_ρ123456789abcdefghij"
    let chunk = make_chunk(
        "a = \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"\nb = \"sk_live_ρ123456789abcdefghij\"",
        "stripe_both.rs",
    );

    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let all_creds: Vec<String> = simd_results
        .iter()
        .flat_map(|v| v.iter().map(|m| m.credential.as_ref().to_string()))
        .collect();

    let has_ascii_stripe = all_creds.iter().any(|c| c.starts_with("sk_live_") && !c.contains('ρ'));
    let has_rho = all_creds.iter().any(|c| c.contains("ρ"));

    assert!(
        has_ascii_stripe && has_rho,
        "ASCII Stripe key and Greek rho form must both fire (found: {:?})",
        all_creds
    );
}

// ============================================================================
// NEGATIVE TESTS: ensure no false positives on non-homoglyph-like ASCII
// ============================================================================

#[test]
fn no_false_positive_on_benign_cyrillic_text() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // Pure Cyrillic prose, no credentials: "Это просто текст на русском"
    let chunk = make_chunk(
        "// Это просто текст на русском языке\nprintln!(\"Привет\");",
        "benign_cyrillic.rs",
    );

    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let all_matches: Vec<String> = simd_results
        .iter()
        .flat_map(|v| v.iter().map(|m| m.credential.as_ref().to_string()))
        .collect();

    assert!(
        all_matches.is_empty(),
        "benign Cyrillic text must not trigger false positives (found: {:?})",
        all_matches
    );
}

#[test]
fn no_false_positive_on_benign_greek_text() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // Greek text without credential shape: "Αυτό είναι Ελληνικά κείμενο"
    let chunk = make_chunk(
        "// Αυτό είναι Ελληνικά κείμενο\nprint(\"Γεια σας\")",
        "benign_greek.rs",
    );

    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let all_matches: Vec<String> = simd_results
        .iter()
        .flat_map(|v| v.iter().map(|m| m.credential.as_ref().to_string()))
        .collect();

    assert!(
        all_matches.is_empty(),
        "benign Greek text must not trigger false positives (found: {:?})",
        all_matches
    );
}

// ============================================================================
// BOUNDARY TESTS: edge cases with mixed widths and format boundaries
// ============================================================================

#[test]
fn homoglyph_at_chunk_start() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // Cyrillic-based homoglyph at position 0
    let chunk = make_chunk(
        "АKIAiosfodnn7example secret=data",
        "homoglyph_start.rs",
    );

    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let all_creds: Vec<String> = simd_results
        .iter()
        .flat_map(|v| v.iter().map(|m| m.credential.as_ref().to_string()))
        .collect();

    let found = all_creds.iter().any(|c| c.contains('А'));

    assert!(
        found,
        "homoglyph at chunk start must be detected (found: {:?})",
        all_creds
    );
}

#[test]
fn homoglyph_at_chunk_end() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // Homoglyph at the end with no trailing content
    let chunk = make_chunk(
        "secret_key = \"АKIAiosfodnn7example\"",
        "homoglyph_end.rs",
    );

    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let all_creds: Vec<String> = simd_results
        .iter()
        .flat_map(|v| v.iter().map(|m| m.credential.as_ref().to_string()))
        .collect();

    let found = all_creds.iter().any(|c| c.contains('А'));

    assert!(
        found,
        "homoglyph at chunk end must be detected (found: {:?})",
        all_creds
    );
}

#[test]
fn homoglyph_with_url_encoding_context() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // URL context: "api_key=АKIAiosfodnn7example&other=value"
    let chunk = make_chunk(
        "https://example.com?api_key=АKIAiosfodnn7example&other=value",
        "homoglyph_url.rs",
    );

    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let all_creds: Vec<String> = simd_results
        .iter()
        .flat_map(|v| v.iter().map(|m| m.credential.as_ref().to_string()))
        .collect();

    let found = all_creds.iter().any(|c| c.contains('А'));

    assert!(
        found,
        "homoglyph in URL query param must be detected (found: {:?})",
        all_creds
    );
}

#[test]
fn multiple_homoglyphs_in_single_chunk() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // Multiple distinct homoglyphs in one chunk
    let chunk = make_chunk(
        concat!(
            "a = \"АKIAiosfodnn7example\"\n",
            "b = \"sk_live_ρ123456789abcdefghij\"\n",
            "c = \"ghp_\u{200B}aBcD1234EFgh5678ijklMNop9012qrSTuvWX\"\n",
        ),
        "homoglyph_multi.rs",
    );

    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let all_creds: Vec<String> = simd_results
        .iter()
        .flat_map(|v| v.iter().map(|m| m.credential.as_ref().to_string()))
        .collect();

    let has_cyrillic = all_creds.iter().any(|c| c.contains('А'));
    let has_greek = all_creds.iter().any(|c| c.contains("ρ"));
    let has_zwsp = all_creds.iter().any(|c| c.contains('\u{200B}'));

    assert!(
        has_cyrillic && has_greek && has_zwsp,
        "all three homoglyph types must be detected (found: {:?})",
        all_creds
    );
}

// ============================================================================
// CPU/GPU PARITY TESTS: backends must produce identical results
// ============================================================================

#[test]
fn cpu_gpu_parity_on_cyrillic_homoglyph() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let chunk = make_chunk(
        "aws_key = \"АKIAiosfodnn7example\"",
        "parity_cyrillic.rs",
    );

    let (simd_keys, gpu_keys) = scan_both_backends(&scanner, &chunk);

    if !gpu_keys.is_empty() || !simd_keys.is_empty() {
        assert_eq!(
            simd_keys, gpu_keys,
            "CPU and GPU must find identical homoglyph credentials (CPU: {:?}, GPU: {:?})",
            simd_keys, gpu_keys
        );
    }
}

#[test]
fn cpu_gpu_parity_on_greek_homoglyph() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let chunk = make_chunk(
        "stripe = \"sk_live_ρ123456789abcdefghij\"",
        "parity_greek.rs",
    );

    let (simd_keys, gpu_keys) = scan_both_backends(&scanner, &chunk);

    if !gpu_keys.is_empty() || !simd_keys.is_empty() {
        assert_eq!(
            simd_keys, gpu_keys,
            "CPU and GPU must find identical Greek homoglyphs (CPU: {:?}, GPU: {:?})",
            simd_keys, gpu_keys
        );
    }
}

#[test]
fn cpu_gpu_parity_on_zero_width_space() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let chunk = make_chunk(
        "github = \"ghp_\u{200B}aBcD1234EFgh5678ijklMNop9012qrSTuvWX\"",
        "parity_zwsp.rs",
    );

    let (simd_keys, gpu_keys) = scan_both_backends(&scanner, &chunk);

    if !gpu_keys.is_empty() || !simd_keys.is_empty() {
        assert_eq!(
            simd_keys, gpu_keys,
            "CPU and GPU must find identical zero-width-space credentials (CPU: {:?}, GPU: {:?})",
            simd_keys, gpu_keys
        );
    }
}

#[test]
fn cpu_gpu_parity_on_rtl_mark() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let chunk = make_chunk(
        "api = \"sk_live_\u{200F}4eC39HqLyjWDarjtT1zdp7dc\"",
        "parity_rtl.rs",
    );

    let (simd_keys, gpu_keys) = scan_both_backends(&scanner, &chunk);

    if !gpu_keys.is_empty() || !simd_keys.is_empty() {
        assert_eq!(
            simd_keys, gpu_keys,
            "CPU and GPU must find identical RTL-mark credentials (CPU: {:?}, GPU: {:?})",
            simd_keys, gpu_keys
        );
    }
}

#[test]
fn cpu_gpu_parity_on_mixed_homoglyphs() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let chunk = make_chunk(
        concat!(
            "k1=\"АKIAiosfodnn7example\"\n",
            "k2=\"sk_live_ρ123456789abcdefghij\"\n",
            "k3=\"ghp_\u{200B}aBcD1234EFgh5678ijklMNop9012qrSTuvWX\"\n",
            "k4=\"sk_live_\u{200F}4eC39HqLyjWDarjtT1zdp7dc\"\n"
        ),
        "parity_mixed.rs",
    );

    let (simd_keys, gpu_keys) = scan_both_backends(&scanner, &chunk);

    assert_eq!(
        simd_keys, gpu_keys,
        "CPU and GPU must find identical results on mixed homoglyphs (CPU: {:?}, GPU: {:?})",
        simd_keys, gpu_keys
    );
}

// ============================================================================
// ADVERSARIAL TESTS: intentional evasion attempts must still be caught
// ============================================================================

#[test]
fn mixed_scripts_cyrillic_and_latin() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // Mixing Cyrillic and Latin in a single key: "АКia0123456789abcdef"
    let chunk = make_chunk(
        "key = \"АКia0123456789abcdef\"",
        "mixed_scripts.rs",
    );

    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let all_creds: Vec<String> = simd_results
        .iter()
        .flat_map(|v| v.iter().map(|m| m.credential.as_ref().to_string()))
        .collect();

    // Even with mixed scripts, the credential should be detected if it matches a pattern.
    let found = !all_creds.is_empty();

    assert!(
        found,
        "mixed Cyrillic/Latin scripts should trigger detection (found: {:?})",
        all_creds
    );
}

#[test]
fn homoglyph_with_leading_zero_width_chars() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // "AKIA" with prefix zero-width space: "\u{200B}AKIA..."
    let chunk = make_chunk(
        "key = \"\u{200B}AKIAiosfodnn7example\"",
        "zw_prefix.rs",
    );

    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let all_creds: Vec<String> = simd_results
        .iter()
        .flat_map(|v| v.iter().map(|m| m.credential.as_ref().to_string()))
        .collect();

    let found = all_creds.iter().any(|c| c.contains("AKIA"));

    assert!(
        found,
        "credential with leading zero-width space must be detected (found: {:?})",
        all_creds
    );
}

#[test]
fn homoglyph_interleaved_invisible_chars() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // "sk_live_" with zero-width space after prefix: "sk_live_\u{200B}4eC39HqLyjWDarjtT1zdp7dc"
    let chunk = make_chunk(
        "secret = \"sk_live_\u{200B}4eC39HqLyjWDarjtT1zdp7dc\"",
        "interleaved_zw.rs",
    );

    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let all_creds: Vec<String> = simd_results
        .iter()
        .flat_map(|v| v.iter().map(|m| m.credential.as_ref().to_string()))
        .collect();

    let found = all_creds.iter().any(|c| c.contains("sk_live_"));

    assert!(
        found,
        "credential with interleaved zero-width chars must be detected (found: {:?})",
        all_creds
    );
}

// ============================================================================
// OFFSET ACCURACY TESTS: ensure reported offsets are correct
// ============================================================================

#[test]
fn homoglyph_credential_offset_accuracy() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // Position of the credential is known: after "key = \""
    let text = "key = \"АKIAiosfodnn7example\"";
    let chunk = make_chunk(text, "offset_test.rs");

    let simd_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let matches: Vec<&RawMatch> = simd_results
        .iter()
        .flat_map(|v| v.iter())
        .collect();

    let found = matches.iter().any(|m| {
        m.credential.as_ref().contains('А') && m.location.offset == 7
    });

    assert!(
        found,
        "homoglyph credential offset must be correct (matches: {:?})",
        matches.iter().map(|m| (m.credential.as_ref(), m.location.offset)).collect::<Vec<_>>()
    );
}

// ============================================================================
// GPU-SPECIFIC TESTS (conditional on GPU availability)
// ============================================================================

#[test]
#[cfg(feature = "gpu")]
fn gpu_homoglyph_detection_available() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU available");
        return;
    }

    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let chunk = make_chunk(
        "key = \"АKIAiosfodnn7example\"",
        "gpu_available.rs",
    );

    let gpu_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::Gpu);
    let gpu_creds: Vec<String> = gpu_results
        .iter()
        .flat_map(|v| v.iter().map(|m| m.credential.as_ref().to_string()))
        .collect();

    let found = gpu_creds.iter().any(|c| c.contains('А'));

    assert!(
        found,
        "GPU must detect homoglyph Cyrillic credentials (found: {:?})",
        gpu_creds
    );
}

#[test]
#[cfg(feature = "gpu")]
fn gpu_parity_comprehensive_homoglyph_corpus() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU available");
        return;
    }

    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let chunks = vec![
        make_chunk("aws_key = \"АKIAiosfodnn7example\"", "cyrillic.rs"),
        make_chunk("stripe = \"sk_live_ρ123456789abcdefghij\"", "greek.rs"),
        make_chunk("github = \"ghp_\u{200B}aBcD1234EFgh5678ijklMNop9012qrSTuvWX\"", "zwsp.rs"),
        make_chunk("api = \"sk_live_\u{200F}4eC39HqLyjWDarjtT1zdp7dc\"", "rtl.rs"),
    ];

    let simd_results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let simd_keys = collect_keys(&simd_results);

    let gpu_results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::Gpu);
    let gpu_keys = collect_keys(&gpu_results);

    assert_eq!(
        simd_keys, gpu_keys,
        "GPU and CPU must have identical findings on comprehensive homoglyph corpus (CPU: {:?}, GPU: {:?})",
        simd_keys, gpu_keys
    );

    assert!(
        !simd_keys.is_empty(),
        "comprehensive homoglyph corpus must produce findings on at least one backend"
    );
}
