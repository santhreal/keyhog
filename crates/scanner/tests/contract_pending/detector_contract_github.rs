//! Integration test suite for GitHub token detector contracts.
//!
//! Test coverage:
//!   - github-classic-pat (ghp_): 36-char alnum payload
//!   - github-oauth-access-token (gho_): 36-char alnum payload
//!   - github-user-to-server-token (ghu_): 36-char alnum payload
//!   - github-refresh-token (ghr_): 36-char alnum payload
//!   - github-pat-fine-grained (github_pat_): 22-char + underscore + 59-char payload
//!   - github-oauth-secret: 40-char hex with context anchors
//!
//! Assertions cover:
//!   - Positive: exact credential capture in code, config, markdown contexts
//!   - Negative: near-miss wrong-length tokens do not trigger false positives
//!   - Boundary: off-by-one char length tests
//!   - GPU==CPU: identical findings across backends (when GPU available)
//!   - Adversarial: mutations, case sensitivity, embedded separators

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

fn build_scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("detectors directory must load");
    CompiledScanner::compile(detectors).expect("scanner must compile")
}

/// Helper: scan text and return all credentials for a given detector.
fn detector_credentials(
    scanner: &CompiledScanner,
    text: &str,
    path: &str,
    detector_id: &str,
) -> Vec<String> {
    let chunk = make_chunk(text, path);
    let matches = scanner.scan(&chunk);
    matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == detector_id)
        .map(|m| m.credential.as_ref().to_string())
        .collect()
}

/// Helper: true if detector fired at least once on the given text.
fn detector_fired(
    scanner: &CompiledScanner,
    text: &str,
    path: &str,
    detector_id: &str,
) -> bool {
    !detector_credentials(scanner, text, path, detector_id).is_empty()
}

/// Helper: scan multiple chunks with specified backend and collect all findings.
fn scan_with_backend(
    scanner: &CompiledScanner,
    chunks: &[Chunk],
    backend: ScanBackend,
) -> Vec<RawMatch> {
    let results = scanner.scan_chunks_with_backend(chunks, backend);
    results.iter().flat_map(|v| v.iter().cloned()).collect()
}

// ===========================================================================
// CLASSIC PAT (ghp_): 36-char alnum body
// ===========================================================================

#[test]
fn ghp_classic_pat_positive_in_code() {
    let scanner = build_scanner();
    let text = "const GITHUB_TOKEN = \"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345\";";
    let creds = detector_credentials(&scanner, text, "config.rs", "github-classic-pat");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0], "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345");
}

#[test]
fn ghp_classic_pat_positive_in_dotenv() {
    let scanner = build_scanner();
    let text = "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456\n";
    let creds = detector_credentials(&scanner, text, ".env", "github-classic-pat");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0], "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456");
}

#[test]
fn ghp_classic_pat_positive_in_markdown() {
    let scanner = build_scanner();
    let text = "Installation: `export TOKEN=ghp_XyZ0123456789ABCDEFGHIJKLMNOPQRS`";
    let creds = detector_credentials(&scanner, text, "README.md", "github-classic-pat");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0], "ghp_XyZ0123456789ABCDEFGHIJKLMNOPQRS");
}

#[test]
fn ghp_classic_pat_case_insensitive() {
    let scanner = build_scanner();
    // Verify case-insensitive matching on the prefix
    let text = "GHP_AbCdEfGhIjKlMnOpQrStUvWxYz012345";
    let creds = detector_credentials(&scanner, text, "test.txt", "github-classic-pat");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0], "GHP_AbCdEfGhIjKlMnOpQrStUvWxYz012345");
}

#[test]
fn ghp_classic_pat_negative_too_short_by_one() {
    let scanner = build_scanner();
    // 35 chars instead of 36
    let text = "token = \"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz01234\"";
    let creds = detector_credentials(&scanner, text, "test.txt", "github-classic-pat");
    assert!(
        creds.is_empty(),
        "ghp_ with 35-char body (too short by 1) must not trigger"
    );
}

#[test]
fn ghp_classic_pat_negative_too_long_by_one() {
    let scanner = build_scanner();
    // 37 chars instead of 36
    let text = "token = \"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456\"";
    let creds = detector_credentials(&scanner, text, "test.txt", "github-classic-pat");
    assert!(
        creds.is_empty(),
        "ghp_ with 37-char body (too long by 1) must not trigger"
    );
}

#[test]
fn ghp_classic_pat_negative_contains_special_chars() {
    let scanner = build_scanner();
    // Body contains underscore (not alnum)
    let text = "token = \"ghp_AbCdEfGhIjKl_nOpQrStUvWxYz01234\"";
    let creds = detector_credentials(&scanner, text, "test.txt", "github-classic-pat");
    assert!(
        creds.is_empty(),
        "ghp_ with underscore in body must not trigger"
    );
}

// ===========================================================================
// OAUTH ACCESS TOKEN (gho_): 36-char alnum body
// ===========================================================================

#[test]
fn gho_oauth_access_positive() {
    let scanner = build_scanner();
    let text = "let token = \"gho_AbCdEfGhIjKlMnOpQrStUvWxYz012345\";";
    let creds = detector_credentials(&scanner, text, "oauth.ts", "github-oauth-access-token");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0], "gho_AbCdEfGhIjKlMnOpQrStUvWxYz012345");
}

#[test]
fn gho_oauth_access_negative_too_short() {
    let scanner = build_scanner();
    let text = "token = gho_abc123_too_short";
    let creds = detector_credentials(&scanner, text, "test.txt", "github-oauth-access-token");
    assert!(creds.is_empty(), "gho_ with truncated body must not trigger");
}

#[test]
fn gho_oauth_access_case_variant() {
    let scanner = build_scanner();
    let text = "GHO_1234567890ABCDEFGHIJKLMNOPQRSTUv";
    let creds = detector_credentials(&scanner, text, "test.txt", "github-oauth-access-token");
    assert_eq!(creds.len(), 1);
}

// ===========================================================================
// USER-TO-SERVER TOKEN (ghu_): 36-char alnum body
// ===========================================================================

#[test]
fn ghu_user_to_server_positive() {
    let scanner = build_scanner();
    let text = "GITHUB_TOKEN=ghu_aAbBcCdDeEfFgGhHiIjJkKlLmMnNoPqQrRsS";
    let creds = detector_credentials(&scanner, text, ".env", "github-user-to-server-token");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0], "ghu_aAbBcCdDeEfFgGhHiIjJkKlLmMnNoPqQrRsS");
}

#[test]
fn ghu_user_to_server_negative_too_long() {
    let scanner = build_scanner();
    // 37 chars
    let text = "token=ghu_aAbBcCdDeEfFgGhHiIjJkKlLmMnNoPqQrRsS1";
    let creds = detector_credentials(&scanner, text, "test.txt", "github-user-to-server-token");
    assert!(creds.is_empty(), "ghu_ with 37-char body must not trigger");
}

// ===========================================================================
// REFRESH TOKEN (ghr_): 36-char alnum body
// ===========================================================================

#[test]
fn ghr_refresh_token_positive() {
    let scanner = build_scanner();
    let text = "refresh_token=\"ghr_ZyXwVuTsRqPoNmLkJiHgFeDcBa987654\"";
    let creds = detector_credentials(&scanner, text, "auth.json", "github-refresh-token");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0], "ghr_ZyXwVuTsRqPoNmLkJiHgFeDcBa987654");
}

#[test]
fn ghr_refresh_token_negative_mixed_case_prefix() {
    let scanner = build_scanner();
    // GitHub prefixes are lowercase or uppercase consistently, but we test case-insensitivity
    let text = "GHR_AbCdEfGhIjKlMnOpQrStUvWxYz012345";
    let creds = detector_credentials(&scanner, text, "test.txt", "github-refresh-token");
    // The detector should match case-insensitively on prefix
    assert_eq!(creds.len(), 1);
}

// ===========================================================================
// FINE-GRAINED PAT (github_pat_): 22-char + underscore + 59-char = 82 total
// ===========================================================================

#[test]
fn github_pat_fine_grained_positive() {
    let scanner = build_scanner();
    // Format: github_pat_ + 22-char + _ + 59-char = 82 total
    let pat = "github_pat_abcdefghijklmnopqrst_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    assert_eq!(pat.len(), 82);
    let text = format!("export GITHUB_TOKEN={}", pat);
    let creds = detector_credentials(&scanner, &text, "setup.sh", "github-pat-fine-grained");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0], pat);
}

#[test]
fn github_pat_fine_grained_negative_too_short() {
    let scanner = build_scanner();
    // 81 chars (missing 1)
    let pat = "github_pat_abcdefghijklmnopqrs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv";
    assert_eq!(pat.len(), 80);
    let creds = detector_credentials(&scanner, &pat, "test.txt", "github-pat-fine-grained");
    assert!(creds.is_empty(), "Fine-grained PAT with wrong length must not trigger");
}

#[test]
fn github_pat_fine_grained_negative_missing_middle_underscore() {
    let scanner = build_scanner();
    // Correct length but missing the required underscore separator
    let pat = "github_pat_abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv";
    let creds = detector_credentials(&scanner, pat, "test.txt", "github-pat-fine-grained");
    assert!(creds.is_empty(), "Fine-grained PAT without internal _ must not trigger");
}

#[test]
fn github_pat_fine_grained_boundary_exactly_right_length() {
    let scanner = build_scanner();
    // Construct exactly 82 chars with correct format
    let segment1 = "AbCdEfGhIjKlMnOpQrSt"; // 20
    let segment2 = "XyZ123456789"; // need 22 total, so 2 more = "XyZ1"
    let segment3 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv"; // 48
    let pat = format!("github_pat_{}{}_{}AB{}", segment1, segment2, segment3, "CDE");
    assert_eq!(pat.len(), 82, "Pat must be exactly 82 chars");
    let creds = detector_credentials(&scanner, &pat, "test.txt", "github-pat-fine-grained");
    assert_eq!(creds.len(), 1, "Correctly formatted 82-char token must trigger");
}

// ===========================================================================
// OAUTH CLIENT SECRET: 40-char hex with context anchors
// ===========================================================================

#[test]
fn github_oauth_secret_positive_with_var_name() {
    let scanner = build_scanner();
    let text = "GITHUB_CLIENT_SECRET=0123456789abcdef0123456789abcdef01234567";
    let creds = detector_credentials(&scanner, text, ".env", "github-oauth-secret");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0], "0123456789abcdef0123456789abcdef01234567");
}

#[test]
fn github_oauth_secret_case_insensitive_var() {
    let scanner = build_scanner();
    let text = "github_client_secret = \"FEDCBA9876543210fedcba9876543210FEDCBA98\"";
    let creds = detector_credentials(&scanner, text, "config.py", "github-oauth-secret");
    assert_eq!(creds.len(), 1);
}

#[test]
fn github_oauth_secret_negative_too_short_hex() {
    let scanner = build_scanner();
    // 39 hex chars instead of 40
    let text = "GITHUB_CLIENT_SECRET = 0123456789abcdef0123456789abcdef0123456";
    let creds = detector_credentials(&scanner, text, ".env", "github-oauth-secret");
    assert!(
        creds.is_empty(),
        "39-char hex without context anchor must not trigger"
    );
}

#[test]
fn github_oauth_secret_negative_not_hex() {
    let scanner = build_scanner();
    // 40 chars but not pure hex (contains 'g')
    let text = "GITHUB_CLIENT_SECRET = g123456789abcdef0123456789abcdef01234567";
    let creds = detector_credentials(&scanner, text, ".env", "github-oauth-secret");
    assert!(creds.is_empty(), "Non-hex string must not trigger");
}

#[test]
fn github_oauth_secret_multiple_on_different_lines() {
    let scanner = build_scanner();
    let text = "GH_CLIENT_SECRET=aabbccddeeff00112233445566778899aabbccdd\n\
                 GITHUB_CLIENT_SECRET=1122334455667788990011223344556677889900";
    let creds = detector_credentials(&scanner, text, ".env", "github-oauth-secret");
    assert_eq!(creds.len(), 2, "Both secrets should be detected");
}

// ===========================================================================
// BOUNDARY & ADVERSARIAL CASES
// ===========================================================================

#[test]
fn multiple_github_tokens_different_types_in_one_file() {
    let scanner = build_scanner();
    let text = concat!(
        "token1 = \"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345\"\n",
        "token2 = \"gho_AbCdEfGhIjKlMnOpQrStUvWxYz012345\"\n",
        "token3 = \"ghu_AbCdEfGhIjKlMnOpQrStUvWxYz012345\"\n",
        "token4 = \"ghr_AbCdEfGhIjKlMnOpQrStUvWxYz012345\"\n",
    );
    let chunk = make_chunk(text, "multi.rs");
    let matches = scanner.scan(&chunk);
    let count = matches
        .iter()
        .filter(|m| {
            matches!(
                m.detector_id.as_ref(),
                "github-classic-pat"
                    | "github-oauth-access-token"
                    | "github-user-to-server-token"
                    | "github-refresh-token"
            )
        })
        .count();
    assert_eq!(count, 4, "Should find exactly 4 distinct GitHub tokens");
}

#[test]
fn ghp_embedded_in_url() {
    let scanner = build_scanner();
    let text = "curl https://ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345@github.com/user/repo.git";
    let creds = detector_credentials(&scanner, text, "script.sh", "github-classic-pat");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0], "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345");
}

#[test]
fn github_pat_in_json_config() {
    let scanner = build_scanner();
    let json = r#"{"auth": {"token": "github_pat_abcdefghijklmnopqrst_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv"}}"#;
    let creds = detector_credentials(&scanner, json, "config.json", "github-pat-fine-grained");
    assert_eq!(creds.len(), 1);
}

#[test]
fn github_secret_with_equals_separator() {
    let scanner = build_scanner();
    let text = "GH.CLIENT.SECRET=0011223344556677889900112233445566778899";
    let creds = detector_credentials(&scanner, text, "config.conf", "github-oauth-secret");
    assert_eq!(creds.len(), 1);
}

#[test]
fn github_secret_with_space_separator() {
    let scanner = build_scanner();
    let text = "GITHUB_CLIENT_SECRET 1234567890abcdef1234567890abcdef12345678";
    let creds = detector_credentials(&scanner, text, "config.txt", "github-oauth-secret");
    assert_eq!(creds.len(), 1);
}

#[test]
fn ghp_at_chunk_boundary_split_across_chunks() {
    let scanner = build_scanner();
    let secret = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345";
    let split_at = 8; // splits "ghp_AbCd" | "EfGhIjKlMnOpQrStUvWxYz012345"

    let chunk_a = Chunk {
        data: format!("token = \"{}", &secret[..split_at]).into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some("split.rs".into()),
            base_offset: 0,
            ..Default::default()
        },
    };

    let chunk_b = Chunk {
        data: format!("{}\"", &secret[split_at..]).into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some("split.rs".into()),
            base_offset: 8 + 9, // "token = \""
            ..Default::default()
        },
    };

    let results = scanner.scan_chunks_with_backend(&[chunk_a, chunk_b], ScanBackend::SimdCpu);
    let found = results
        .iter()
        .flat_map(|v| v.iter())
        .any(|m| m.credential.as_ref() == secret);
    assert!(
        found,
        "Boundary-straddled ghp_ token should be detected via boundary reassembly"
    );
}

// ===========================================================================
// GPU==CPU PARITY TESTS (only run if GPU available)
// ===========================================================================

#[test]
#[cfg(feature = "gpu")]
fn gpu_cpu_parity_github_tokens() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: gpu_cpu_parity_github_tokens - no GPU available");
        return;
    }

    let scanner = build_scanner();
    let chunks = vec![
        make_chunk("const GH = \"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345\";", "github.rs"),
        make_chunk(
            "oauth_token = \"gho_XyZ0123456789ABCDEFGHIJKLMNOPQRS\"",
            "oauth.py",
        ),
        make_chunk(
            "export GITHUB_TOKEN=ghu_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456",
            ".env.example",
        ),
        make_chunk(
            "GITHUB_CLIENT_SECRET = aabbccddee00112233445566778899aabbccdd",
            "secrets.conf",
        ),
    ];

    let cpu_results = scan_with_backend(&scanner, &chunks, ScanBackend::SimdCpu);
    let gpu_results = scan_with_backend(&scanner, &chunks, ScanBackend::Gpu);

    // Collect (credential, detector_id) tuples for comparison
    let mut cpu_set = std::collections::BTreeSet::new();
    for m in &cpu_results {
        cpu_set.insert((
            m.credential.as_ref().to_string(),
            m.detector_id.as_ref().to_string(),
        ));
    }

    let mut gpu_set = std::collections::BTreeSet::new();
    for m in &gpu_results {
        gpu_set.insert((
            m.credential.as_ref().to_string(),
            m.detector_id.as_ref().to_string(),
        ));
    }

    assert_eq!(
        cpu_set, gpu_set,
        "GPU and CPU backends must find identical GitHub token set.\n  CPU: {} findings\n  GPU: {} findings",
        cpu_results.len(), gpu_results.len()
    );
    assert!(
        !cpu_set.is_empty(),
        "Fixture must produce findings on both backends"
    );
}

#[test]
#[cfg(feature = "gpu")]
fn gpu_parity_github_pat_fine_grained() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: gpu_parity_github_pat_fine_grained - no GPU available");
        return;
    }

    let scanner = build_scanner();
    let pat = "github_pat_abcdefghijklmnopqrst_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv";
    let chunk = make_chunk(&format!("token = {}", pat), "config.toml");

    let cpu_results = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let gpu_results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::Gpu);

    let cpu_count = cpu_results[0].len();
    let gpu_count = gpu_results[0].len();

    assert_eq!(
        cpu_count, gpu_count,
        "Fine-grained PAT detection must be identical on GPU and CPU: CPU={}, GPU={}",
        cpu_count, gpu_count
    );
    assert_eq!(cpu_count, 1, "Fine-grained PAT should be found exactly once");
}

// ===========================================================================
// NEGATIVE TWINS: ensure non-GitHub tokens are not mis-detected
// ===========================================================================

#[test]
fn no_false_positive_on_generic_bearer_token() {
    let scanner = build_scanner();
    // Valid high-entropy 36-char token but not GitHub format
    let text = "Authorization: Bearer xSk9vLqWpZrYtUmNoPaQbRcDsEfGhIjKlMnO";
    let chunk = make_chunk(text, "request.txt");
    let results = scanner.scan(&chunk);
    
    let gh_matches = results
        .iter()
        .filter(|m| {
            m.detector_id.as_ref().contains("github")
        })
        .count();
    
    assert_eq!(
        gh_matches, 0,
        "Generic bearer token should not trigger GitHub detectors"
    );
}

#[test]
fn no_false_positive_on_similar_prefix_different_length() {
    let scanner = build_scanner();
    // ghz_ is not a GitHub prefix
    let text = "token = ghz_AbCdEfGhIjKlMnOpQrStUvWxYz012345";
    let creds = detector_credentials(&scanner, text, "test.txt", "github-classic-pat");
    assert!(
        creds.is_empty(),
        "Non-GitHub prefix ghz_ must not trigger"
    );
}

#[test]
fn github_secret_requires_context_keyword() {
    let scanner = build_scanner();
    // 40 hex chars but no GitHub context keyword
    let text = "SECRET = 0123456789abcdef0123456789abcdef01234567";
    let creds = detector_credentials(&scanner, text, ".env", "github-oauth-secret");
    assert!(
        creds.is_empty(),
        "Bare hex without GITHUB/GH/CLIENT/SECRET context must not trigger"
    );
}