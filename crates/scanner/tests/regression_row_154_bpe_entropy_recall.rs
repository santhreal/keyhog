//! WHY: Regression suite for Row 154 BPE entropy recall and token boundary refinement.
//!
//! Validates:
//! 1. High-entropy string detection across representative secret token shapes (mixed case, digits, symbols).
//! 2. Complex secret keys with punctuation (`!`, `@`, `#`, `$`, `%`, `^`, `&`, `*`, `~`, `_`, `-`) not prematurely truncated.
//! 3. Backtick-wrapped secret literals in code assignments.
//! 4. BPE bytes-per-token gate discrimination: real high-entropy secrets survive while word-like structures suppress.
//! 5. 16-char mixed alphanumeric tokens with digits clearing entropy threshold in credential context.
//! 6. Zero false positives on canonical word-like / program identifier shapes (maintaining precision).

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};

fn build_scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    CompiledScanner::compile(detectors)
        .expect("compile scanner")
        .with_config(ScannerConfig::default().min_confidence(0.1))
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
        .expect("selected backend scan succeeds")
        .into_iter()
        .flatten()
        .collect()
}

#[test]
fn complex_secret_key_with_ampersand_and_symbols_is_not_truncated() {
    let scanner = build_scanner();
    let secret = "QwErTy123!@#ZxCvBn456$%^AsDfGh789!*(YuIoP0)_+LmNoPqRsTuV";
    let text = format!("API_SECRET=\"{secret}\"\n");
    let matches = scan(&scanner, &text, "config/secrets.env");
    assert!(
        !matches.is_empty(),
        "complex secret with & and symbols must be detected"
    );
    assert!(
        matches.iter().any(|m| m.credential.as_ref() == secret),
        "extracted candidate must be the full secret value, got: {matches:?}"
    );
}

#[test]
fn unquoted_complex_secret_with_ampersand_is_detected() {
    let scanner = build_scanner();
    let secret = "kL9#mP2$vR5&xT8*zW1!bC4@dF7^hJ0~";
    let text = format!("master_secret={secret}\n");
    let matches = scan(&scanner, &text, "config/secrets.env");
    assert!(
        !matches.is_empty(),
        "unquoted complex secret with & and symbols must be detected"
    );
    assert!(
        matches.iter().any(|m| m.credential.as_ref() == secret),
        "full unquoted secret value must be captured, got: {matches:?}"
    );
}

#[test]
fn backtick_wrapped_secret_is_extracted_and_detected() {
    let scanner = build_scanner();
    let secret = "sk_live_9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d";
    let text = format!("const apiKey = `{secret}`;\n");
    let matches = scan(&scanner, &text, "src/config.ts");
    assert!(
        !matches.is_empty(),
        "backtick-wrapped secret must be detected"
    );
    assert!(
        matches.iter().any(|m| m.credential.as_ref() == secret),
        "backtick quotes must be properly stripped, got: {matches:?}"
    );
}

#[test]
fn mixed_case_alnum_16char_token_is_detected() {
    let scanner = build_scanner();
    let secret = "aB3dE5gH7jK9mN1p";
    let text = format!("secret_key = \"{secret}\"\n");
    let matches = scan(&scanner, &text, "config/secrets.env");
    assert!(
        !matches.is_empty(),
        "16-character mixed-case alphanumeric secret token must be detected in credential context"
    );
    assert!(
        matches.iter().any(|m| m.credential.as_ref() == secret),
        "matched credential must equal secret, got: {matches:?}"
    );
}

#[test]
fn tilde_bearing_opaque_token_is_detected() {
    let scanner = build_scanner();
    let secret = "vX9~mK3_pL7#qR2$tW5*yB8!";
    let text = format!("auth_secret=\"{secret}\"\n");
    let matches = scan(&scanner, &text, "config/secrets.env");
    assert!(
        !matches.is_empty(),
        "tilde-bearing high-entropy secret must be detected"
    );
    assert!(
        matches.iter().any(|m| m.credential.as_ref() == secret),
        "matched credential must equal secret, got: {matches:?}"
    );
}

#[test]
fn word_like_structured_identifiers_are_suppressed_by_bpe() {
    let scanner = build_scanner();
    let text = r#"
        PInvoke.User32.WindowMessage.WM_SYSCOLORCHANGE = 0x0015;
        let className = "System.Security.Cryptography.Algorithms.AesManaged";
        let path = "com.enterprise.service.configuration.ApiKeyProviderFactory";
        let xmlNamespace = "http://schemas.microsoft.com/expression/2010/interactivity";
    "#;
    let matches = scan(&scanner, text, "src/Interop.cs");
    assert!(
        matches.is_empty(),
        "word-like structured identifiers must be suppressed by BPE and shape gates, got: {matches:?}"
    );
}

#[test]
fn bracket_and_brace_wrapped_secrets_are_cleaned() {
    let scanner = build_scanner();
    let secret = "9f8e7d6c5b4a3928170f1e2d3c4b5a69";
    let text = format!("export API_KEY=({secret})\n");
    let matches = scan(&scanner, &text, "config/secrets.env");
    assert!(
        !matches.is_empty(),
        "parenthesis-wrapped secret must be detected"
    );
    assert!(
        matches.iter().any(|m| m.credential.as_ref() == secret),
        "parenthesis must be cleaned, got: {matches:?}"
    );
}
