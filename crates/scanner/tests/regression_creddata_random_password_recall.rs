//! Regression (KH-L-0413): the generic keyword bridge must SURFACE a random
//! low-entropy password that is shape-identical to a code identifier (all
//! lowercase, no digit), and must keep SUPPRESSING genuine dictionary
//! identifiers under the same credential keywords.
//!
//! Root cause this locks against: the identifier/type-name shape gates
//! (`pure_identifier_no_digit`, `pure_identifier`, `type_name_shape`,
//! `word_separated_identifier`) in `generic_value_shape_rejected` dropped EVERY
//! all-letters-no-digit value, suppressing not just `password = getUserName`
//! (a code reference) but also ~1114 real CredData passwords that happen to be
//! random lowercase strings (`GRAPHITE_PASS=gjbubxsu`, `password="ufnlbbavawsdeecn"`).
//! The two classes are shape-identical, so the gate is now conditioned on an
//! English bigram-model randomness check (`suppression::token_randomness`): a
//! RANDOM token lifts the gate (recover the password); a pronounceable
//! dictionary identifier still fires it (stay suppressed).
//!
//! Measured A/B (vs the pre-change binary): CredData TP +957 / FP +71 (93%
//! marginal precision; recall 0.181→0.250, precision 0.600→0.665) and mirror
//! precision HELD 0.9954 ≥ 0.9945, the dictionary discriminator is what makes
//! the lift sound (lifting unconditionally cost +3554 FP).

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    CompiledScanner::compile(detectors).expect("compile scanner")
}

fn scanner_with_bpe_override(bound: f64) -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let cfg = ScannerConfig::default()
        .with_entropy_bpe_max_bytes_per_token_override(bound)
        .unwrap_or_else(|error| panic!("override {bound} must be valid: {error}"));
    CompiledScanner::compile(detectors)
        .expect("compile scanner")
        .with_config(cfg)
}

fn credentials_for(scanner: &CompiledScanner, line: &str) -> Vec<String> {
    credentials_for_backend(scanner, line, ScanBackend::CpuFallback)
}

fn credentials_for_backend(
    scanner: &CompiledScanner,
    line: &str,
    backend: ScanBackend,
) -> Vec<String> {
    matches_for_backend(scanner, line, backend)
        .into_iter()
        .map(|m| m.credential.as_str().to_string())
        .collect()
}

fn matches_for_backend(
    scanner: &CompiledScanner,
    line: &str,
    backend: ScanBackend,
) -> Vec<RawMatch> {
    let chunk = Chunk {
        data: line.into(),
        metadata: ChunkMetadata::default(),
    };
    scanner.clear_fragment_cache();
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), backend)
        .into_iter()
        .flatten()
        .collect()
}

fn finding_keys_for_backend(
    scanner: &CompiledScanner,
    line: &str,
    backend: ScanBackend,
) -> Vec<(String, String, usize)> {
    let mut keys = matches_for_backend(scanner, line, backend)
        .into_iter()
        .map(|finding| {
            (
                finding.detector_id.to_string(),
                finding.credential.as_str().to_string(),
                finding.location.offset,
            )
        })
        .collect::<Vec<_>>();
    keys.sort_unstable();
    keys
}

fn caught(scanner: &CompiledScanner, line: &str, value: &str) -> bool {
    credentials_for(scanner, line).iter().any(|c| c == value)
}

#[test]
fn random_lowercase_passwords_under_keyword_are_surfaced() {
    let s = scanner();
    // Real CredData passwords: all-lowercase, no digit, IMPROBABLE English
    // bigrams (gjb, kr, bx, dz), the identifier gates dropped these before the
    // randomness discriminator. Each is keyword-anchored.
    for (line, val) in [
        ("GRAPHITE_PASS=gjbubxsu", "gjbubxsu"),
        ("JENKINS_PASS=krbykalt", "krbykalt"),
        ("password = \"ufnlbbavawsdeecn\"", "ufnlbbavawsdeecn"),
        ("self.password = \"rwwjfwpbqxzkdv\"", "rwwjfwpbqxzkdv"),
        ("SES_PASS=dzdvnffvqp", "dzdvnffvqp"),
        (
            "passphrase = \"CorrectHorseBatteryStaple!9\"",
            "CorrectHorseBatteryStaple!9",
        ),
    ] {
        assert!(
            caught(&s, line, val),
            "random lowercase password {val:?} (improbable-bigram) must surface \
             via the keyword bridge (KH-L-0413 randomness lift); line {line:?}"
        );
    }
}

#[test]
fn dictionary_identifiers_under_keyword_stay_suppressed() {
    let s = scanner();
    // Pronounceable English/code identifiers under the SAME credential keywords:
    // these are code references, NOT secrets, and must NOT bridge, the randomness
    // discriminator scores them as dictionary (high bigram probability) so the
    // identifier gate still fires. (Lifting these is the +3554-FP class the
    // unconditional lift caused.)
    for (line, val) in [
        ("password = getUserName", "getUserName"),
        ("secret = configValue", "configValue"),
        ("password = defaultPassword", "defaultPassword"),
        ("token = requestToken", "requestToken"),
        ("api_key = accessToken", "accessToken"),
        ("secret = administrator", "administrator"),
    ] {
        assert!(
            !caught(&s, line, val),
            "dictionary identifier {val:?} (pronounceable) must stay suppressed. \
             it is a code reference, not a secret; line {line:?}"
        );
    }
}

#[test]
fn detector_owned_bpe_policy_distinguishes_passphrases_from_opaque_api_keys() {
    let s = scanner();
    let value = "CorrectHorseBatteryStaple!9";
    assert!(
        caught(&s, &format!("passphrase = \"{value}\""), value),
        "the passphrase detector disables BPE because word-like passwords are legitimate"
    );
    assert!(
        !caught(&s, &format!("api_key = \"{value}\""), value),
        "the opaque API-key detector keeps BPE enabled and must reject the same language-compressible value"
    );
}

#[test]
fn explicit_scan_bpe_override_can_release_opaque_api_key_language_like_values() {
    let value = "CorrectHorseBatteryStaple!9";
    let strict = scanner();
    assert!(
        !caught(&strict, &format!("api_key = \"{value}\""), value),
        "with detector-local policy only, the language-like API-key value must remain suppressed"
    );
    let relaxed = scanner_with_bpe_override(99.0);
    assert!(
        caught(&relaxed, &format!("api_key = \"{value}\""), value),
        "a scan-wide BPE override must be the final runtime authority when explicitly set"
    );
}

#[test]
fn generic_api_key_json_envelope_obeys_the_same_bpe_policy_as_assignment() {
    let value = "CorrectHorseBatteryStaple!9";
    let assignment = format!("api_key = \"{value}\"");
    let json = format!(r#"{{"api_key": "{value}"}}"#);

    let strict = scanner();
    assert!(!caught(&strict, &assignment, value));
    assert!(
        !caught(&strict, &json, value),
        "the explicit JSON regex envelope must not bypass generic-api-key's detector-owned BPE gate"
    );
    if strict.warm_backend(ScanBackend::SimdCpu) {
        assert_eq!(
            finding_keys_for_backend(&strict, &json, ScanBackend::CpuFallback),
            finding_keys_for_backend(&strict, &json, ScanBackend::SimdCpu),
            "CPU and Hyperscan must apply the strict detector policy identically"
        );
    } else {
        eprintln!("SKIP Hyperscan parity leg: SimdCpu is unavailable on this build or host");
    }
    let canonical_hex = "cb083aad257625089dbc5234812146ca";
    assert!(
        caught(
            &strict,
            &format!(r#"{{"api_key": "{canonical_hex}"}}"#),
            canonical_hex,
        ),
        "detector-declared 32-hex key material must bypass token-efficiency suppression"
    );

    let relaxed = scanner_with_bpe_override(99.0);
    assert!(caught(&relaxed, &assignment, value));
    assert!(
        caught(&relaxed, &json, value),
        "the same explicit scan override must govern assignment and JSON producers"
    );
    let relaxed_cpu = finding_keys_for_backend(&relaxed, &json, ScanBackend::CpuFallback);
    assert!(
        relaxed_cpu
            .iter()
            .any(|(detector, credential, _)| detector == "generic-api-key" && credential == value),
        "the relaxed CPU leg must contain the expected generic-api-key finding"
    );
    if relaxed.warm_backend(ScanBackend::SimdCpu) {
        assert_eq!(
            relaxed_cpu,
            finding_keys_for_backend(&relaxed, &json, ScanBackend::SimdCpu),
            "CPU and Hyperscan must apply the relaxed scan override identically"
        );
    } else {
        eprintln!("SKIP Hyperscan parity leg: SimdCpu is unavailable on this build or host");
    }
}

#[test]
fn explicit_scan_bpe_override_does_not_enable_bpe_for_generically_disabled_detectors() {
    let value = "CorrectHorseBatteryStaple!9";
    let relaxed = scanner_with_bpe_override(99.0);
    assert!(
        caught(&relaxed, &format!("passphrase = \"{value}\""), value),
        "generic-password-owned BPE disablement is detector-local and must survive a scan-wide override"
    );
}
