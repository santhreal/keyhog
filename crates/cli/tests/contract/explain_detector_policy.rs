//! The shipped explainer must expose detector-local admission policy, not only
//! regexes. Operators tune generic detection in the owning detector TOML.

use std::path::PathBuf;
use std::process::{Command, Output};

fn explain(detector_id: &str) -> Output {
    let detectors = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("detectors");
    Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .args(["explain", detector_id, "--detectors"])
        .arg(detectors)
        .output()
        .unwrap_or_else(|error| panic!("run keyhog explain {detector_id}: {error}"))
}

fn detector_bpe_ceiling(detector_id: &str) -> f64 {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("detectors")
        .join(format!("{detector_id}.toml"));
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let document: toml::Value =
        toml::from_str(&source).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
    document["detector"]["bpe_max_bytes_per_token"]
        .as_float()
        .unwrap_or_else(|| {
            panic!(
                "{} must declare detector.bpe_max_bytes_per_token",
                path.display()
            )
        })
}

#[test]
fn explain_generic_secret_prints_detector_owned_entropy_and_bpe_policy() {
    let output = explain("generic-secret");

    assert_eq!(
        output.status.code(),
        Some(0),
        "explain failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let bpe_ceiling = detector_bpe_ceiling("generic-secret");
    for expected in [
        "Declared detector policy:".to_string(),
        "kind: phase2-generic".to_string(),
        "entropy_high: 4.5 bits/byte".to_string(),
        "entropy_low: 3 bits/byte".to_string(),
        "plausibility:".to_string(),
        "symbolic_entropy_floor: 3.5 bits/byte".to_string(),
        "second_half_entropy_floor: 2.5 bits/byte".to_string(),
        "mixed_alnum_min_len: 20 bytes".to_string(),
        "isolated_mixed_entropy_floor: 3.65 bits/byte".to_string(),
        "isolated_symbolic_min_len: 18 bytes".to_string(),
        "isolated_colon_left_min_len: 20 bytes".to_string(),
        "isolated_colon_right_min_len: 16 bytes".to_string(),
        "leading_slash_base64_entropy_floor: 4.8 bits/byte".to_string(),
        format!("bpe_max_bytes_per_token: {bpe_ceiling} UTF-8 bytes/token"),
        "max_len: 512 bytes".to_string(),
        "canonical_hex_key_material: lengths=[32, 48] keywords=[secret, private_key, signing_secret] suffixes=[key, secret] excluded_keywords=[license_key]".to_string(),
        "canonical_hex_key_material: lengths=[64] keywords=[private_key, signing_secret]"
            .to_string(),
        "entropy_floor: 2.8 bits/byte through 24 bytes".to_string(),
        "entropy_fallback: class=generic id=entropy-generic name=\"Generic High-Entropy Secret\" service=generic".to_string(),
        "declared policy owner: [detector] in the loaded detector TOML".to_string(),
        "unset optional fields: field defaults or scan policy resolve at scan time; use `config --effective` for scan-fallback/scan-override".to_string(),
    ] {
        assert!(
            stdout.contains(&expected),
            "explain output is missing {expected:?}:\n{stdout}"
        );
    }
}

#[test]
fn explain_generic_api_key_prints_transport_and_direct_hex_policy() {
    let output = explain("generic-api-key");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "decoded_hex_key_material_lengths: 32, 48",
        "canonical_hex_key_material: lengths=[32, 48] keywords=[api_key, access_key, secret_key, client_secret, x-api-key, auth_key, signing_key, encryption_key, master_key, session_key, hmac_secret, hmac_seed] suffixes=[key, secret] excluded_keywords=[license_key]",
        "canonical_hex_key_material: lengths=[64]",
        "entropy_fallback: class=api-key id=entropy-api-key",
    ] {
        assert!(
            stdout.contains(expected),
            "generic API-key explanation is missing {expected:?}:\n{stdout}"
        );
    }
}

#[test]
fn explain_distinguishes_absent_detector_policy_from_resolved_scan_fallback() {
    let output = explain("123formbuilder-api-key");

    assert_eq!(
        output.status.code(),
        Some(0),
        "explain failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("declared detector fields: none"),
        "explain must identify an empty detector-local policy without inventing defaults:\n{stdout}"
    );
    assert!(
        stdout.contains(
            "unset optional fields: field defaults or scan policy resolve at scan time; use `config --effective` for scan-fallback/scan-override"
        ),
        "explain must state when values are resolved by scan policy:\n{stdout}"
    );
    assert!(
        !stdout.contains("scan defaults apply"),
        "the ambiguous retired label must not hide runtime precedence:\n{stdout}"
    );
}

#[test]
fn explain_password_reports_explicit_bpe_disablement() {
    let output = explain("generic-password");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("bpe_enabled: false"),
        "password policy must expose explicit BPE disablement:\n{stdout}"
    );
    assert!(
        !stdout.contains("bpe_max_bytes_per_token:"),
        "disabled policy must not retain a magic BPE ceiling:\n{stdout}"
    );
}

#[test]
fn every_generic_entropy_owner_exposes_complete_toml_policy() {
    for (detector_id, class) in [
        ("generic-api-key", "api-key"),
        ("generic-keyword-secret", "token"),
        ("generic-password", "password"),
        ("generic-secret", "generic"),
    ] {
        let output = explain(detector_id);
        assert_eq!(
            output.status.code(),
            Some(0),
            "explain failed for {detector_id}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        for field in [
            "entropy_high:",
            "entropy_low:",
            "entropy_very_high:",
            "plausibility:",
            "mixed_alnum_floor:",
            "symbolic_entropy_floor:",
            "second_half_entropy_floor:",
            "mixed_alnum_min_len:",
            "isolated_mixed_entropy_floor:",
            "isolated_symbolic_min_len:",
            "isolated_colon_left_min_len:",
            "isolated_colon_right_min_len:",
            "leading_slash_base64_entropy_floor:",
            "reject_repeated_blocks:",
            "allow_alphabetic_credential:",
            "reject_program_identifiers:",
            "reject_dash_segmented_alnum:",
            "entropy_policy_priority:",
        ] {
            assert!(
                stdout.contains(field),
                "{detector_id} must expose TOML-owned {field} in explain output:\n{stdout}"
            );
        }
        assert!(
            stdout.contains("declared policy owner: [detector] in the loaded detector TOML"),
            "{detector_id} must identify the detector TOML as policy owner:\n{stdout}"
        );
        assert!(
            stdout.contains(&format!("entropy_fallback: class={class}")),
            "{detector_id} must expose its typed entropy-fallback class:\n{stdout}"
        );
    }
}
