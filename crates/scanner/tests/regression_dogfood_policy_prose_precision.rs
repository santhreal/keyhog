//! Dogfood precision regression: policy/config prose and public schema/template
//! identifiers must not surface as `entropy-*` or `generic-secret` findings
//! merely because the surrounding key contains `token`, `secret`, or `key`.

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn findings_for(scanner: &CompiledScanner, text: &str) -> Vec<(String, String)> {
    let chunk: Chunk = make_chunk(text, "filesystem", "policy.toml");
    scanner.clear_fragment_cache();
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}

fn assert_no_exact_credential(scanner: &CompiledScanner, line: &str, credential: &str) {
    let findings = findings_for(scanner, line);
    assert!(
        findings.iter().all(|(_, found)| found != credential),
        "dogfood precision value {credential:?} must not surface from {line:?}; findings: {findings:#?}"
    );
}

fn assert_no_credential_prefix(scanner: &CompiledScanner, line: &str, prefix: &str) {
    let findings = findings_for(scanner, line);
    assert!(
        findings.iter().all(|(_, found)| !found.starts_with(prefix)),
        "template prefix {prefix:?} must not surface from {line:?}; findings: {findings:#?}"
    );
}

#[test]
fn policy_train_case_strings_do_not_surface_as_entropy_or_generic_secrets() {
    let scanner = scanner();
    for value in [
        "ExecStart-points-to-public-vyre-binary-or-verified-install-path",
        "ConfigMap-values-carry-non-secret-Tier-A-runtime-knobs-only",
        "CPUWeight-MemoryMax-TasksMax-and-runtime-timeout-declared",
        "package-files-and-postinstall-behavior-exclude-private-Santh-and-secrets",
        "DynamicUser-or-dedicated-unprivileged-user-required-for-daemon-mode",
    ] {
        assert_no_exact_credential(&scanner, &format!("api_key_policy = \"{value}\""), value);
    }
}

#[test]
fn public_schema_version_identifiers_do_not_surface_as_generic_secrets() {
    let scanner = scanner();
    for value in [
        "vyre-archive-replay-audits:v1",
        "vyre-runtime-release-policy:v2",
        "santh-install-contract:v12",
    ] {
        assert_no_exact_credential(&scanner, &format!("schema_token = \"{value}\""), value);
    }
}

#[test]
fn shell_template_values_do_not_surface_as_literal_secrets() {
    let scanner = scanner();
    assert_no_credential_prefix(
        &scanner,
        r#"VYRE_RELEASE_PUBLISH_APPROVAL_TOKEN="publish-vyre-${VERSION}-weir-${BUILD}""#,
        "publish-vyre",
    );
    assert_no_credential_prefix(
        &scanner,
        r#"LAUNCH_APPROVAL_TOKEN="launch-vyre-$(date +%s)""#,
        "launch-vyre",
    );
}

#[test]
fn encoded_markup_and_html_event_fragments_do_not_surface_as_secrets() {
    let scanner = scanner();
    for value in [
        "%253Cscript%253E",
        "%3Cimg%20src=x%20onerror=alert%281%29%3E",
    ] {
        assert_no_exact_credential(&scanner, &format!("payload = \"{value}\""), value);
    }
    assert_no_exact_credential(&scanner, r#"token = "onfocus=""#, "onfocus=");
}

#[test]
fn random_hyphenated_password_under_keyword_still_surfaces() {
    let scanner = scanner();
    let credential = "aapqhgn-qhuuc-trnmf";
    let findings = findings_for(&scanner, &format!("GRAPHITE_PASS={credential}"));
    assert!(
        findings
            .iter()
            .any(|(id, found)| id == "generic-secret" && found == credential),
        "random hyphenated password must still surface; findings: {findings:#?}"
    );
}
