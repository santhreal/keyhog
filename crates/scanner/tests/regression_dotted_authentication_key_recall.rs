//! Regression: generic credential anchors must keep Discord-style dotted tokens.
//!
//! The generic shape gauntlet used to treat every non-JWT dotted value as a
//! property access. That is correct for `this.someService.copilotToken`, but it
//! silently dropped three-segment authentication tokens with the Discord bot
//! token length profile under ordinary `API_KEY`, `SECRET`, or HCL `api_key`
//! anchors.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};

const DOTTED_AUTH_TOKEN: &str = "kdMYBSw4rL4cTIi0PJYuX5Ko.4QUYAm.ma6AMslIIBXcDRHt__vJEST006b";

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    CompiledScanner::compile(detectors)
        .expect("compile scanner")
        .with_config(ScannerConfig::default().min_confidence(0.40))
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
        .into_iter()
        .flatten()
        .collect()
}

fn reports(matches: &[RawMatch], credential: &str) -> bool {
    matches
        .iter()
        .any(|m| m.credential.as_ref() == credential && m.confidence.unwrap_or_default() >= 0.40)
}

#[test]
fn api_key_dotted_authentication_token_surfaces() {
    let body = format!("API_KEY = \"{DOTTED_AUTH_TOKEN}\"\n");
    let matches = scan(&scanner(), &body, "/repo/client.py");
    assert!(
        reports(&matches, DOTTED_AUTH_TOKEN),
        "API_KEY anchored dotted auth token must report; matches={matches:?}"
    );
}

#[test]
fn hcl_api_key_dotted_authentication_token_surfaces() {
    let body = format!(
        "variable \"api_key\" {{\n  type    = string\n  default = \"{DOTTED_AUTH_TOKEN}\"\n}}\n"
    );
    let matches = scan(&scanner(), &body, "/repo/variables.tf");
    assert!(
        reports(&matches, DOTTED_AUTH_TOKEN),
        "HCL api_key default dotted auth token must report; matches={matches:?}"
    );
}

#[test]
fn yaml_bare_auth_dotted_authentication_token_surfaces() {
    let body = format!("config:\n  auth: \"{DOTTED_AUTH_TOKEN}\"\n  enabled: true\n");
    let matches = scan(&scanner(), &body, "/repo/config.yaml");
    assert!(
        reports(&matches, DOTTED_AUTH_TOKEN),
        "bare auth YAML field with structured dotted token must report; matches={matches:?}"
    );
}

#[test]
fn registry_auth_dotted_authentication_token_surfaces() {
    let body = format!(
        "name: deploy\njobs:\n  deploy:\n    env:\n      REGISTRY_AUTH: {DOTTED_AUTH_TOKEN}\n"
    );
    let matches = scan(&scanner(), &body, "/repo/workflow.yaml");
    assert!(
        reports(&matches, DOTTED_AUTH_TOKEN),
        "REGISTRY_AUTH structured dotted token must report; matches={matches:?}"
    );
}

#[test]
fn db_url_dotted_authentication_token_surfaces_without_db_url_widening() {
    let body = format!("DB_URL={DOTTED_AUTH_TOKEN}\n");
    let matches = scan(&scanner(), &body, "/repo/.env");
    assert!(
        reports(&matches, DOTTED_AUTH_TOKEN),
        "exact structured dotted token assigned to DB_URL must report through entropy; matches={matches:?}"
    );
}

#[test]
fn auth_key_existing_generic_anchor_still_accepts_nondotted_tokens() {
    let credential = "HVupsQnTMKFMuM199OtdO";
    let body = format!("auth_key={credential}\n");
    let matches = scan(&scanner(), &body, "/repo/config.env");
    assert!(
        reports(&matches, credential),
        "auth_key must stay owned by the existing key anchor, not the bare-auth dotted carveout; matches={matches:?}"
    );
}

#[test]
fn property_access_shape_stays_suppressed() {
    let body = "API_KEY = \"this.someService.copilotToken\"\n";
    let matches = scan(&scanner(), body, "/repo/client.ts");
    assert!(
        !reports(&matches, "this.someService.copilotToken"),
        "property access must stay below report floor; matches={matches:?}"
    );
}

#[test]
fn bare_auth_unstructured_value_stays_suppressed() {
    let body = "auth: \"someService.copilotToken.value\"\n";
    let matches = scan(&scanner(), body, "/repo/config.yaml");
    assert!(
        !reports(&matches, "someService.copilotToken.value"),
        "bare auth must not promote unstructured dotted values; matches={matches:?}"
    );
}

#[test]
fn db_url_unstructured_dotted_value_stays_suppressed() {
    let body = "DB_URL=someService.copilotToken.value\n";
    let matches = scan(&scanner(), body, "/repo/.env");
    assert!(
        !reports(&matches, "someService.copilotToken.value"),
        "DB_URL must not promote arbitrary dotted values; matches={matches:?}"
    );
}
