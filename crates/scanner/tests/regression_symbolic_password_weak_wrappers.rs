//! Regression: symbolic passwords behind weak wrappers must still surface.
//!
//! Mirror plants real password-shaped values behind `auth` and `WEBHOOK_URL`
//! wrappers. Those keys are too broad to treat as universal credential anchors,
//! so the value shape must carry the recall: a mixed alnum + symbol password
//! accepted by the existing strict-secret owner.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};

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
fn bare_json_auth_symbolic_password_surfaces() {
    let credential = "Y6NPMwS*rWGUv!JQnSG6a#D14";
    let body = format!("{{\n  \"auth\": \"{credential}\",\n  \"ttl\": 3600\n}}\n");
    let matches = scan(&scanner(), &body, "/repo/config.json");
    assert!(
        reports(&matches, credential),
        "bare JSON auth symbolic password must report; matches={matches:?}"
    );
}

#[test]
fn bare_yaml_auth_symbolic_password_surfaces() {
    let credential = "ol^!1&%TX!y&hGDoaLA7AT1S2D";
    let body = format!("config:\n  auth: \"{credential}\"\n  enabled: true\n");
    let matches = scan(&scanner(), &body, "/repo/config.yaml");
    assert!(
        reports(&matches, credential),
        "bare YAML auth symbolic password must report; matches={matches:?}"
    );
}

#[test]
fn webhook_url_symbolic_password_surfaces_without_url_widening() {
    let credential = "1E1B3b4Ho$U4kYBi";
    let body = format!("WEBHOOK_URL={credential}\n");
    let matches = scan(&scanner(), &body, "/repo/.env");
    assert!(
        reports(&matches, credential),
        "WEBHOOK_URL symbolic password wrapper must report; matches={matches:?}"
    );
}

#[test]
fn bare_auth_property_access_stays_suppressed() {
    let body = "auth: \"this.someService.copilotToken\"\n";
    let matches = scan(&scanner(), body, "/repo/config.yaml");
    assert!(
        !reports(&matches, "this.someService.copilotToken"),
        "bare auth must not promote property-access values; matches={matches:?}"
    );
}

#[test]
fn webhook_url_plain_identifier_stays_suppressed() {
    let body = "WEBHOOK_URL=internal_status_enabled\n";
    let matches = scan(&scanner(), body, "/repo/.env");
    assert!(
        !reports(&matches, "internal_status_enabled"),
        "WEBHOOK_URL must not promote plain identifiers; matches={matches:?}"
    );
}
