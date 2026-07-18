//! Detection-truth: full finding IDENTITY for more vendors + SEVERITY variety
//! (#177/#184). Extends the identity suite; includes High-severity detectors
//! (Postman/HuggingFace/Square) so severity mapping is pinned, not assumed
//! uniform. Law 6 (rule + service + severity + offset + credential).
//! ML-independent; run without `ml` while the embedded weights are mid-retrain.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::{LazyLock, Mutex};

static SCANNER: LazyLock<Mutex<CompiledScanner>> = LazyLock::new(|| {
    Mutex::new(
        CompiledScanner::compile(keyhog_core::embedded_detector_specs().to_vec())
            .expect("scanner compile"),
    )
});

struct Found {
    detector_id: String,
    service: String,
    severity: String,
    offset: usize,
    credential: String,
}

fn scan(text: &str) -> Vec<Found> {
    let scanner = SCANNER.lock().expect("identity scanner lock");
    scanner.clear_fragment_cache();
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "detection-truth-test".into(),
            path: Some("s.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .iter()
        .flat_map(|per_chunk| per_chunk.iter())
        .map(|m| Found {
            detector_id: m.detector_id.to_string(),
            service: m.service.to_string(),
            severity: format!("{:?}", m.severity),
            offset: m.location.offset,
            credential: m.credential.as_ref().to_string(),
        })
        .collect()
}

fn assert_identity(
    text: &str,
    detector_id: &str,
    service: &str,
    severity: &str,
    offset: usize,
    credential: &str,
) {
    let found = scan(text);
    assert!(
        found.iter().any(|f| f.detector_id == detector_id
            && f.service == service
            && f.severity == severity
            && f.offset == offset
            && f.credential == credential),
        "no finding matched id={detector_id} service={service} sev={severity} off={offset} \
         cred={credential}; got: {:?}",
        found
            .iter()
            .map(|f| format!(
                "(id={} svc={} sev={} off={} cred={})",
                f.detector_id, f.service, f.severity, f.offset, f.credential
            ))
            .collect::<Vec<_>>()
    );
}

// ── Critical-severity detectors ──────────────────────────────────────────────

#[test]
fn shopify_admin_token_identity() {
    assert_identity(
        "t = shpat_0123456789abcdef0123456789abcdef",
        "shopify-admin-api-token",
        "shopify",
        "Critical",
        4,
        "shpat_0123456789abcdef0123456789abcdef",
    );
}

#[test]
fn npm_access_token_identity() {
    assert_identity(
        "t = npm_0123456789abcdefghijklmnopqrstuvwxyzAB",
        "npm-access-token",
        "npm",
        "Critical",
        4,
        "npm_0123456789abcdefghijklmnopqrstuvwxyzAB",
    );
}

#[test]
fn discord_bot_token_identity() {
    assert_identity(
        "t = MTE2MjkzNDU2Nzg5MDEyMzQ1Ng.GxYzAb.abcdefghijklmnopqrstuvwxyz01234",
        "discord-bot-token",
        "discord",
        "Critical",
        4,
        "MTE2MjkzNDU2Nzg5MDEyMzQ1Ng.GxYzAb.abcdefghijklmnopqrstuvwxyz01234",
    );
}

#[test]
fn mailgun_api_key_identity() {
    assert_identity(
        "t = key-0123456789abcdef0123456789abcdef",
        "mailgun-api-key",
        "mailgun",
        "Critical",
        4,
        "key-0123456789abcdef0123456789abcdef",
    );
}

#[test]
fn github_oauth_token_identity() {
    assert_identity(
        "t = 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",
        "github-oauth-access-token",
        "github",
        "Critical",
        4,
        "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",
    );
}

#[test]
fn google_oauth_client_secret_identity() {
    assert_identity(
        "t = GOCSPX-0123456789abcdefghijklmnopqr",
        "google-oauth-client-secret",
        "google",
        "Critical",
        4,
        "GOCSPX-0123456789abcdefghijklmnopqr",
    );
}

#[test]
fn eight_x_eight_header_requires_service_context() {
    let credential = "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5";
    let unrelated = format!("X-Api-Key: {credential}");
    let unrelated_findings = scan(&unrelated);
    assert!(
        unrelated_findings
            .iter()
            .all(|finding| finding.detector_id != "8x8-api-credentials"),
        "a generic X-Api-Key header must not be attributed to 8x8: {}",
        unrelated_findings
            .iter()
            .map(|finding| finding.detector_id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let contextual = format!("https://api.8x8.com/stats\nX-Api-Key: {credential}");
    assert_identity(
        &contextual,
        "8x8-api-credentials",
        "8x8",
        "Critical",
        contextual
            .find(credential)
            .expect("fixture contains its credential"),
        credential,
    );

    let reversed = format!("X-Api-Key: {credential}\nhttps://api.8x8.com/stats");
    assert_identity(
        &reversed,
        "8x8-api-credentials",
        "8x8",
        "Critical",
        reversed
            .find(credential)
            .expect("fixture contains its credential"),
        credential,
    );
}

#[test]
fn x2y2_header_requires_service_context() {
    let credential = "JSuKxKWNfd898GujYX9p66-_M1knu3xIPTZfsus5cByqlnilvi7";
    let unrelated = format!("X-API-KEY: {credential}");
    let unrelated_findings = scan(&unrelated);
    assert!(
        unrelated_findings
            .iter()
            .all(|finding| finding.detector_id != "x2y2-api-key"),
        "a generic X-API-KEY header must not be attributed to X2Y2: {}",
        unrelated_findings
            .iter()
            .map(|finding| finding.detector_id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let contextual = format!("https://api.x2y2.org/orders\nX-API-KEY: {credential}");
    assert_identity(
        &contextual,
        "x2y2-api-key",
        "x2y2",
        "Medium",
        contextual
            .find(credential)
            .expect("fixture contains its credential"),
        credential,
    );

    let reversed = format!("X-API-KEY: {credential}\nhttps://api.x2y2.org/orders");
    assert_identity(
        &reversed,
        "x2y2-api-key",
        "x2y2",
        "Medium",
        reversed
            .find(credential)
            .expect("fixture contains its credential"),
        credential,
    );
}

#[test]
fn provider_api_headers_require_service_context() {
    let cases = [
        (
            "opensea-api-key",
            "opensea",
            "High",
            "https://api.opensea.io/api/v2/collections",
            "X-API-KEY",
            "2sIuLPADN-nQyiY2sVUsxowxpKZUoKKW",
        ),
        (
            "omnisend-api-key",
            "omnisend",
            "Critical",
            "https://api.omnisend.com/v3/account",
            "X-API-Key",
            "614030930ca9626eedd2b6b73c763ac9",
        ),
        (
            "skyscanner-api-key",
            "skyscanner",
            "Medium",
            "https://partners.api.skyscanner.net/apiservices/v3/cultures",
            "x-api-key",
            "JEA8DfgFxzo9YbHh99eKuvHZUH62tIOeNPCQWBgg",
        ),
        (
            "moosend-api-key",
            "moosend",
            "High",
            "https://api.moosend.com/v3/subscribers.json",
            "X-Api-Key",
            "a4f4f-7a6c28--633f18a1a2b0ff571464fc",
        ),
    ];

    for (detector_id, service, severity, endpoint, header, credential) in cases {
        let unrelated = format!("{header}: {credential}");
        assert!(
            scan(&unrelated)
                .iter()
                .all(|finding| finding.detector_id != detector_id),
            "a generic {header} header must not be attributed to {detector_id}"
        );

        for contextual in [
            format!("{endpoint}\n{header}: {credential}"),
            format!("{header}: {credential}\n{endpoint}"),
        ] {
            assert_identity(
                &contextual,
                detector_id,
                service,
                severity,
                contextual
                    .find(credential)
                    .expect("fixture contains its credential"),
                credential,
            );
        }
    }

    let passbase_key = "7VVpvY_rJEc_G33gXrRw";
    assert!(
        scan(&format!("X-API-KEY: {passbase_key}"))
            .iter()
            .all(|finding| finding.detector_id != "passbase-api-key"),
        "a generic X-API-KEY header must not be attributed to Passbase"
    );
    let passbase_assignment = format!("PASSBASE_API_KEY={passbase_key}");
    assert_identity(
        &passbase_assignment,
        "passbase-api-key",
        "passbase",
        "High",
        passbase_assignment
            .find(passbase_key)
            .expect("fixture contains its credential"),
        passbase_key,
    );
}

// ── High-severity detectors (severity mapping is NOT uniform) ─────────────────

#[test]
fn postman_api_key_is_high_severity() {
    assert_identity(
        "t = PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123",
        "postman-api-key",
        "postman",
        "High",
        4,
        "PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123",
    );
}

#[test]
fn square_access_token_is_high_severity() {
    assert_identity(
        "t = sq0atp-0123456789abcdefghijkl",
        "square-access-token",
        "square",
        "High",
        4,
        "sq0atp-0123456789abcdefghijkl",
    );
}

#[test]
fn huggingface_token_is_high_severity() {
    assert_identity(
        "t = hf_0123456789abcdefghijklmnopqrstuvwxyz",
        "huggingface-api-key",
        "huggingface",
        "High",
        4,
        "hf_0123456789abcdefghijklmnopqrstuvwxyz",
    );
}
