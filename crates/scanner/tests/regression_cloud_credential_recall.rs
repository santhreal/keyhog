//! #108 recall lock: cloud-provider credentials across the canonical artifacts
//! they actually leak in.
//!
//!  - AWS: the `~/.aws/credentials` INI (`aws_access_key_id` + `aws_secret_
//!    access_key`), `AWS_SECRET_ACCESS_KEY` env exports, camelCase JSON config.
//!  - Azure: storage-account keys (env var, connection-string `AccountKey=`,
//!    `AzureWebJobsStorage`), IoT-Hub and Service-Bus connection strings, and
//!    the AD / Entra service-principal client secret (`AZURE_CLIENT_SECRET` /
//!    `ARM_CLIENT_SECRET` / `AAD_CLIENT_SECRET` / `servicePrincipalKey`) — a
//!    class that had NO standalone detector before this lock.
//!  - GCP: service-account JSON key files in BOTH the minified and the
//!    pretty-printed (`gcloud iam service-accounts keys create`) layout. The
//!    pretty-printed form is the dominant real artifact and the one the
//!    vertexai detector's old `[^\n]` bridge could not cross.
//!
//! The oracle asserts the exact secret bytes are CONTAINED in some finding's
//! credential through the on-disk `CompiledScanner` — never `!is_empty`. Each
//! synthesized body is high-entropy and distinct (no repeated/placeholder shape
//! suppression would drop, no `EXAMPLE` marker) so a miss is a real recall gap.

mod support;

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;
use std::sync::OnceLock;
use support::contracts::{make_chunk, scanner};

/// One shared compiled scanner for the whole file — `scanner()` recompiles all
/// detectors per call, so caching keeps the suite fast. `CompiledScanner` is
/// `Send + Sync`; the harness runs these `#[test]`s serially
/// (`--test-threads=1`) so the per-scan fragment-cache clear never races.
fn shared() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(scanner)
}

/// Deterministic high-entropy alphanumeric body of length `n`. The `seed` varies
/// the stream so each fixture's secret is distinct, and the quadratic `i*i` term
/// breaks any periodicity that would lower entropy. Pure alnum (a subset of every
/// cloud-key charset) so it never introduces a delimiter that would truncate the
/// surrounding connection-string syntax.
fn body(n: usize, seed: usize) -> String {
    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..n)
        .map(|i| ALNUM[(i * 7 + seed * 13 + i * i) % ALNUM.len()] as char)
        .collect()
}

/// True iff scanning `text` surfaces `needle` — i.e. some finding's credential
/// CONTAINS it. Connection-string / service-anchored detectors capture the whole
/// URL or block as the credential, so the embedded secret is recoverable from
/// that finding; the recall contract is only that the secret value reaches a
/// finding, not which detector owns it.
fn surfaces(text: &str, needle: &str) -> bool {
    let s = shared();
    s.clear_fragment_cache();
    let chunk: Chunk = make_chunk(text, "filesystem", "cloud.conf");
    s.scan(&chunk).into_iter().any(|m| m.credential.to_string().contains(needle))
}

/// Detector ids whose credential contains `needle`, for asserting attribution.
fn detectors_for(text: &str, needle: &str) -> Vec<String> {
    let s = shared();
    s.clear_fragment_cache();
    let chunk: Chunk = make_chunk(text, "filesystem", "cloud.conf");
    s.scan(&chunk)
        .into_iter()
        .filter(|m| m.credential.to_string().contains(needle))
        .map(|m| m.detector_id.to_string())
        .collect()
}

// ── GCP service-account JSON helpers ─────────────────────────────────────────

/// A JSON-encoded PEM private-key value: one physical line with the real
/// newlines escaped as `\n` (backslash-n), exactly as a service-account key
/// file stores it.
fn sa_private_key_field() -> String {
    let b = body(200, 9);
    format!("-----BEGIN PRIVATE KEY-----\\n{b}\\n-----END PRIVATE KEY-----\\n")
}

/// Minified single-line service-account JSON.
fn sa_json_minified() -> String {
    format!(
        "{{\"type\":\"service_account\",\"project_id\":\"demo-proj-7788\",\
         \"private_key_id\":\"{}\",\"private_key\":\"{}\",\
         \"client_email\":\"svc@demo-proj-7788.iam.gserviceaccount.com\",\
         \"token_uri\":\"https://oauth2.googleapis.com/token\"}}",
        body(40, 3),
        sa_private_key_field()
    )
}

/// Pretty-printed (multi-line) service-account JSON — the canonical downloaded
/// key file, with real newlines between fields.
fn sa_json_multiline() -> String {
    format!(
        "{{\n  \"type\": \"service_account\",\n  \"project_id\": \"demo-proj-7788\",\n  \
         \"private_key_id\": \"{}\",\n  \"private_key\": \"{}\",\n  \
         \"client_email\": \"svc@demo-proj-7788.iam.gserviceaccount.com\",\n  \
         \"token_uri\": \"https://oauth2.googleapis.com/token\"\n}}",
        body(40, 3),
        sa_private_key_field()
    )
}

// ── AWS ──────────────────────────────────────────────────────────────────────

#[test]
fn aws_access_key_id_akia_surfaces() {
    let key = "AKIAZ7QH4XNB2WKLP3RV";
    assert!(surfaces(&format!("aws_access_key_id = {key}\n"), key));
}

#[test]
fn aws_access_key_id_asia_session_surfaces() {
    let key = "ASIA5TKD9WBN3FYQ8MJV";
    assert!(surfaces(&format!("aws_access_key_id = {key}\n"), key));
}

#[test]
fn aws_secret_access_key_ini_anchor_surfaces() {
    let sec = body(40, 1);
    assert!(surfaces(&format!("aws_secret_access_key = {sec}\n"), &sec));
}

#[test]
fn aws_secret_access_key_env_export_surfaces() {
    let sec = body(40, 2);
    assert!(surfaces(&format!("export AWS_SECRET_ACCESS_KEY={sec}\n"), &sec));
}

#[test]
fn aws_shared_credentials_file_both_keys_surface() {
    let akid = "AKIA3QH7XNB2WKLP9RZV";
    let sec = body(40, 6);
    let file = format!("[default]\naws_access_key_id = {akid}\naws_secret_access_key = {sec}\n");
    assert!(surfaces(&file, akid), "access key id must surface");
    assert!(surfaces(&file, &sec), "secret access key must surface");
}

#[test]
fn aws_secret_access_key_camelcase_json_surfaces() {
    let sec = body(40, 7);
    assert!(surfaces(&format!("\"awsSecretAccessKey\": \"{sec}\""), &sec));
}

// ── Azure storage ────────────────────────────────────────────────────────────

#[test]
fn azure_storage_env_key_surfaces() {
    let key = format!("{}==", body(86, 11));
    assert!(surfaces(&format!("AZURE_STORAGE_KEY={key}\n"), &key));
}

#[test]
fn azure_storage_connection_string_accountkey_surfaces() {
    let key = format!("{}==", body(86, 12));
    let conn = format!(
        "DefaultEndpointsProtocol=https;AccountName=demostorage;AccountKey={key};\
         EndpointSuffix=core.windows.net"
    );
    assert!(surfaces(&conn, &key));
}

#[test]
fn azure_webjobs_storage_accountkey_surfaces() {
    let key = format!("{}==", body(86, 13));
    let conn = format!(
        "AzureWebJobsStorage=DefaultEndpointsProtocol=https;AccountName=fnstore;AccountKey={key};"
    );
    assert!(surfaces(&conn, &key));
}

// ── Azure messaging connection strings ───────────────────────────────────────

#[test]
fn azure_iot_hub_connection_string_surfaces() {
    let key = body(44, 14);
    let conn = format!(
        "HostName=my-hub.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey={key}"
    );
    assert!(surfaces(&conn, &key));
}

#[test]
fn azure_service_bus_connection_string_surfaces() {
    let key = body(44, 15);
    let conn = format!(
        "Endpoint=sb://contoso-ns.servicebus.windows.net/;\
         SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey={key}"
    );
    assert!(surfaces(&conn, &key));
}

// ── Azure AD / Entra service-principal client secret (new detector) ───────────

#[test]
fn azure_client_secret_env_var_surfaces() {
    let sec = format!("Xy8Q~{}", body(34, 16));
    assert!(surfaces(&format!("AZURE_CLIENT_SECRET={sec}\n"), &sec));
}

#[test]
fn arm_client_secret_terraform_surfaces() {
    let sec = body(40, 17);
    assert!(surfaces(&format!("ARM_CLIENT_SECRET={sec}\n"), &sec));
}

#[test]
fn aad_client_secret_surfaces() {
    let sec = body(40, 18);
    assert!(surfaces(&format!("AAD_CLIENT_SECRET=\"{sec}\""), &sec));
}

#[test]
fn azure_service_principal_key_devops_surfaces() {
    let sec = body(40, 19);
    assert!(surfaces(&format!("servicePrincipalKey: {sec}\n"), &sec));
}

#[test]
fn azure_ad_client_secret_attributes_to_azure_client_secret() {
    let sec = body(40, 20);
    let ids = detectors_for(&format!("AZURE_AD_CLIENT_SECRET={sec}\n"), &sec);
    assert!(
        ids.iter().any(|id| id == "azure-client-secret"),
        "AZURE_AD_CLIENT_SECRET must route through azure-client-secret; got {ids:?}"
    );
}

// ── GCP service-account JSON ──────────────────────────────────────────────────

#[test]
fn gcp_sa_json_minified_private_key_surfaces() {
    assert!(surfaces(&sa_json_minified(), "-----BEGIN PRIVATE KEY-----"));
}

#[test]
fn gcp_sa_json_multiline_private_key_surfaces() {
    // The canonical downloaded key file — real newlines between fields.
    assert!(surfaces(&sa_json_multiline(), "-----BEGIN PRIVATE KEY-----"));
}

#[test]
fn gcp_sa_json_minified_attributes_to_vertexai() {
    let ids = detectors_for(&sa_json_minified(), "-----BEGIN PRIVATE KEY-----");
    assert!(
        ids.iter().any(|id| id == "vertexai-service-account"),
        "minified service-account JSON must attribute to vertexai-service-account; got {ids:?}"
    );
}

#[test]
fn gcp_sa_json_multiline_attributes_to_vertexai() {
    // The fix target: the pretty-printed bridge must cross the newlines so the
    // GCP-specific detector — not just the generic private-key block — fires.
    let ids = detectors_for(&sa_json_multiline(), "-----BEGIN PRIVATE KEY-----");
    assert!(
        ids.iter().any(|id| id == "vertexai-service-account"),
        "pretty-printed service-account JSON must attribute to vertexai-service-account; got {ids:?}"
    );
}

// ── GCP API key / OAuth client secret ────────────────────────────────────────

#[test]
fn google_api_key_aiza_surfaces() {
    let key = format!("AIza{}", body(35, 21));
    assert!(surfaces(&format!("GOOGLE_API_KEY={key}"), &key));
}

#[test]
fn google_oauth_client_secret_gocspx_surfaces() {
    let sec = format!("GOCSPX-{}", body(24, 22));
    assert!(surfaces(&format!("GOOGLE_CLIENT_SECRET={sec}"), &sec));
}

// ── precision spot-checks ─────────────────────────────────────────────────────

#[test]
fn azure_client_secret_below_floor_does_not_surface() {
    // A sub-floor value (< the {24,} body) must not raise azure-client-secret.
    let ids = detectors_for("AZURE_CLIENT_SECRET=short", "short");
    assert!(
        !ids.iter().any(|id| id == "azure-client-secret"),
        "a 5-char client secret is below the floor and must not surface as azure-client-secret"
    );
}

#[test]
fn bare_client_secret_not_attributed_to_azure() {
    // No AZURE_/ARM_/AAD_ scope prefix — a generic client_secret must NOT be
    // mislabeled as an Azure service-principal secret.
    let v = body(40, 23);
    let ids = detectors_for(&format!("keycloak_client_secret={v}"), &v);
    assert!(
        !ids.iter().any(|id| id == "azure-client-secret"),
        "an unscoped client_secret must not attribute to azure-client-secret; got {ids:?}"
    );
}

#[test]
fn aws_access_key_lowercase_lookalike_not_surfaced() {
    // AKIA/ASIA ids are always uppercase; the `(?-i)` guard must reject the
    // lowercase doc/test look-alike so it is not flagged as an AWS access key.
    let lower = "akiaz7qh4xnb2wklp3rv";
    let ids = detectors_for(&format!("key = {lower}\n"), lower);
    assert!(
        !ids.iter().any(|id| id == "aws-access-key"),
        "lowercase AKIA look-alike must not surface as aws-access-key; got {ids:?}"
    );
}
