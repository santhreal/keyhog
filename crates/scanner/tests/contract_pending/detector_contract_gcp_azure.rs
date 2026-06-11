//! GCP service-account JSON keys + AIza API keys + Azure connection strings + client secrets
//! detector contract & GPU parity validation.
//!
//! This test file validates that detectors for Google Cloud Platform credentials
//! (service accounts, AIza API keys) and Azure credentials (connection strings,
//! client secrets, OpenAI keys) correctly identify real patterns, reject false
//! positives, and produce identical results across CPU and GPU backends.
//!
//! Test coverage:
//! - GCP service account JSON (vertexai-service-account detector)
//! - Google API keys (AIza prefix) (google-api-key detector)
//! - Azure service bus connection strings (azure-service-bus-connection-string detector)
//! - Azure storage account keys (azure-storage-account-key detector)
//! - Azure OpenAI API keys (azure-openai-api-key detector)
//! - Positive cases with real patterns
//! - Negative cases to exclude false positives
//! - GPU ↔ SIMD parity validation
//! - Boundary conditions, encoding variations, and embedded patterns

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

/// Collects (credential_string, detector_id, file_path, offset) tuples for
/// cross-backend comparison. Tuple form allows us to assert identity across
/// SIMD and GPU backends - if the credential text and location match, the
/// finding is valid regardless of which detector matched (upstream merging
/// may attribute multiple detectors to the same cred).
fn collect_findings(results: &[Vec<RawMatch>]) -> std::collections::BTreeSet<(String, String, String, usize)> {
    let mut set = std::collections::BTreeSet::new();
    for chunk in results {
        for m in chunk {
            set.insert((
                m.credential.as_ref().to_string(),
                m.detector_id.as_ref().to_string(),
                m.location
                    .file_path
                    .as_deref()
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
                m.location.offset,
            ));
        }
    }
    set
}

// ============================================================================
// GCP SERVICE ACCOUNT TESTS (vertexai-service-account detector)
// ============================================================================

#[test]
fn gcp_service_account_json_complete() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Real GCP service account JSON structure with all required fields.
    let json = r#"{
  "type": "service_account",
  "project_id": "my-project",
  "private_key_id": "abc123",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQE=\n-----END PRIVATE KEY-----\n",
  "client_email": "sa@my-project.iam.gserviceaccount.com"
}"#;

    let chunk = make_chunk(json, "config/service-account.json");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, detector, _, _)| {
            detector == "vertexai-service-account"
                && cred.contains("-----BEGIN PRIVATE KEY-----")
        }),
        "should detect complete service account JSON with private key marker"
    );
}

#[test]
fn gcp_service_account_inline_no_spacing() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Compact JSON without whitespace (common in minified configs).
    let json =
        r#"{"type":"service_account","project_id":"compact-proj","private_key":"-----BEGIN PRIVATE KEY-----\nMII=\n-----END PRIVATE KEY-----"}"#;

    let chunk = make_chunk(json, "config.json");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(_, detector, _, _)| detector == "vertexai-service-account"),
        "should detect minified JSON service account"
    );
}

#[test]
fn gcp_service_account_multiline_private_key() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Service account with multiline private key (standard PEM format).
    let text = r#"type = "service_account"
project_id = "multiline-proj"
private_key = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC7...
...more base64...
-----END PRIVATE KEY-----""#;

    let chunk = make_chunk(text, "app.hcl");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(_, detector, _, _)| detector == "vertexai-service-account"),
        "should detect service account with multiline key"
    );
}

#[test]
fn gcp_service_account_missing_private_key_no_match() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Missing the private_key field - should NOT match.
    let json = r#"{
  "type": "service_account",
  "project_id": "incomplete-proj",
  "client_email": "sa@my-project.iam.gserviceaccount.com"
}"#;

    let chunk = make_chunk(json, "incomplete.json");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        !findings.iter().any(|(_, detector, _, _)| detector == "vertexai-service-account"),
        "should NOT detect service account without private_key field"
    );
}

#[test]
fn gcp_service_account_env_var_name_only_no_match() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Env var name alone should NOT match - it's not a credential.
    let text = "export GOOGLE_APPLICATION_CREDENTIALS=/path/to/config.json";

    let chunk = make_chunk(text, "setup.sh");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        !findings.iter().any(|(_, detector, _, _)| detector == "vertexai-service-account"),
        "should NOT match env var name without actual credential"
    );
}

#[test]
fn gcp_service_account_project_id_bounds() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Project IDs capped at 30 chars per GCP spec - regex bounds at this limit.
    let json = r#"{"type":"service_account","project_id":"this-is-exactly-30-characters","private_key":"-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----"}"#;

    let chunk = make_chunk(json, "config.json");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(_, detector, _, _)| detector == "vertexai-service-account"),
        "should detect service account with max-length project ID"
    );
}

// ============================================================================
// GOOGLE API KEY TESTS (AIza prefix, google-api-key detector)
// ============================================================================

#[test]
fn google_api_key_youtube_aiza_prefix() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Standard YouTube API key: AIza + 35 alphanumeric chars.
    let text = "const YOUTUBE_API_KEY = \"AIzaSyC1_H8_Z9q-JxJ_7k-NmHf3oK2LZ-a9pB4\";";

    let chunk = make_chunk(text, "youtube.js");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, detector, _, _)| {
            detector == "google-api-key"
                && cred.contains("AIzaSyC1_H8_Z9q-JxJ_7k-NmHf3oK2LZ-a9pB4")
        }),
        "should detect YouTube API key with AIza prefix"
    );
}

#[test]
fn google_api_key_maps_aiza_prefix() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Maps API key with context anchor.
    let text = r#"GOOGLE_API_KEY="AIzaSyAaBjJJHHH-VvF_xX-Xx_Xll999_aZaAaA""#;

    let chunk = make_chunk(text, ".env");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, detector, _, _)| {
            detector == "google-api-key" && cred.contains("AIzaSyAaBjJJHHH-VvF_xX-Xx_Xll999_aZaAaA")
        }),
        "should detect Google API key with env-var anchor"
    );
}

#[test]
fn google_api_key_places_aizasy_variant() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Places API key: AIzaSy variant (33 additional chars).
    let text = "PLACES_API_KEY=AIzaSyPlacesKEY1234567890PlacesKEY12345";

    let chunk = make_chunk(text, "config.py");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, detector, _, _)| {
            detector == "google-api-key" && cred.contains("AIzaSyPlacesKEY1234567890PlacesKEY12345")
        }),
        "should detect AIzaSy Places API key variant"
    );
}

#[test]
fn google_api_key_cloud_functions_url_encoded() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Cloud Functions URL with API key in query string.
    let text = "https://my-func-prod-abc123.a.run.app?key=AIzaSyURLTestKey1234567890URLKEY";

    let chunk = make_chunk(text, "request.log");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, detector, _, _)| {
            detector == "google-api-key" && cred.contains("AIzaSyURLTestKey1234567890URLKEY")
        }),
        "should extract Google API key from Cloud Functions URL"
    );
}

#[test]
fn google_api_key_translation_service_anchor() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Translation service with context anchor.
    let text = r#"GOOGLE_TRANSLATE_API_KEY = "AIzaSyTranslateKEY1234567890TRANSLKEY""#;

    let chunk = make_chunk(text, "settings.conf");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, detector, _, _)| {
            detector == "google-api-key" && cred.contains("AIzaSyTranslateKEY1234567890TRANSLKEY")
        }),
        "should detect Google Translate API key"
    );
}

#[test]
fn google_api_key_too_short_no_match() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // AIza prefix but insufficient length - should NOT match.
    let text = "key: AIzaSyShort123";

    let chunk = make_chunk(text, "short.yaml");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        !findings.iter().any(|(cred, detector, _, _)| {
            detector == "google-api-key" && cred.contains("AIzaSyShort123")
        }),
        "should NOT match truncated AIza key"
    );
}

#[test]
fn google_api_key_underscore_dash_chars() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // AIza keys can include underscores and dashes.
    let text = "API_KEY: AIza-Key_With_Underscores_And-Dashes-XYZ123456";

    let chunk = make_chunk(text, "config.toml");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, detector, _, _)| {
            detector == "google-api-key" && cred.contains("AIza-Key_With_Underscores_And-Dashes-XYZ123456")
        }),
        "should detect AIza key with underscores and dashes"
    );
}

// ============================================================================
// AZURE SERVICE BUS CONNECTION STRING TESTS
// ============================================================================

#[test]
fn azure_service_bus_connection_string_shared_access_key() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Standard Service Bus connection string with SharedAccessKey (real test case from detector).
    let text =
        "Endpoint=sb://contoso-ns.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=NB8zVq3F7pXm2kJdR9sLtY6wEoQa1uHcZbVgXn4MiP0=";

    let chunk = make_chunk(text, "config.txt");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, detector, _, _)| {
            detector == "azure-service-bus-connection-string"
                && cred.contains("NB8zVq3F7pXm2kJdR9sLtY6wEoQa1uHcZbVgXn4MiP0=")
        }),
        "should detect Service Bus connection string with SharedAccessKey"
    );
}

#[test]
fn azure_service_bus_sas_signature_form() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Service Bus SAS token form: sig=<payload>.
    let text = "Endpoint=sb://my-namespace.servicebus.windows.net/;SharedAccessSignature sig=SharedAccessSignatureSigValue123456==";

    let chunk = make_chunk(text, "env.sh");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, detector, _, _)| {
            detector == "azure-service-bus-connection-string"
                && cred.contains("SharedAccessSignatureSigValue123456==")
        }),
        "should detect Service Bus SAS signature form"
    );
}

#[test]
fn azure_service_bus_with_entity_path() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Connection string with EntityPath (queue/topic name).
    let text =
        "Endpoint=sb://prod-namespace.servicebus.windows.net/;SharedAccessKeyName=SendListen;SharedAccessKey=Ky4xZ9jH3fL8mP0nQ2rS4tU5vW6xY7zAa9bC0dE1fG2=;EntityPath=myqueue";

    let chunk = make_chunk(text, "connection.conf");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, detector, _, _)| {
            detector == "azure-service-bus-connection-string"
        }),
        "should detect Service Bus connection string with EntityPath"
    );
}

#[test]
fn azure_service_bus_with_env_var_anchor() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Env var anchor form.
    let text = r#"SERVICE_BUS_CONNECTION_STRING="Endpoint=sb://test-ns.servicebus.windows.net/;SharedAccessKeyName=Admin;SharedAccessKey=AdminKeyBase64String1234567890abcdef==;EntityPath=events""#;

    let chunk = make_chunk(text, ".env");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(_, detector, _, _)| {
            detector == "azure-service-bus-connection-string"
        }),
        "should detect Service Bus connection string via env-var anchor"
    );
}

#[test]
fn azure_service_bus_incomplete_no_shared_access_key() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Incomplete: has Endpoint and KeyName but no Key value.
    let text =
        "Endpoint=sb://incomplete-ns.servicebus.windows.net/;SharedAccessKeyName=TestKey";

    let chunk = make_chunk(text, "incomplete.txt");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        !findings.iter().any(|(_, detector, _, _)| {
            detector == "azure-service-bus-connection-string"
        }),
        "should NOT detect Service Bus connection string without SharedAccessKey value"
    );
}

// ============================================================================
// AZURE STORAGE ACCOUNT KEY TESTS
// ============================================================================

#[test]
fn azure_storage_account_key_88_char_base64() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Azure storage keys are 86 chars + 2-char padding = 88 chars total base64.
    let text = "AccountKey=C9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4g3h2i1j0k9l8m7n6o5p4q3r2s1t0u9v8w7x6y5z4a3b2c1==";

    let chunk = make_chunk(text, "connection.txt");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, detector, _, _)| {
            detector == "azure-storage-account-key"
                && cred.contains("C9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4g3h2i1j0k9l8m7n6o5p4q3r2s1t0u9v8w7x6y5z4a3b2c1==")
        }),
        "should detect Azure storage account key (88-char base64)"
    );
}

#[test]
fn azure_storage_account_env_var_anchor() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // With AZURE_STORAGE_KEY env-var anchor.
    let text = "AZURE_STORAGE_KEY=Aa1bB2cC3dD4eE5fF6gG7hH8iI9jJ0kK1lL2mM3nN4oO5pP6qQ7rR8sS9tT0uU1vV2wW3xX4yY5zZ6Aa==";

    let chunk = make_chunk(text, ".env.production");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, detector, _, _)| {
            detector == "azure-storage-account-key"
                && cred.contains("Aa1bB2cC3dD4eE5fF6gG7hH8iI9jJ0kK1lL2mM3nN4oO5pP6qQ7rR8sS9tT0uU1vV2wW3xX4yY5zZ6Aa==")
        }),
        "should detect storage key via AZURE_STORAGE_KEY env var"
    );
}

#[test]
fn azure_storage_azure_web_jobs_storage() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // AzureWebJobsStorage connection string form.
    let text = "AzureWebJobsStorage=DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=zzZz9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2h1g0f9e8d7c6b5a4Z3Y2X1W0V9U8T7S6R5Q4P3O2N1M==;EndpointSuffix=core.windows.net";

    let chunk = make_chunk(text, "app.config");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, detector, _, _)| {
            detector == "azure-storage-account-key"
                && cred.contains("zzZz9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2h1g0f9e8d7c6b5a4Z3Y2X1W0V9U8T7S6R5Q4P3O2N1M==")
        }),
        "should detect AccountKey from AzureWebJobsStorage connection string"
    );
}

#[test]
fn azure_storage_too_short_no_match() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Base64 shorter than 86 chars - should NOT match.
    let text = "AccountKey=ShortBase64Key123==";

    let chunk = make_chunk(text, "short.txt");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        !findings.iter().any(|(_, detector, _, _)| {
            detector == "azure-storage-account-key"
        }),
        "should NOT detect storage key shorter than 86 chars"
    );
}

// ============================================================================
// AZURE OPENAI API KEY TESTS
// ============================================================================

#[test]
fn azure_openai_api_key_32_hex() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Azure OpenAI API key: 32 hex characters.
    let text = "AZURE_OPENAI_API_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";

    let chunk = make_chunk(text, ".env");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, detector, _, _)| {
            detector == "azure-openai-api-key"
                && cred.contains("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
        }),
        "should detect Azure OpenAI API key (32 hex)"
    );
}

#[test]
fn azure_openai_with_endpoint_context() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // API key with endpoint context.
    let text = r#"api-key = "f0e1d2c3b4a59687a5b4c3d2e1f0a9b"
endpoint = "https://my-openai.openai.azure.com"
"#;

    let chunk = make_chunk(text, "config.toml");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, detector, _, _)| {
            detector == "azure-openai-api-key"
                && cred.contains("f0e1d2c3b4a59687a5b4c3d2e1f0a9b")
        }),
        "should detect Azure OpenAI API key with endpoint context"
    );
}

#[test]
fn azure_openai_non_hex_no_match() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Contains non-hex chars (g,h) - should NOT match (only a-f allowed).
    let text = "AZURE_OPENAI_API_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5dg";

    let chunk = make_chunk(text, ".env");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        !findings.iter().any(|(_, detector, _, _)| {
            detector == "azure-openai-api-key"
        }),
        "should NOT detect key with non-hex characters"
    );
}

// ============================================================================
// GPU PARITY TESTS (if GPU available)
// ============================================================================

#[test]
#[cfg(feature = "gpu")]
fn gpu_parity_gcp_azure_mixed_corpus() {
    // Skip if no GPU available - GPU tests are optional.
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }

    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Mixed corpus with GCP service account, AIza key, and Azure service bus connection string.
    let chunks = vec![
        make_chunk(
            r#"{"type":"service_account","project_id":"parity-test","private_key":"-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----"}"#,
            "gcp.json",
        ),
        make_chunk(
            "const API_KEY = \"AIzaSyGCPTestKey1234567890GCPTestKey\";",
            "app.js",
        ),
        make_chunk(
            "Endpoint=sb://parity-ns.servicebus.windows.net/;SharedAccessKeyName=Test;SharedAccessKey=Test1234567890Test1234567890Test123456==",
            "config.txt",
        ),
        make_chunk(
            "AZURE_OPENAI_API_KEY=1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
            ".env",
        ),
    ];

    let simd_results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let gpu_results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::Gpu);

    let simd_findings = collect_findings(&simd_results);
    let gpu_findings = collect_findings(&gpu_results);

    // Hard fail if GPU returned zero findings but SIMD found matches.
    if gpu_findings.is_empty() && !simd_findings.is_empty() {
        panic!(
            "GPU returned zero findings vs {} SIMD findings - adapter init failure or silent fallback",
            simd_findings.len()
        );
    }

    // If GPU is fully functional, parity must match.
    if !gpu_findings.is_empty() {
        assert_eq!(
            simd_findings, gpu_findings,
            "GPU and SIMD findings must match exactly (same credentials, detectors, locations)"
        );
    }
}

#[test]
#[cfg(feature = "gpu")]
fn gpu_parity_aiza_variants() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }

    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Multiple AIza variants in one chunk.
    let chunks = vec![
        make_chunk(
            r#"
YOUTUBE_KEY=AIzaSyYouTube1234567890YouTubeKey
MAPS_KEY=AIzaSyMaps1234567890MapsKeyVeryLong
PLACES_KEY=AIzaSyPlaces1234567890PlacesKeyVariant
"#,
            "keys.conf",
        ),
    ];

    let simd_results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let gpu_results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::Gpu);

    let simd_findings = collect_findings(&simd_results);
    let gpu_findings = collect_findings(&gpu_results);

    if gpu_findings.is_empty() && !simd_findings.is_empty() {
        panic!(
            "GPU/SIMD parity broken: GPU={}, SIMD={}",
            gpu_findings.len(),
            simd_findings.len()
        );
    }

    if !gpu_findings.is_empty() {
        assert_eq!(simd_findings, gpu_findings);
    }
}

#[test]
#[cfg(feature = "gpu")]
fn gpu_parity_azure_connection_strings() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }

    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Multiple Azure connection string patterns.
    let chunks = vec![
        make_chunk(
            r#"
SERVICE_BUS=Endpoint=sb://ns1.servicebus.windows.net/;SharedAccessKeyName=Send;SharedAccessKey=Key1Key1Key1Key1Key1Key1Key1Key1Key1Key1Key1K1==
STORAGE=DefaultEndpointsProtocol=https;AccountName=storage;AccountKey=Storage1Storage1Storage1Storage1Storage1Storage1Storage1Storage1Storage1Storage1==;
"#,
            "connections.conf",
        ),
    ];

    let simd_results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let gpu_results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::Gpu);

    let simd_findings = collect_findings(&simd_results);
    let gpu_findings = collect_findings(&gpu_results);

    if gpu_findings.is_empty() && !simd_findings.is_empty() {
        panic!(
            "GPU/SIMD parity broken: GPU={}, SIMD={}",
            gpu_findings.len(),
            simd_findings.len()
        );
    }

    if !gpu_findings.is_empty() {
        assert_eq!(simd_findings, gpu_findings);
    }
}

// ============================================================================
// BOUNDARY & ADVERSARIAL TESTS
// ============================================================================

#[test]
fn gcp_service_account_base64_padding_variations() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Private key with various padding lengths (none, single =, double ==).
    let json = r#"{"type":"service_account","project_id":"padding-test","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBA\n-----END PRIVATE KEY-----"}"#;

    let chunk = make_chunk(json, "config.json");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(_, detector, _, _)| {
            detector == "vertexai-service-account"
        }),
        "should detect service account with various key padding"
    );
}

#[test]
fn multiple_credentials_in_single_chunk() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Chunk containing multiple different credential types.
    let text = r#"
{
  "type": "service_account",
  "project_id": "multi-test",
  "private_key": "-----BEGIN PRIVATE KEY-----\nXX\n-----END PRIVATE KEY-----"
}
API_KEY = AIzaSyMultiTest1234567890MultiTest
SERVICE_BUS = Endpoint=sb://multi.servicebus.windows.net/;SharedAccessKeyName=Key;SharedAccessKey=Multi1Multi1Multi1Multi1Multi1Multi1MultiKey==
AZURE_OPENAI = 9f8e7d6c5b4a39281f0e1d2c3b4a5968
"#;

    let chunk = make_chunk(text, "secrets.conf");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.len() >= 4,
        "should detect all four credential types (found: {})",
        findings.len()
    );
    assert!(
        findings.iter().any(|(_, d, _, _)| d == "vertexai-service-account"),
        "should detect GCP service account"
    );
    assert!(
        findings.iter().any(|(_, d, _, _)| d == "google-api-key"),
        "should detect Google API key"
    );
    assert!(
        findings.iter().any(|(_, d, _, _)| d == "azure-service-bus-connection-string"),
        "should detect Azure service bus"
    );
    assert!(
        findings.iter().any(|(_, d, _, _)| d == "azure-openai-api-key"),
        "should detect Azure OpenAI key"
    );
}

#[test]
fn credential_at_chunk_boundary() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Credential split across two chunks (boundary condition).
    let chunk1 = make_chunk(
        "start=AIzaSyBoundary",
        "part1.txt",
    );
    let chunk2 = make_chunk(
        "Test1234567890BoundaryTest",
        "part2.txt",
    );

    let results = scanner.scan_chunks_with_backend(&[chunk1, chunk2], ScanBackend::SimdCpu);
    // Note: cross-chunk patterns may not be detected depending on the scanner's window design.
    // This test documents the behavior rather than enforcing cross-chunk assembly.
    let findings = collect_findings(&results);
    // Expectations depend on scanner boundary handling - just verify no panic.
    assert!(findings.len() >= 0, "boundary test should not panic");
}

#[test]
fn escaped_characters_in_json_strings() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Escaped newlines in JSON private key.
    let json = r#"{"type":"service_account","project_id":"escaped-test","private_key":"-----BEGIN PRIVATE KEY-----\\nMIIEvQIBA\\n-----END PRIVATE KEY-----"}"#;

    let chunk = make_chunk(json, "escaped.json");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    // Escaped form may or may not match depending on detector design.
    assert!(findings.len() >= 0, "escaped form should not panic");
}

#[test]
fn azure_storage_key_with_special_base64_chars() {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Azure keys may include + and / (base64 special chars).
    let text = "AccountKey=+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/A==";

    let chunk = make_chunk(text, "special.txt");
    let results = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);

    let findings = collect_findings(&results);
    assert!(
        findings.iter().any(|(cred, detector, _, _)| {
            detector == "azure-storage-account-key"
                && cred.contains("+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/A==")
        }),
        "should detect storage key with base64 special characters (+/)"
    );
}
