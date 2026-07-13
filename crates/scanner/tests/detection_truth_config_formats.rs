//! Detection-truth: realistic FILE-FORMAT embedding (#177/#184). Real leaks live
//! in .env / YAML / JSON / TOML / Dockerfile / compose / k8s Secrets / XML /
//! .properties / connection strings / auth headers (not bare `key = value`).
//! Each test plants a known-firing credential in a realistic format and asserts
//! the exact value is recovered (Law 6). ML-independent; run without `ml` while
//! the embedded weights are mid-retrain.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn scan_credentials(text: &str, path: &str) -> Vec<String> {
    let detectors = keyhog_core::embedded_detector_specs().to_vec();
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "config-format-test".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .iter()
        .flat_map(|per_chunk| per_chunk.iter())
        .map(|m| m.credential.as_ref().to_string())
        .collect()
}

fn assert_found(text: &str, path: &str, expected: &str) {
    let creds = scan_credentials(text, path);
    assert!(
        creds.iter().any(|c| c == expected),
        "expected `{expected}` in {path}; found: {creds:?}\n--- input ---\n{text}"
    );
}

#[test]
fn dotenv_file_aws_access_key() {
    assert_found(
        "# production\nAWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7BBB\nAWS_REGION=us-east-1\n",
        ".env",
        "AKIAQYLPMN5HFIQR7BBB",
    );
}

#[test]
fn yaml_gitlab_token() {
    assert_found(
        "ci:\n  variables:\n    GITLAB_TOKEN: glpat-ABCDEF1234567890abcd\n",
        "config.yaml",
        "glpat-ABCDEF1234567890abcd",
    );
}

#[test]
fn json_google_api_key() {
    assert_found(
        "{\n  \"maps\": {\n    \"apiKey\": \"AIzaSyA1234567890abcdefghijklmnopqrstuv\"\n  }\n}",
        "config.json",
        "AIzaSyA1234567890abcdefghijklmnopqrstuv",
    );
}

#[test]
fn toml_slack_bot_token() {
    assert_found(
        "[slack]\ntoken = \"xoxb-2345678901234-2345678901234-AbCdEfGhIjKlMnOpQrStUvWx\"\n",
        "config.toml",
        "xoxb-2345678901234-2345678901234-AbCdEfGhIjKlMnOpQrStUvWx",
    );
}

#[test]
fn dockerfile_env_stripe_key() {
    assert_found(
        "FROM alpine:3.19\nENV STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000\nRUN echo ok\n",
        "Dockerfile",
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000",
    );
}

#[test]
fn docker_compose_environment_stripe_key() {
    assert_found(
        "services:\n  web:\n    environment:\n      - STRIPE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000\n",
        "docker-compose.yml",
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000",
    );
}

#[test]
fn shell_export_gitlab_token() {
    assert_found(
        "#!/bin/sh\nexport GITLAB_TOKEN=glpat-ABCDEF1234567890abcd\n",
        "deploy.sh",
        "glpat-ABCDEF1234567890abcd",
    );
}

#[test]
fn ini_section_google_key() {
    assert_found(
        "[credentials]\ngoogle_api_key=AIzaSyA1234567890abcdefghijklmnopqrstuv\n",
        "settings.ini",
        "AIzaSyA1234567890abcdefghijklmnopqrstuv",
    );
}

#[test]
fn xml_element_stripe_key() {
    assert_found(
        "<config>\n  <stripe><secretKey>sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000</secretKey></stripe>\n</config>",
        "config.xml",
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000",
    );
}

#[test]
fn java_properties_stripe_key() {
    assert_found(
        "server.port=8080\nstripe.api.key=sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000\n",
        "application.properties",
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000",
    );
}

#[test]
fn http_authorization_bearer_header() {
    assert_found(
        "GET /v1/charges HTTP/1.1\nHost: api.stripe.com\nAuthorization: Bearer sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000\n",
        "request.http",
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc00000000",
    );
}

#[test]
fn github_actions_yaml_secret_literal() {
    assert_found(
        "jobs:\n  build:\n    steps:\n      - env:\n          SLACK: xoxb-2345678901234-2345678901234-AbCdEfGhIjKlMnOpQrStUvWx\n",
        ".github/workflows/ci.yml",
        "xoxb-2345678901234-2345678901234-AbCdEfGhIjKlMnOpQrStUvWx",
    );
}
