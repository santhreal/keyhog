//! Production-path regressions for observed detector false-positive classes.
//!
//! The matrix keeps provider and command recall while rejecting identifier,
//! sibling-prefix, provider-overlap, and detector-rule collisions.

mod support;

use keyhog_scanner::CompiledScanner;
use std::sync::Mutex;
use support::contracts::{make_chunk, scanner};

static SCAN_LOCK: Mutex<()> = Mutex::new(());

struct Case {
    label: &'static str,
    detector_id: &'static str,
    text: &'static str,
    path: &'static str,
}

fn reports(scanner: &CompiledScanner, case: &Case) -> bool {
    let _guard = SCAN_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    scanner.clear_fragment_cache();
    scanner
        .scan(&make_chunk(case.text, "filesystem", case.path))
        .expect("observed detector-class scan succeeds")
        .iter()
        .any(|matched| matched.detector_id.as_ref() == case.detector_id)
}

/// WHY: precision repairs must not trade away real provider assignments or
/// command arguments. The cases span every operator surface named by the
/// repaired detector contracts.
#[test]
fn observed_detector_repairs_preserve_genuine_counterparts() {
    let cases = [
        Case {
            label: "atlas exact environment assignment",
            detector_id: "mongodb-atlas-api-key",
            text: "MONGODB_ATLAS_PUBLIC_KEY=eHIfkXby",
            path: ".env",
        },
        Case {
            label: "atlas paired public and private keys",
            detector_id: "mongodb-atlas-api-key",
            text: "ATLAS=eHIfkXby\nMONGODB_ATLAS_PRIVATE_KEY=12345678-1234-1234-1234-123456789abc",
            path: "application.env",
        },
        Case {
            label: "atlas paired structured assignments",
            detector_id: "mongodb-atlas-api-key",
            text: "MONGODB_ATLAS_PUBLIC_KEY: eHIfkXby\nMONGODB_ATLAS_PRIVATE_KEY: 12345678-1234-1234-1234-123456789abc",
            path: "application.yml",
        },
        Case {
            label: "CLI shell argument",
            detector_id: "cli-password-flag",
            text: "mysql --password Xy9KmPq2LvWnB7tR",
            path: "deploy.sh",
        },
        Case {
            label: "CLI Dockerfile argument",
            detector_id: "cli-password-flag",
            text: "RUN mysql --password=Xy9KmPq2LvWnB7tR",
            path: "Dockerfile",
        },
        Case {
            label: "CLI PowerShell argument",
            detector_id: "cli-password-flag",
            text: "tool.exe -Password Xy9KmPq2LvWnB7tR",
            path: "deploy.ps1",
        },
        Case {
            label: "CLI CI argument",
            detector_id: "cli-password-flag",
            text: "args: --password Xy9KmPq2LvWnB7tR",
            path: "pipeline.yml",
        },
        Case {
            label: "CLI programmatic literal argument",
            detector_id: "cli-password-flag",
            text: "Command::new(\"mysql\").args([\"--password=Xy9KmPq2LvWnB7tR\"])",
            path: "main.rs",
        },
        Case {
            label: "Scalr assigned JWT",
            detector_id: "scalr-api-token",
            text: "SCALR_TOKEN=eyJabcdefgh.eyJabcdefghij.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
            path: ".env",
        },
        Case {
            label: "generic JWT with cryptographic signature floor",
            detector_id: "jwt-token",
            text: "TOKEN=eyJabcdefgh.eyJabcdefghij.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
            path: "application.env",
        },
        Case {
            label: "bare Helicone read key",
            detector_id: "helicone-api-key",
            text: "sk-0ocqX7mxUDlWFHzlNiC0oKONoezJ9vAX",
            path: "secret.txt",
        },
        Case {
            label: "short Helicone key with owned header",
            detector_id: "helicone-api-key",
            text: "Helicone-Auth: Bearer sk-Ab3xY7zQ9mK2wL5jH8nR4pT6",
            path: "request.http",
        },
        Case {
            label: "Helicone-owned key at OpenAI legacy length",
            detector_id: "helicone-api-key",
            text: "HELICONE_API_KEY=sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ",
            path: ".env",
        },
        Case {
            label: "canonical OpenAI legacy key",
            detector_id: "openai-api-key",
            text: "OPENAI_API_KEY=sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ",
            path: ".env",
        },
        Case {
            label: "Druid password assignment",
            detector_id: "druid-credentials",
            text: "DRUID_PASSWORD=AFHzLDdEbht+JO%$Qr",
            path: ".env",
        },
        Case {
            label: "sovereign private key id assignment",
            detector_id: "google-cloud-sovereign-credentials",
            text: "GOOGLE_SOVEREIGN_PRIVATE_KEY_ID=0123456789abcdef0123456789abcdef01234567",
            path: "service-account.env",
        },
        Case {
            label: "RabbitMQ password assignment",
            detector_id: "rabbitmq-credentials",
            text: "RABBITMQ_PASSWORD=SecretPass123456",
            path: ".env",
        },
    ];
    let scanner = scanner();

    let failures = cases
        .iter()
        .filter(|case| !reports(&scanner, case))
        .map(|case| case.label)
        .collect::<Vec<_>>();
    assert!(
        failures.is_empty(),
        "genuine detector counterparts stopped surfacing: {}",
        failures.join(", ")
    );
}

/// WHY: each reported incident represents a class. Sibling variants keep the
/// test from passing through one reproduction-specific exclusion.
#[test]
fn observed_detector_repairs_reject_siblings_and_rule_literals() {
    let cases = [
        Case {
            label: "Atlas field type",
            detector_id: "mongodb-atlas-api-key",
            text: "atlas: GlyphAtlas",
            path: "renderer.rs",
        },
        Case {
            label: "Atlas constructor",
            detector_id: "mongodb-atlas-api-key",
            text: "let atlas = GlyphAtlas::new(device);",
            path: "renderer.rs",
        },
        Case {
            label: "Atlas generation identifier",
            detector_id: "mongodb-atlas-api-key",
            text: "atlas_generation: u64",
            path: "renderer.rs",
        },
        Case {
            label: "CLI add-password declaration",
            detector_id: "cli-password-flag",
            text: "option = \"--add-password=Passphrase\"",
            path: "options.rs",
        },
        Case {
            label: "CLI db-password declaration",
            detector_id: "cli-password-flag",
            text: "option = \"--db-password=SecretValue\"",
            path: "options.ts",
        },
        Case {
            label: "CLI password-policy declaration",
            detector_id: "cli-password-flag",
            text: "name = \"--password-policy=required\"",
            path: "options.py",
        },
        Case {
            label: "CLI flag embedded in an identifier",
            detector_id: "cli-password-flag",
            text: "name = \"x--password=SecretValue\"",
            path: "options.go",
        },
        Case {
            label: "short Scalr-shaped bearer example",
            detector_id: "scalr-api-token",
            text: "Authorization: Bearer eyJ.eyJ.sig",
            path: "jwt_example.rs",
        },
        Case {
            label: "Scalr JWT below signature boundary",
            detector_id: "scalr-api-token",
            text: "SCALR_TOKEN=eyJabcdefgh.eyJabcdefghij.ABCDEFGHIJKLMNOPQRS",
            path: "fixture.env",
        },
        Case {
            label: "short OpenAI sibling assigned as OpenAI",
            detector_id: "helicone-api-key",
            text: "OPENAI_API_KEY=sk-abc123def456ghi789jklmnopqrs",
            path: "migration.rs",
        },
        Case {
            label: "longer short OpenAI sibling assigned as OpenAI",
            detector_id: "helicone-api-key",
            text: "OPENAI_API_KEY=sk-abc123def456ghi789jklmnopqrstu",
            path: "migration_test.rs",
        },
        Case {
            label: "Helicone key below bare length boundary",
            detector_id: "helicone-api-key",
            text: "OPENAI_API_KEY=sk-0ocqX7mxUDlWFHzlNiC0oKONoezJ9vA",
            path: "migration_fixture.rs",
        },
        Case {
            label: "canonical OpenAI key owned by OpenAI",
            detector_id: "helicone-api-key",
            text: "OPENAI_API_KEY=sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ",
            path: ".env",
        },
        Case {
            label: "quoted OpenAI sibling assigned as OpenAI",
            detector_id: "helicone-api-key",
            text: "OPENAI_API_KEY=\"sk-abc123def456ghi789jklmnopqrs\"",
            path: "migration_quoted.rs",
        },
        Case {
            label: "quoted canonical OpenAI key owned by OpenAI",
            detector_id: "helicone-api-key",
            text: "OPENAI_API_KEY=\"sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ\"",
            path: ".env",
        },
        Case {
            label: "Druid detector regex literal",
            detector_id: "druid-credentials",
            text: "regex = \"(?:DRUID)[_\\s]*(?:URL|HOST)[=:\\s\\\"'']+(?:https?://|druid://)?(?:[^:@]+):([^@]+)@\"",
            path: "druid-credentials.toml",
        },
        Case {
            label: "sovereign detector regex literal",
            detector_id: "google-cloud-sovereign-credentials",
            text: "regex = \"(?:GOOGLE[_-]?CLOUD[_-]?SOVEREIGN|GOOGLE[_-]?SOVEREIGN)[_\\s]*(?:PROJECT[_-]?ID)[=:\\s\\\"'']+([a-z][a-z0-9-]{4,28})\"",
            path: "google-cloud-sovereign-credentials.toml",
        },
        Case {
            label: "RabbitMQ detector name literal",
            detector_id: "rabbitmq-credentials",
            text: "name = \"rabbitmq_username\"",
            path: "rabbitmq-management-credentials.toml",
        },
    ];
    let scanner = scanner();

    let failures = cases
        .iter()
        .filter(|case| reports(&scanner, case))
        .map(|case| case.label)
        .collect::<Vec<_>>();
    assert!(
        failures.is_empty(),
        "observed false-positive siblings still surfaced: {}",
        failures.join(", ")
    );
}
