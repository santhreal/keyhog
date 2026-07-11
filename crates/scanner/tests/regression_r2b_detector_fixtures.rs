//! R2-B detector truth fixtures. These began as a print-only tuning probe; each
//! row is now a release-blocking positive contract.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::sync::LazyLock;

#[path = "support/mod.rs"]
mod support;
use support::paths::detector_dir;

static DETECTORS: LazyLock<Vec<keyhog_core::DetectorSpec>> =
    LazyLock::new(|| keyhog_core::load_detectors(&detector_dir()).expect("load detectors"));

fn scanner(detector_id: &str) -> CompiledScanner {
    let detector = DETECTORS
        .iter()
        .find(|detector| detector.id == detector_id)
        .unwrap_or_else(|| panic!("missing detector {detector_id}"))
        .clone();
    CompiledScanner::compile(vec![detector]).expect("compile focused detector")
}

fn scan(scanner: &CompiledScanner, detector_id: &str, text: &str) -> Vec<String> {
    scanner.clear_fragment_cache();
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "probe".into(),
            path: Some("contract.txt".into()),
            ..Default::default()
        },
    };
    scanner
        .scan(&chunk)
        .into_iter()
        .filter(|m| m.detector_id.as_ref() == detector_id)
        .map(|m| m.credential.as_ref().to_string())
        .collect()
}

#[test]
fn r2b_top50_candidates_are_detected() {
    let cases: &[(&str, &[(&str, &str)])] = &[
        (
            "foundation-api-key",
            &[
                (
                    "foundation API KEY=\"M9TBrKrmGsNmjQ8mT3OA94HhblZa\"",
                    "M9TBrKrmGsNmjQ8mT3OA94HhblZa",
                ),
                (
                    "FOUNDATION KEY=\"odFX1GOZrhrztAQpiN0k8s0Rc3VgTg9\"",
                    "odFX1GOZrhrztAQpiN0k8s0Rc3VgTg9",
                ),
            ],
        ),
        (
            "genesys-cloud-credentials",
            &[
                (
                    "GENESYS CLIENT ID=2963950e-3ed2-e3dc-49d5-740982bac6a9",
                    "2963950e-3ed2-e3dc-49d5-740982bac6a9",
                ),
                (
                    "purecloud client_secret=\"3f2da167246ebe0e04dc37c9e74a75b5b95a61d015\"",
                    "3f2da167246ebe0e04dc37c9e74a75b5b95a61d015",
                ),
            ],
        ),
        (
            "github-app-private-key",
            &[
                (
                    "-----BEGIN RSA PRIVATE KEY-----\ndlV24zQrYwR9Sp8Rc182G8EmK6e2QyaZs/mHkr2CHwPzwWeq99cv5x18sWmE8aWZ\n02TE7k6yGCaz19klBt3oxH8sn20kPTZPbD8l848y8zn5+4b8VauL81Yo5DrW3XKB\nxNA6kEdkADdGjpXsZbe3yaoZKSV5n5HQN48qBcCFyCu6bnuOFniyJwvUuVnrjkAY\nJsdt7Ag8XuB1E85A46rqL/fDPQPD78PcCzz7/7JkG1dlOCFPV2PKwVDx/Y8RBjiG\nit8PLSWzqJt0dK1SLhUnCCrjIVQjacw5wTfEEQ==\n-----END RSA PRIVATE KEY-----\n",
                    "-----BEGIN RSA PRIVATE KEY-----\ndlV24zQrYwR9Sp8Rc182G8EmK6e2QyaZs/mHkr2CHwPzwWeq99cv5x18sWmE8aWZ\n02TE7k6yGCaz19klBt3oxH8sn20kPTZPbD8l848y8zn5+4b8VauL81Yo5DrW3XKB\nxNA6kEdkADdGjpXsZbe3yaoZKSV5n5HQN48qBcCFyCu6bnuOFniyJwvUuVnrjkAY\nJsdt7Ag8XuB1E85A46rqL/fDPQPD78PcCzz7/7JkG1dlOCFPV2PKwVDx/Y8RBjiG\nit8PLSWzqJt0dK1SLhUnCCrjIVQjacw5wTfEEQ==\n-----END RSA PRIVATE KEY-----",
                ),
            ],
        ),
        (
            "google-cloud-iot-credentials",
            &[
                (
                    "cloudiot PROJECT_ID=my-iot-project-01",
                    "my-iot-project-01",
                ),
                (
                    "CLOUDIOT_REGISTRY_ID=my-registry-01",
                    "my-registry-01",
                ),
            ],
        ),
        (
            "google-cloud-sovereign-credentials",
            &[
                (
                    "GOOGLE_CLOUD_SOVEREIGN PROJECT_ID=my-sovereign-project-01",
                    "my-sovereign-project-01",
                ),
                (
                    "GOOGLE_SOVEREIGN CLIENT_ID=123456789012345678901",
                    "123456789012345678901",
                ),
            ],
        ),
        (
            "google-forms-api-credentials",
            &[
                (
                    "google forms api key abcdefghijklmnopqrstuvwxyz123456",
                    "abcdefghijklmnopqrstuvwxyz123456",
                ),
                (
                    "GOOGLE_FORMS private_key=\"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcA==\"",
                    "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcA==",
                ),
            ],
        ),
        (
            "google-meet-api",
            &[
                (
                    "GOOGLE_MEET_API_KEY=\"JodFX1GOZrhrztAQpiN0k8s0Rc3VgTg9abcd\"",
                    "JodFX1GOZrhrztAQpiN0k8s0Rc3VgTg9abcd",
                ),
                (
                    "GMEET_SECRET=M9TBrKrmGsNmjQ8mT3OA94HhblZaQFPiyCEs5lkO",
                    "M9TBrKrmGsNmjQ8mT3OA94HhblZaQFPiyCEs5lkO",
                ),
            ],
        ),
        (
            "google-oauth-client-secret",
            &[
                (
                    "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Iofz",
                    "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",
                ),
                (
                    "google_client_secret=\"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Iofz\"",
                    "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",
                ),
            ],
        ),
        (
            "goto-meeting-api",
            &[
                (
                    "GOTO_MEETING_API_KEY=\"JodFX1GOZrhrztAQpiN0k8s0Rc3VgTg9abcd\"",
                    "JodFX1GOZrhrztAQpiN0k8s0Rc3VgTg9abcd",
                ),
                (
                    "gotomeeting access_token=M9TBrKrmGsNmjQ8mT3OA94HhblZaQFPiyCEs5lkO",
                    "M9TBrKrmGsNmjQ8mT3OA94HhblZaQFPiyCEs5lkO",
                ),
            ],
        ),
        (
            "gravity-forms-rest-api-key",
            &[
                (
                    "gravity forms api key abcdef0123456789abcdef0123456789",
                    "abcdef0123456789abcdef0123456789",
                ),
                (
                    "GRAVITY_FORMS private_key=\"fedcba9876543210fedcba9876543210\"",
                    "fedcba9876543210fedcba9876543210",
                ),
            ],
        ),
        (
            "gumroad-api-key",
            &[
                (
                    "gumroad access_token=b2963950e3ed2e3dc49d5740982bac6a94",
                    "b2963950e3ed2e3dc49d5740982bac6a94",
                ),
                (
                    "GUMROAD api_key=\"353f2da167246ebe0e04dc37c9e74a75b5b95a61d015\"",
                    "353f2da167246ebe0e04dc37c9e74a75b5b95a61d015",
                ),
            ],
        ),
        (
            "hubspot-private-app-token",
            &[
                (
                    concat!("pat-", "na1-a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
                    concat!("pat-", "na1-a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
                ),
                (
                    "export pat-na1-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    concat!("pat-", "na1-a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
                ),
            ],
        ),
        (
            "ibm-cloud-government-credentials",
            &[
                (
                    "IBM_CLOUD_GOV API KEY=\"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGh\"",
                    "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGh",
                ),
                (
                    "IBM_CLOUD_GOV REGION=us-south",
                    "us-south",
                ),
            ],
        ),
        (
            "idenfy-api-credentials",
            &[
                (
                    "idenfy api_key \"H_ZM9TBrKrmGsNmjQ8mT3OA9\"",
                    "H_ZM9TBrKrmGsNmjQ8mT3OA9",
                ),
                (
                    "IDENFY api_key: LwJodFX1GOZrhrztAQpiN0k8s0Rc3VgTg9",
                    "LwJodFX1GOZrhrztAQpiN0k8s0Rc3VgTg9",
                ),
            ],
        ),
        (
            "jotform-api-key",
            &[
                (
                    "jotform api key 2963950e3ed2e3dc49d5740982bac6a9",
                    "2963950e3ed2e3dc49d5740982bac6a9",
                ),
                (
                    "JOTFORM_API_KEY 53f2da167246ebe0e04dc37c9e74a75b",
                    "53f2da167246ebe0e04dc37c9e74a75b",
                ),
            ],
        ),
        (
            "jumio-api-credentials",
            &[
                (
                    "jumio api_token H_ZM9TBrKrmGsNmjQ8mT3OA94Hh",
                    "H_ZM9TBrKrmGsNmjQ8mT3OA94Hh",
                ),
                (
                    "JUMIO client_secret=\"LwJodFX1GOZrhrztAQpiN0k8s0Rc3VgTg9abcd\"",
                    "LwJodFX1GOZrhrztAQpiN0k8s0Rc3VgTg9abcd",
                ),
            ],
        ),
        (
            "kafka-connect-credentials",
            &[
                (
                    "connect.password=SecretPass123456",
                    "SecretPass123456",
                ),
                (
                    "CONNECT_PASSWORD=\"KafkaConnectPass123\"",
                    "KafkaConnectPass123",
                ),
            ],
        ),
        (
            "kafka-sasl-credentials",
            &[
                (
                    "KAFKA_SASL_PASSWORD=SecretPass123456",
                    "SecretPass123456",
                ),
                (
                    "sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username=\"kafkauser\" password=\"SecretPass123456\";",
                    "SecretPass123456",
                ),
            ],
        ),
        (
            "lastpass-dev-creds",
            &[
                ("lastpass id=9860386", "9860386"),
                ("LASTPASS id=9860387", "9860387"),
            ],
        ),
        (
            "line-api-token",
            &[
                (
                    "line channel_secret=0123456789abcdef0123456789abcdef",
                    "0123456789abcdef0123456789abcdef",
                ),
                (
                    "LINE CHANNEL_ACCESS_TOKEN=\"/ZM9TBrKrmGsNmjQ8mT3OA94HhblZa+QFPiyCEs5lkO/nMLpQAK4lXOELxyxeH8ilqtekYJEB1J5+TkPo/QyFcIoCVvQ2hmsCfjd==\"",
                    "/ZM9TBrKrmGsNmjQ8mT3OA94HhblZa+QFPiyCEs5lkO/nMLpQAK4lXOELxyxeH8ilqtekYJEB1J5+TkPo/QyFcIoCVvQ2hmsCfjd==",
                ),
            ],
        ),
        (
            "postgresql-connection-string",
            &[
                (
                    "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech/neondb",
                    "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech",
                ),
            ],
        ),
        (
            "rabbitmq-credentials",
            &[
                (
                    "amqp://user:SecretPass123456@rabbitmq.example.com:5672/vhost",
                    "SecretPass123456",
                ),
            ],
        ),
        (
            "reddit-ads-api-credentials",
            &[
                (
                    "reddit_ads_client_id=AbCdEfGhIjKlMn",
                    "AbCdEfGhIjKlMn",
                ),
            ],
        ),
        (
            "sanity-api-token",
            &[
                (
                    "SANITY_API_TOKEN=sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
                    "sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
                ),
                (
                    "SANITY_API_TOKEN=\"sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289\"",
                    "sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
                ),
            ],
        ),
        (
            "socure-api-key",
            &[
                (
                    "socure api key=abcdefghijklmnopqrstuvwx",
                    "abcdefghijklmnopqrstuvwx",
                ),
                (
                    "SOCURE sdk_key=\"abcdefghijklmnopqrstuvwx123456\"",
                    "abcdefghijklmnopqrstuvwx123456",
                ),
            ],
        ),
        (
            "splitio-api-key",
            &[
                (
                    "split_io_api_key=YWJjZGVmZ2hpamtsbW5vcA==",
                    "YWJjZGVmZ2hpamtsbW5vcA==",
                ),
            ],
        ),
        (
            "statuscake-api-key",
            &[
                (
                    "statuscake api_key abcdefghijklmnopqrstuvwx",
                    "abcdefghijklmnopqrstuvwx",
                ),
                (
                    "STATUSCAKE token: \"abcdefghijklmnopqrstuvwx\"",
                    "abcdefghijklmnopqrstuvwx",
                ),
            ],
        ),
        (
            "google-artifact-registry-key",
            &[
                (
                    r#"_json_key="{\"type\":\"service_account\",\"private_key\":\"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\"}""#,
                    "-----BEGIN PRIVATE KEY-----",
                ),
            ],
        ),
        (
            "google-classroom-api-credentials",
            &[
                (
                    "classroom api key ya29.Habcdefghijklmnopqrstuvwxyz1234567890abcd",
                    "ya29.Habcdefghijklmnopqrstuvwxyz1234567890abcd",
                ),
            ],
        ),
        (
            "invision-api-key",
            &[
                (
                    "IPS4 api key abcdef0123456789abcdef0123456789",
                    "abcdef0123456789abcdef0123456789",
                ),
            ],
        ),
        (
            "prometheus-remote-write-credentials",
            &[
                (
                    "remote_write:\n  - url: https://prom.example.com/api/v1/write\n    basic_auth:\n      username: prom_remote_user\n      password: s3cr3t",
                    "prom_remote_user",
                ),
            ],
        ),
        (
            "render-deploy-hook",
            &[
                (
                    "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
                    "https://api.render.com/deploy/srv-io418fk5icxm3yawaaove0uasyyelq6t5818ilo9b92bkw1pt15ff3jkwo0y6h80mz4zp1ho6h5p3r84ra0f3fjh6sk03mtpz9?key=6EW1MZSw_KYtNzt_qVhQ2jVpB8XWuRi8lXju",
                ),
            ],
        ),
        (
            "lark-app-id",
            &[
                (
                    "lark app_id cli_a1b2c3d4e5f67890",
                    "cli_a1b2c3d4e5f67890",
                ),
            ],
        ),
    ];

    for (det, texts) in cases {
        let scanner = scanner(det);
        for (text, expected) in *texts {
            let creds = scan(&scanner, det, text);
            assert!(
                creds.iter().any(|credential| credential == expected),
                "{det} missed expected credential {expected:?} in {text:?}; got {creds:?}"
            );
        }
    }
}

#[test]
fn r2b_retry_fixtures_are_detected() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "genesys-cloud-credentials",
            "GENESYS_CLIENT_ID=2963950e-3ed2-e3dc-49d5-740982bac6a9",
            "2963950e-3ed2-e3dc-49d5-740982bac6a9",
        ),
        (
            "jotform-api-key",
            "jotform api_key 2963950e3ed2e3dc49d5740982bac6a9",
            "2963950e3ed2e3dc49d5740982bac6a9",
        ),
        (
            "jotform-api-key",
            "JOTFORM API KEY 2963950e3ed2e3dc49d5740982bac6a9",
            "2963950e3ed2e3dc49d5740982bac6a9",
        ),
        (
            "gravity-forms-rest-api-key",
            "gravityforms api key abcdef0123456789abcdef0123456789",
            "abcdef0123456789abcdef0123456789",
        ),
        (
            "statuscake-api-key",
            "statuscake_api_key=abcdefghijklmnopqrstuvwx",
            "abcdefghijklmnopqrstuvwx",
        ),
        (
            "invision-api-key",
            "IPS4 api_key=\"abcdef0123456789abcdef0123456789\"",
            "abcdef0123456789abcdef0123456789",
        ),
        (
            "reddit-ads-api-credentials",
            "reddit ads client_id=AbCdEfGhIjKlMn",
            "AbCdEfGhIjKlMn",
        ),
        (
            "ibm-cloud-government-credentials",
            "IBM_CLOUD_GOV API_KEY=\"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGh\"",
            "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGh",
        ),
        (
            "google-artifact-registry-key",
            r#"{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"}"#,
            "-----BEGIN PRIVATE KEY-----",
        ),
        (
            "jumio-api-credentials",
            "jumio client_secret LwJodFX1GOZrhrztAQpiN0k8s0Rc3VgTg9abcd",
            "LwJodFX1GOZrhrztAQpiN0k8s0Rc3VgTg9abcd",
        ),
        (
            "kafka-connect-credentials",
            "CONNECT_PASSWORD=KafkaConnectPass123",
            "KafkaConnectPass123",
        ),
        (
            "line-api-token",
            "LINE channel_secret=0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef",
        ),
        (
            "google-cloud-sovereign-credentials",
            "GOOGLE_SOVEREIGN PRIVATE_KEY_ID=0123456789abcdef0123456789abcdef01234567",
            "0123456789abcdef0123456789abcdef01234567",
        ),
    ];
    for (det, text, expected) in cases {
        let scanner = scanner(det);
        let creds = scan(&scanner, det, text);
        assert!(
            creds.iter().any(|credential| credential == expected),
            "{det} missed expected credential {expected:?} in {text:?}; got {creds:?}"
        );
    }
}

#[test]
fn r2b_path_shape_fixtures_are_detected() {
    let cases = [
        (
            "marketo-api-credentials",
            "MARKETO_CLIENT_ID=abcdefghijklmnopqrstuvwx12",
            "abcdefghijklmnopqrstuvwx12",
        ),
        (
            "marketo-api-credentials",
            "MARKETO_CLIENT_SECRET=fedcba9876543210fedcba98",
            "fedcba9876543210fedcba98",
        ),
        (
            "pardot-api-credentials",
            "PARDOT_BUSINESS_UNIT_ID=0Uv1234567890AbCdE",
            "0Uv1234567890AbCdE",
        ),
        (
            "reddit-ads-api-credentials",
            "reddit_ads_client_id=AbCdEfGhIjKlMnOp",
            "AbCdEfGhIjKlMnOp",
        ),
        (
            "spotify-client-credentials",
            "SPOTIFY_CLIENT_ID=25b7136a1e10908bb8e7a0f15e1a29d2",
            "25b7136a1e10908bb8e7a0f15e1a29d2",
        ),
        (
            "spotify-client-credentials",
            "SPOTIFY_CLIENT_SECRET=cba9f43862d7150a9e3b1f84d7e6025c",
            "cba9f43862d7150a9e3b1f84d7e6025c",
        ),
    ];
    for (det, text, expected) in cases {
        let scanner = scanner(det);
        let creds = scan(&scanner, det, text);
        assert!(
            creds.iter().any(|credential| credential == expected),
            "{det} missed expected credential {expected:?} in {text:?}; got {creds:?}"
        );
    }
}
