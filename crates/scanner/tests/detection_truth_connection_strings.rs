//! Detection-truth: database CONNECTION STRINGS + provider tokens (#177/#184).
//! A URI with embedded `user:password@host` is one of the most common real
//! leaks. keyhog fires both the service-specific connection-string detector AND
//! generic-password on the embedded secret. Each test pins the specific
//! detector + the recovered password value (Law 6). ML-independent; run without
//! `ml` while the embedded weights are mid-retrain.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn findings(text: &str) -> Vec<(String, String)> {
    let detectors = keyhog_core::embedded_detector_specs().to_vec();
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "conn-string-test".into(),
            path: Some("s.env".into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .iter()
        .flat_map(|per_chunk| per_chunk.iter())
        .map(|m| (m.detector_id.to_string(), m.credential.as_ref().to_string()))
        .collect()
}

fn assert_fires(text: &str, want_id: &str) {
    let f = findings(text);
    assert!(
        f.iter().any(|(id, _)| id == want_id),
        "expected detector `{want_id}` on {text:?}; got {f:?}"
    );
}

fn assert_password_recovered(text: &str, want_pw: &str) {
    let f = findings(text);
    assert!(
        f.iter()
            .any(|(id, cred)| id == "generic-password" && cred == want_pw),
        "expected generic-password `{want_pw}` on {text:?}; got {f:?}"
    );
}

#[test]
fn postgres_connection_string_and_password() {
    let s = "DATABASE_URL=postgres://dbuser:s3cr3tP4ssw0rd@db.example.com:5432/prod";
    assert_fires(s, "postgresql-connection-string");
    assert_password_recovered(s, "s3cr3tP4ssw0rd");
}

#[test]
fn mysql_connection_string_and_password() {
    let s = "url = mysql://root:MyS3cretPass99@10.0.0.5:3306/app";
    assert_fires(s, "mysql-connection-string");
    assert_password_recovered(s, "MyS3cretPass99");
}

#[test]
fn redis_connection_string_and_password() {
    let s = "REDIS_URL=redis://default:R3disPassw0rd123@redis.example.com:6379";
    assert_fires(s, "redis-connection-string");
    assert_password_recovered(s, "R3disPassw0rd123");
}

#[test]
fn amqp_rabbitmq_credentials_and_password() {
    let s = "broker = amqp://guest:RabbitSecret42@rabbitmq.example.com:5672";
    assert_fires(s, "rabbitmq-credentials");
    assert_password_recovered(s, "RabbitSecret42");
}

#[test]
fn sendgrid_api_key_in_env() {
    assert_fires(
        "SENDGRID_API_KEY=SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg",
        "sendgrid-api-key",
    );
}

#[test]
fn mongodb_uri_password_is_recovered_by_generic_password() {
    // The specific detector and the generic password recovery are both expected
    // on every backend; this assertion pins the embedded-password half.
    assert_password_recovered(
        "MONGO_URI=mongodb://admin:Str0ngMongoPwd@cluster0.example.com:27017/db",
        "Str0ngMongoPwd",
    );
}
