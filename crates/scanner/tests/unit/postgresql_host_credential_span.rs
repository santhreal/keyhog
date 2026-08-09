use crate::testing::named_detector_fixture_defaults;
use crate::CompiledScanner;
use keyhog_core::Chunk;

#[test]
fn test_postgresql_connection_string_host_credential_span() {
    let spec = keyhog_core::DetectorSpec {
        id: "postgresql-connection-string".into(),
        name: "PostgreSQL Connection String".into(),
        service: "postgresql".into(),
        severity: keyhog_core::Severity::Critical,
        patterns: vec![keyhog_core::PatternSpec {
            regex: r#"(?:postgresql|postgres)://[^:]*:[^@\s"'']+@[a-zA-Z0-9._-]+"#.into(),
            ..Default::default()
        }],
        ..named_detector_fixture_defaults()
    };

    let scanner = CompiledScanner::compile(vec![spec]).expect("compile postgresql spec");
    let chunk = Chunk::from("pg-url: postgres://user:secret_pass_12345@db.internal.example.com:5432/app_db?sslmode=require#readonly");
    let matches = scanner.scan_coalesced(&[chunk]).expect("scan chunk");

    assert!(
        !matches.is_empty() && !matches[0].is_empty(),
        "postgres url pattern must match"
    );
    let matched_cred = matches[0][0].credential.as_ref();
    assert_eq!(
        matched_cred,
        "postgres://user:secret_pass_12345@db.internal.example.com",
        "postgres credential span must capture exactly the host-bounded user:pass@host portion: got {matched_cred}"
    );
}
