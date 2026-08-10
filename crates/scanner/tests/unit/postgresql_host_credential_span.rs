use crate::CompiledScanner;
use keyhog_core::Chunk;

#[test]
fn test_postgresql_connection_string_host_credential_span() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../detectors");
    let specs = keyhog_core::load_detectors(&dir).expect("load detectors");
    let scanner = CompiledScanner::compile(specs).expect("compile scanner");

    let chunk = Chunk::from(
        "pg-url: postgres://user:secret_pass_12345@db.internal.example.com:5432/app_db?sslmode=require#readonly",
    );
    let matches = scanner.scan_coalesced(&[chunk]).expect("scan chunk");

    let postgres_matches: Vec<_> = matches
        .into_iter()
        .flatten()
        .filter(|m| m.detector_id.as_ref() == "postgresql-connection-string")
        .collect();

    assert!(
        !postgres_matches.is_empty(),
        "postgres url pattern must match postgresql-connection-string detector"
    );
    let matched_cred = postgres_matches[0].credential.as_ref();
    assert_eq!(
        matched_cred,
        "postgres://user:secret_pass_12345@db.internal.example.com",
        "postgres credential span must capture exactly the host-bounded user:pass@host portion: got {matched_cred}"
    );
}

/// WHY: host-boundary coverage must not turn credential-free database URLs into findings.
#[test]
fn test_postgresql_connection_string_host_credential_span_negatives() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../detectors");
    let specs = keyhog_core::load_detectors(&dir).expect("load detectors");
    let scanner = CompiledScanner::compile(specs).expect("compile scanner");

    let negative_payloads = [
        "pg-url: postgres://db.internal.example.com:5432/app_db",
        "pg-url: postgres://user@db.internal.example.com:5432/app_db",
    ];
    for payload in negative_payloads {
        let matches = scanner
            .scan_coalesced(&[Chunk::from(payload)])
            .expect("scan chunk");
        assert!(
            matches
                .into_iter()
                .flatten()
                .all(|finding| finding.detector_id.as_ref() != "postgresql-connection-string"),
            "credential-free PostgreSQL URLs must not produce a finding: {payload}"
        );
    }
}
