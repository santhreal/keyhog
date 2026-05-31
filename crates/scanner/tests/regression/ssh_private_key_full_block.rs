use keyhog_core::{Chunk, ChunkMetadata, DedupScope, dedup_matches};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

const EC_KEY_ONE: &str = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIOm3mXvR6x1N8z4Gq9nV0lQaB7yZpC2sTdUf5hJkLmNo\n-----END EC PRIVATE KEY-----";
const EC_KEY_TWO: &str = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEINx7qMb2vL4pR9sAe3TyK0hCu8WdF6gJzQnVp5kXyZaB\n-----END EC PRIVATE KEY-----";

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

fn scan_fixture(text: &str) -> Vec<keyhog_core::RawMatch> {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let ssh = detectors
        .iter()
        .find(|detector| detector.id == "ssh-private-key")
        .expect("ssh-private-key detector must load");
    assert!(
        ssh.patterns
            .iter()
            .any(|pattern| pattern.regex.contains("-----END EC PRIVATE KEY-----")),
        "ssh-private-key detector must load the full-block PEM regex; got {:?}",
        ssh.patterns
            .iter()
            .map(|pattern| pattern.regex.as_str())
            .collect::<Vec<_>>()
    );
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("secrets.pem".into()),
            ..Default::default()
        },
    };
    scanner.scan(&chunk)
}

#[test]
fn ssh_private_key_full_blocks_stay_distinct_under_credential_dedup() {
    let fixture = format!("{EC_KEY_ONE}\n\n{EC_KEY_TWO}");
    let raw = scan_fixture(&fixture);
    let ssh_matches: Vec<_> = raw
        .into_iter()
        .filter(|m| m.detector_id.as_ref() == "ssh-private-key")
        .collect();

    assert_eq!(
        ssh_matches.len(),
        2,
        "two distinct EC PEM blocks must produce two raw ssh-private-key matches"
    );
    assert!(
        ssh_matches
            .iter()
            .any(|m| m.credential.as_ref() == EC_KEY_ONE),
        "first EC key body must be part of the reported credential: {ssh_matches:?}"
    );
    assert!(
        ssh_matches
            .iter()
            .any(|m| m.credential.as_ref() == EC_KEY_TWO),
        "second EC key body must be part of the reported credential: {ssh_matches:?}"
    );

    let deduped = dedup_matches(ssh_matches, &DedupScope::Credential);
    assert_eq!(
        deduped.len(),
        2,
        "credential-scope dedup must not collapse distinct keys that share the same PEM header"
    );
    assert!(
        deduped.iter().all(|m| m.additional_locations.is_empty()),
        "distinct private keys must be primary findings, not hidden in additional_locations"
    );
}

#[test]
fn ssh_private_key_header_only_marker_is_not_a_credential() {
    let raw = scan_fixture("-----BEGIN EC PRIVATE KEY-----");
    assert!(
        raw.iter()
            .all(|m| m.detector_id.as_ref() != "ssh-private-key"),
        "header-only PEM markers must not produce ssh-private-key findings: {raw:?}"
    );
}
