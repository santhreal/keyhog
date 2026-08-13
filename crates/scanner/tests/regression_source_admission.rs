//! Behavioral contracts for detector-owned positive source admission.

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity, SourceAdmissionSpec};
use keyhog_scanner::CompiledScanner;

const TOKEN: &str = "ADM_7Gk2Nq9Vm4Xs8Wp3Dz6H";

fn scanner() -> CompiledScanner {
    let detector = DetectorSpec {
        id: "source-admitted-token".into(),
        name: "Source admitted token".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: format!(r"\b{TOKEN}\b"),
            required_literals: vec!["ADM_".into()],
            ..Default::default()
        }],
        keywords: vec!["ADM_".into()],
        source_admission: SourceAdmissionSpec {
            path_patterns: vec![r"(?:^|/)secrets/".into()],
            source_types: vec!["filesystem".into()],
            file_extensions: vec!["json".into()],
        },
        min_confidence: Some(0.0),
        match_confidence: keyhog_core::detector_spec_by_id("github-classic-pat")
            .and_then(|detector| detector.match_confidence),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    CompiledScanner::compile(vec![detector]).expect("source admission fixture compiles")
}

fn count(scanner: &CompiledScanner, path: Option<&str>, source_type: &str) -> usize {
    scanner
        .scan(&Chunk {
            data: format!("token={TOKEN}").into(),
            metadata: ChunkMetadata {
                path: path.map(Into::into),
                source_type: source_type.into(),
                ..Default::default()
            },
        })
        .expect("source admission fixture scans")
        .len()
}

/// Every declared selector family must admit the source before the finding survives.
#[test]
fn matching_path_type_and_extension_admit_finding() {
    assert_eq!(
        count(&scanner(), Some("config/secrets/live.json"), "filesystem"),
        1
    );
}

/// A matching path and extension cannot bypass a mismatched source type.
#[test]
fn mismatched_source_type_rejects_finding() {
    assert_eq!(
        count(&scanner(), Some("config/secrets/live.json"), "git-history"),
        0
    );
}

/// A matching source type and extension cannot bypass the positive path selector.
#[test]
fn mismatched_path_rejects_finding() {
    assert_eq!(
        count(&scanner(), Some("config/public/live.json"), "filesystem"),
        0
    );
}

/// Missing paths and case-varied extensions exercise fail-closed metadata and case-insensitive suffix matching.
#[test]
fn missing_path_rejects_while_case_varied_extension_is_admitted() {
    let scanner = scanner();
    assert_eq!(count(&scanner, None, "filesystem"), 0);
    assert_eq!(
        count(&scanner, Some("config/secrets/live.JSON"), "filesystem"),
        1
    );
    assert_eq!(
        count(&scanner, Some("config/secrets/live.json.bak"), "filesystem"),
        0
    );
}
#[cfg(feature = "decode")]
#[test]
fn registered_decode_provenance_preserves_source_admission() {
    use base64::Engine;

    let scanner = scanner();
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(format!("token={TOKEN}").as_bytes());
    let matches = scanner
        .scan(&Chunk {
            data: format!("payload={encoded}").into(),
            metadata: ChunkMetadata {
                path: Some("config/secrets/live.json".into()),
                source_type: "filesystem".into(),
                ..Default::default()
            },
        })
        .expect("decoded source-admission fixture scans");

    assert!(
        matches
            .iter()
            .any(|matched| matched.detector_id.as_ref() == "source-admitted-token"),
        "a registered decoder suffix must not change source-admission truth"
    );
}

fn netrc_scanner() -> CompiledScanner {
    let detector = keyhog_core::detector_spec_by_id("netrc-password")
        .expect("the shipped netrc detector must exist");
    CompiledScanner::compile(vec![detector.clone()])
        .expect("the shipped netrc detector must compile")
}

fn netrc_count(path: Option<&str>) -> usize {
    netrc_scanner()
        .scan(&Chunk {
            data: "machine api.example.com login deploy password Zx9Qw3Rt7Lp2Mk".into(),
            metadata: ChunkMetadata {
                path: path.map(Into::into),
                source_type: "filesystem".into(),
                ..Default::default()
            },
        })
        .expect("the netrc admission fixture scans")
        .into_iter()
        .filter(|matched| matched.detector_id.as_ref() == "netrc-password")
        .count()
}

/// Canonical Unix, authinfo, and Windows netrc filenames must retain the credential.
#[test]
fn shipped_netrc_policy_admits_every_supported_credential_filename() {
    assert_eq!(netrc_count(Some("/home/alice/.netrc")), 1);
    assert_eq!(netrc_count(Some("/home/alice/.authinfo")), 1);
    assert_eq!(netrc_count(Some(r"C:\Users\alice\_netrc")), 1);
}

/// Netrc-shaped prose, backups, and pathless streams must not bypass positive source admission.
#[test]
fn shipped_netrc_policy_rejects_noncredential_source_boundaries() {
    assert_eq!(netrc_count(Some("docs/netrc-example.txt")), 0);
    assert_eq!(netrc_count(Some("/home/alice/.netrc.backup")), 0);
    assert_eq!(netrc_count(None), 0);
}
