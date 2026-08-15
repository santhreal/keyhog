//! Contract coverage for access-target association.
//!
//! Association is the first keyhog output that answers "what does this open"
//! rather than "where is this", so the contracts worth defending are:
//!
//! * a real connection string yields the endpoint and the database, and neither
//!   value contains the password that sat between them;
//! * a candidate that hashes to a credential in the same report is dropped even
//!   when a rule matched it;
//! * evidence is structural: rule id, line, column, span length, distance. It
//!   never carries document text;
//! * distance decays confidence and the ordering is deterministic;
//! * the pass is bounded by bytes, not by findings squared, and one file is read
//!   once no matter how many findings sit in it;
//! * a finding the pass could not inspect is a visible coverage gap, never an
//!   empty target list that reads as "no doors".

use keyhog_core::{
    associate_access_targets_with, sha256_hash, AccessTargetKind, ContentError, CoverageGapReason,
    CredentialHash, FileContent, FileContentSource, MatchLocation, Redaction, Severity,
    TargetRelation, VerificationResult, VerifiedFinding,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

/// An in-memory content source that counts reads, so a test can prove the index
/// is built once per file rather than once per finding.
#[derive(Default)]
struct MemoryContent {
    files: HashMap<String, String>,
    reads: RefCell<Vec<String>>,
}

impl MemoryContent {
    fn with(path: &str, body: &str) -> Self {
        let mut files = HashMap::new();
        files.insert(path.to_string(), body.to_string());
        Self {
            files,
            reads: RefCell::new(Vec::new()),
        }
    }

    fn add(mut self, path: &str, body: &str) -> Self {
        self.files.insert(path.to_string(), body.to_string());
        self
    }

    fn read_count(&self, path: &str) -> usize {
        self.reads
            .borrow()
            .iter()
            .filter(|seen| *seen == path)
            .count()
    }
}

impl FileContentSource for MemoryContent {
    fn read_prefix(&self, path: &str, max_bytes: u64) -> Result<FileContent, ContentError> {
        self.reads.borrow_mut().push(path.to_string());
        let body = self.files.get(path).ok_or(ContentError::TransientRead)?;
        let cap = usize::try_from(max_bytes).unwrap_or(usize::MAX);
        if body.len() > cap {
            // Cut on a char boundary the way a byte-capped read would have to.
            let mut end = cap;
            while end > 0 && !body.is_char_boundary(end) {
                end -= 1;
            }
            return Ok(FileContent {
                text: body[..end].to_string(),
                truncated: true,
            });
        }
        Ok(FileContent {
            text: body.clone(),
            truncated: false,
        })
    }
}

fn finding(
    credential: &str,
    source: &str,
    path: Option<&str>,
    line: Option<usize>,
) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("generic-password"),
        detector_name: Arc::from("Generic Password"),
        service: Arc::from("generic"),
        severity: Severity::High,
        credential_redacted: "abcd...wxyz".into(),
        credential_hash: sha256_hash(credential),
        companions_redacted: HashMap::new(),
        location: MatchLocation {
            source: Arc::from(source),
            file_path: path.map(Arc::from),
            line,
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Skipped,
        metadata: HashMap::new(),
        additional_locations: Vec::new(),
        entropy: None,
        evidence_score: Some(0.8),
        evidence: keyhog_core::EvidenceVerdict::review_unattributed(),
    }
}

const CONNECTION_STRING: &str =
    "const DATABASE_URL = \"mysql://dmzzpqdc:DXGlyfbp9xHZQajM381Sfwmx@zajgrjseiiwa.example.org:3306/tigiwuns\";\n";

#[test]
fn a_connection_string_yields_its_endpoint_and_database() {
    let content = MemoryContent::with("app.js", CONNECTION_STRING);
    let findings = vec![finding(
        "DXGlyfbp9xHZQajM381Sfwmx",
        "filesystem",
        Some("app.js"),
        Some(1),
    )];

    let report = associate_access_targets_with(&findings, &content);
    assert_eq!(report.targets.len(), 1, "{report:?}");
    let row = &report.targets[0];

    let endpoint = row
        .targets
        .iter()
        .find(|target| target.kind == AccessTargetKind::Endpoint)
        .expect("endpoint target");
    assert_eq!(endpoint.value, "zajgrjseiiwa.example.org:3306");
    assert_eq!(endpoint.evidence.rule_id, "database-uri-endpoint");
    assert_eq!(endpoint.evidence.relation, TargetRelation::SameLine);
    assert_eq!(endpoint.redaction, Redaction::None);

    let database = row
        .targets
        .iter()
        .find(|target| target.kind == AccessTargetKind::Database)
        .expect("database target");
    assert_eq!(database.value, "tigiwuns");
}

#[test]
fn no_target_value_contains_the_password_from_the_connection_string() {
    let content = MemoryContent::with("app.js", CONNECTION_STRING);
    let findings = vec![finding(
        "DXGlyfbp9xHZQajM381Sfwmx",
        "filesystem",
        Some("app.js"),
        Some(1),
    )];

    let report = associate_access_targets_with(&findings, &content);
    for row in &report.targets {
        for target in &row.targets {
            assert!(
                !target.value.contains("DXGlyfbp9xHZQajM381Sfwmx"),
                "password leaked into target value {:?}",
                target.value
            );
            assert!(
                !target.value.contains('@'),
                "userinfo leaked into target value {:?}",
                target.value
            );
        }
    }
}

#[test]
fn a_candidate_that_is_a_reported_credential_is_dropped() {
    // `hunter2hunter2` is both a plausible database name for the rule and the
    // credential another finding in this same report is about. The digest guard
    // must drop it whatever the rule thought.
    let body = "url: postgres://svc@db.internal:5432/hunter2hunter2\n";
    let content = MemoryContent::with("conf.yaml", body);
    let findings = vec![finding(
        "hunter2hunter2",
        "filesystem",
        Some("conf.yaml"),
        Some(1),
    )];

    let report = associate_access_targets_with(&findings, &content);
    let values: Vec<&str> = report
        .targets
        .iter()
        .flat_map(|row| row.targets.iter().map(|target| target.value.as_str()))
        .collect();
    assert!(
        !values.contains(&"hunter2hunter2"),
        "a reported credential was emitted as an access target: {values:?}"
    );
    // The endpoint on the same line is an address, so it survives.
    assert!(values.contains(&"db.internal:5432"), "{values:?}");
}

#[test]
fn evidence_is_structural_and_carries_no_document_text() {
    let content = MemoryContent::with("app.js", CONNECTION_STRING);
    let findings = vec![finding(
        "DXGlyfbp9xHZQajM381Sfwmx",
        "filesystem",
        Some("app.js"),
        Some(1),
    )];

    let report = associate_access_targets_with(&findings, &content);
    let target = &report.targets[0].targets[0];
    let evidence = &target.evidence;
    assert_eq!(evidence.line, Some(1));
    assert!(evidence.column.is_some_and(|column| column > 1));
    assert_eq!(evidence.span_bytes, Some(target.value.len()));
    assert_eq!(evidence.line_distance, Some(0));
    assert_eq!(evidence.provenance.source, "tier_b_rule");

    // Serialize the whole report and prove no document text escaped. The only
    // strings a reader may see are addresses, rule ids, and numbers.
    let json = serde_json::to_string(&report).expect("serialize");
    assert!(!json.contains("DXGlyfbp9xHZQajM381Sfwmx"), "{json}");
    assert!(!json.contains("DATABASE_URL"), "{json}");
    assert!(!json.contains("const "), "{json}");
}

#[test]
fn distance_decays_confidence_and_a_far_match_ranks_below_a_near_one() {
    let mut body = String::from("host: near.example.org:5432\n");
    for _ in 0..120 {
        body.push_str("filler\n");
    }
    body.push_str("host: far.example.org:5432\n");
    // Both lines need a db scheme for the rule to fire.
    let body = body
        .replace("host: near", "url: postgres://svc@near")
        .replace("host: far", "url: postgres://svc@far");

    let content = MemoryContent::with("conf.yaml", &body);
    let findings = vec![finding(
        "secret-value",
        "filesystem",
        Some("conf.yaml"),
        Some(1),
    )];

    let report = associate_access_targets_with(&findings, &content);
    let targets = &report.targets[0].targets;
    let near = targets
        .iter()
        .find(|target| target.value.starts_with("near."))
        .expect("near target");
    let far = targets
        .iter()
        .find(|target| target.value.starts_with("far."))
        .expect("far target");

    assert_eq!(near.evidence.relation, TargetRelation::SameLine);
    assert_eq!(far.evidence.relation, TargetRelation::SameFile);
    assert!(
        near.confidence > far.confidence,
        "near {} should outrank far {}",
        near.confidence,
        far.confidence
    );
    assert!(far.evidence.provenance.decay_steps >= 1);

    let near_position = targets
        .iter()
        .position(|t| t.value.starts_with("near."))
        .unwrap_or(usize::MAX);
    let far_position = targets
        .iter()
        .position(|t| t.value.starts_with("far."))
        .unwrap_or(0);
    assert!(near_position < far_position, "near target must sort first");
}

#[test]
fn one_file_is_indexed_once_regardless_of_how_many_findings_it_holds() {
    let body = "url: postgres://svc@db.example.org:5432/orders\nsecret_a: aaa\nsecret_b: bbb\n";
    let content = MemoryContent::with("conf.yaml", body);
    let findings: Vec<VerifiedFinding> = (0..25)
        .map(|index| {
            finding(
                &format!("credential-{index}"),
                "filesystem",
                Some("conf.yaml"),
                Some(2),
            )
        })
        .collect();

    let report = associate_access_targets_with(&findings, &content);
    assert_eq!(
        content.read_count("conf.yaml"),
        1,
        "the bounded index must read each file once, not once per finding"
    );
    assert_eq!(report.coverage.files_indexed, 1);
    assert_eq!(report.coverage.findings_with_file_context, 25);
    assert_eq!(report.targets.len(), 25);
}

#[test]
fn a_file_larger_than_the_cap_is_reported_truncated_not_silently_complete() {
    // The shipped cap is 1 MiB; build something past it whose only door sits
    // beyond the cap, so a silent truncation would look like a clean file.
    let mut body = String::with_capacity(1_200_000);
    while body.len() < 1_100_000 {
        body.push_str("// padding line with no credential and no address\n");
    }
    body.push_str("url: postgres://svc@hidden.example.org:5432/late\n");

    let content = MemoryContent::with("big.txt", &body);
    let findings = vec![finding(
        "secret-value",
        "filesystem",
        Some("big.txt"),
        Some(1),
    )];

    let report = associate_access_targets_with(&findings, &content);
    assert!(
        !report.coverage.complete,
        "truncation must break completeness"
    );
    let gap = report
        .coverage
        .gaps
        .iter()
        .find(|gap| gap.reason == CoverageGapReason::FileTruncated)
        .expect("truncation gap");
    assert_eq!(gap.findings, 1);
    assert!(gap.explanation.contains("max_file_bytes"), "{gap:?}");
    assert!(report.coverage.bytes_indexed <= 1_048_576);
}

#[test]
fn a_git_history_finding_is_a_coverage_gap_not_an_empty_result() {
    let content = MemoryContent::with("app.js", CONNECTION_STRING);
    let mut historical = finding("secret-value", "filesystem", Some("app.js"), Some(1));
    historical.location.commit = Some(Arc::from("2af3bda6fe8102c0fa7a26774e22af3993a69e2c"));

    let report = associate_access_targets_with(&[historical], &content);
    assert!(report.targets.is_empty());
    assert!(!report.coverage.complete);
    assert_eq!(report.coverage.gaps.len(), 1);
    assert_eq!(
        report.coverage.gaps[0].reason,
        CoverageGapReason::HistoricalContent
    );
    assert_eq!(
        content.read_count("app.js"),
        0,
        "history must not read the working tree"
    );
}

#[test]
fn a_non_filesystem_source_is_a_coverage_gap() {
    let content = MemoryContent::default();
    let report = associate_access_targets_with(
        &[finding(
            "secret-value",
            "docker",
            Some("layer/etc/app.conf"),
            Some(3),
        )],
        &content,
    );
    assert!(!report.coverage.complete);
    assert_eq!(
        report.coverage.gaps[0].reason,
        CoverageGapReason::SourceNotReadable
    );
    assert_eq!(report.coverage.gaps[0].findings, 1);
    assert!(report.coverage.gaps[0]
        .examples
        .contains(&"layer/etc/app.conf".to_string()));
}

#[test]
fn an_unreadable_file_is_tallied_for_every_finding_in_it() {
    let content = MemoryContent::default();
    let findings: Vec<VerifiedFinding> = (0..4)
        .map(|index| {
            finding(
                &format!("credential-{index}"),
                "filesystem",
                Some("gone.txt"),
                Some(1),
            )
        })
        .collect();

    let report = associate_access_targets_with(&findings, &content);
    let gap = report
        .coverage
        .gaps
        .iter()
        .find(|gap| gap.reason == CoverageGapReason::TransientReadFailed)
        .expect("read failure gap");
    assert_eq!(
        gap.findings, 4,
        "a cached read failure must still be tallied per finding"
    );
    assert_eq!(content.read_count("gone.txt"), 1, "and only retried once");
}

#[test]
fn decoded_metadata_yields_an_account_target_with_no_file_read() {
    let content = MemoryContent::default();
    let mut aws = finding("AKIAIOSFODNN7EXAMPLE", "git", None, None);
    aws.detector_id = Arc::from("aws-access-key-id");
    aws.service = Arc::from("aws");
    aws.metadata
        .insert("account_id".to_string(), "123456789012".to_string());

    let report = associate_access_targets_with(&[aws], &content);
    assert_eq!(report.targets.len(), 1);
    let target = &report.targets[0].targets[0];
    assert_eq!(target.kind, AccessTargetKind::Account);
    assert_eq!(target.value, "123456789012");
    assert_eq!(target.evidence.relation, TargetRelation::Decoded);
    assert_eq!(target.evidence.rule_id, "metadata:account_id");
    assert_eq!(target.evidence.provenance.source, "credential_metadata");
    assert_eq!(target.evidence.file_path, None);

    // The finding still had no readable file, and the report says so rather than
    // implying the account is the whole blast radius.
    assert!(!report.coverage.complete);
}

#[test]
fn an_empty_finding_set_produces_an_empty_complete_report() {
    let content = MemoryContent::default();
    let report = associate_access_targets_with(&[], &content);
    assert!(report.is_empty());
    assert!(report.coverage.complete);
    assert_eq!(report.coverage.findings_total, 0);
    assert_eq!(report.coverage.bytes_indexed, 0);
}

#[test]
fn the_same_findings_always_produce_the_same_bytes() {
    let content = MemoryContent::with("a.yaml", "url: postgres://svc@a.example.org:5432/one\n")
        .add("b.yaml", "url: mysql://svc@b.example.org:3306/two\n");
    let findings = vec![
        finding("cred-b", "filesystem", Some("b.yaml"), Some(1)),
        finding("cred-a", "filesystem", Some("a.yaml"), Some(1)),
    ];
    let reversed: Vec<VerifiedFinding> = findings.iter().rev().cloned().collect();

    let first = serde_json::to_string(&associate_access_targets_with(&findings, &content))
        .expect("serialize");
    let second = serde_json::to_string(&associate_access_targets_with(&findings, &content))
        .expect("serialize");
    assert_eq!(first, second);

    // Input order must not change the emitted order: rows sort by path.
    let flipped = serde_json::to_string(&associate_access_targets_with(&reversed, &content))
        .expect("serialize");
    let first_rows = associate_access_targets_with(&findings, &content);
    let flipped_rows = associate_access_targets_with(&reversed, &content);
    assert_eq!(
        first_rows
            .targets
            .iter()
            .map(|row| row.location.file_path.clone())
            .collect::<Vec<_>>(),
        flipped_rows
            .targets
            .iter()
            .map(|row| row.location.file_path.clone())
            .collect::<Vec<_>>()
    );
    assert!(!flipped.is_empty());
}

#[test]
fn credential_hash_type_is_the_join_key_back_to_the_finding() {
    let content = MemoryContent::with("app.js", CONNECTION_STRING);
    let one = finding(
        "DXGlyfbp9xHZQajM381Sfwmx",
        "filesystem",
        Some("app.js"),
        Some(1),
    );
    let expected: CredentialHash = one.credential_hash;
    let report = associate_access_targets_with(&[one], &content);
    assert_eq!(
        report.targets[0].credential_hash,
        keyhog_core::hex_encode(expected)
    );
}

/// A file that vanished between the scan and this pass is a different fact from
/// a file this process may not read. Only the first is worth retrying, so the
/// two must never collapse into one reason.
#[test]
fn a_vanished_file_and_an_unreadable_one_are_different_facts() {
    use std::io::{Error, ErrorKind};

    assert_eq!(
        ContentError::classify(&Error::from(ErrorKind::NotFound)),
        ContentError::TransientRead,
        "a file removed after the scan may be back on the next run"
    );
    assert_eq!(
        ContentError::classify(&Error::from(ErrorKind::Interrupted)),
        ContentError::TransientRead
    );
    assert_eq!(
        ContentError::classify(&Error::from(ErrorKind::WouldBlock)),
        ContentError::TransientRead
    );
    assert_eq!(
        ContentError::classify(&Error::from(ErrorKind::PermissionDenied)),
        ContentError::PermanentRead,
        "retrying will not grant permission"
    );
    assert_eq!(
        ContentError::classify(&Error::from(ErrorKind::Unsupported)),
        ContentError::PermanentRead
    );
}

/// A permanent read failure must reach the report as its own reason, so a
/// retry policy above this pass never wastes a retry on it and an operator is
/// never told to rerun something that cannot change.
#[test]
fn a_permanent_read_failure_is_reported_as_permanent() {
    struct Denied;
    impl FileContentSource for Denied {
        fn read_prefix(&self, _path: &str, _max: u64) -> Result<FileContent, ContentError> {
            Err(ContentError::PermanentRead)
        }
    }

    let report = associate_access_targets_with(
        &[finding(
            "secret-value",
            "filesystem",
            Some("locked.conf"),
            Some(1),
        )],
        &Denied,
    );
    assert!(!report.coverage.complete);
    assert_eq!(
        report.coverage.gaps[0].reason,
        CoverageGapReason::PermanentReadFailed
    );
    assert!(
        report.coverage.gaps[0]
            .explanation
            .contains("rerunning will not"),
        "{:?}",
        report.coverage.gaps[0]
    );
}
