use keyhog_core::{Allowlist, MatchLocation, Severity, VerificationResult, VerifiedFinding};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

struct GuardedWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for GuardedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedWriter {
    type Writer = GuardedWriter;

    fn make_writer(&'a self) -> Self::Writer {
        GuardedWriter(self.0.clone())
    }
}

fn capture_logs<F: FnOnce()>(f: F) -> String {
    let writer = SharedWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(writer.clone())
        .without_time()
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    let bytes = writer.0.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}

#[test]
fn parse_allowlist() {
    let content = "
# Known false positives
hash:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
detector:entropy
path:tests/**
path:*.example
";
    let al = Allowlist::parse(content);
    assert_eq!(al.credential_hashes.len(), 1);
    assert!(al.ignored_detectors.contains("entropy"));
    assert_eq!(al.ignored_paths.len(), 2);
}

#[test]
fn empty_allowlist_allows_nothing() {
    let al = Allowlist::empty();
    assert!(!al.is_hash_allowed("anything"));
}

#[test]
fn normalized_paths_still_match_globs() {
    let mut al = Allowlist::empty();
    al.ignored_paths.push("tests/**".into());
    assert!(al.is_path_ignored("./tests/fixtures/../fixtures/config.env"));
}

#[test]
fn is_allowed_checks_detector_and_path_rules_consistently() {
    let mut al = Allowlist::empty();
    al.ignored_detectors.insert("aws".into());
    al.ignored_paths.push("tests/**".into());

    let finding = VerifiedFinding {
        detector_id: "aws".into(),
        detector_name: "AWS".into(),
        service: "aws".into(),
        severity: Severity::High,
        credential_redacted: "***".into(),
        credential_hash: "".into(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some("src/main.rs".into()),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: Vec::new(),
        confidence: None,
    };
    assert!(al.is_allowed(&finding));

    let finding = VerifiedFinding {
        detector_id: "other".into(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some("tests/fixture.env".into()),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        ..finding
    };
    assert!(al.is_allowed(&finding));
}

#[test]
fn gitleaks_format_parse_compatibility() {
    let content = "hash:deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678\ndetector:aws-access-key\npath:**/*.test\n";
    let al = Allowlist::parse(content);
    assert_eq!(al.credential_hashes.len(), 1);
    assert!(al.ignored_detectors.contains("aws-access-key"));
    assert_eq!(al.ignored_paths.len(), 1);
}

#[test]
fn gitleaks_hash_suppression_behavior() {
    // Hardened API: callers pass the pre-hashed hex (matches scanner's
    // `credential_hash` field). Plaintext fallback was removed because it
    // encouraged accidentally committing real secrets in `.keyhogignore`.
    let entry_hash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    let other_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let content = format!("hash:{entry_hash}");
    let al = Allowlist::parse(&content);
    assert!(al.is_hash_allowed(entry_hash));
    assert!(!al.is_hash_allowed(other_hash));
}

#[test]
fn gitleaks_detector_ignore_by_id() {
    let content = "detector:generic-api-key";
    let al = Allowlist::parse(content);
    let finding = VerifiedFinding {
        detector_id: "generic-api-key".into(),
        detector_name: "Generic API Key".into(),
        service: "generic".into(),
        severity: Severity::High,
        credential_redacted: "***".into(),
        credential_hash: "".into(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some("any/path/file.rs".into()),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: Vec::new(),
        confidence: None,
    };
    assert!(al.is_allowed(&finding));

    let other_finding = VerifiedFinding {
        detector_id: "different-detector".into(),
        ..finding
    };
    assert!(!al.is_allowed(&other_finding));
}

#[test]
fn gitleaks_comment_lines_ignored() {
    let content = "
# This is a comment
hash:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
# Another comment
detector:test
";
    let al = Allowlist::parse(content);
    assert_eq!(al.credential_hashes.len(), 1);
    assert!(al.ignored_detectors.contains("test"));
}

#[test]
fn gitleaks_malformed_lines_warning_not_crash() {
    let logs = capture_logs(|| {
        let content = "
hash:invalid_hash
not_a_valid_line
random_text_here
detector:
hash:
path:
hash:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
";
        let al = Allowlist::parse(content);
        assert_eq!(al.credential_hashes.len(), 1);
    });
    assert!(logs.contains("invalid allowlist entry"));
    assert!(logs.contains("invalid hash allowlist entry"));
}

#[test]
fn gitleaks_windows_backslash_normalized() {
    let mut al = Allowlist::empty();
    al.ignored_paths.push("tests/**".into());
    assert!(al.is_path_ignored("tests\\fixtures\\config.env"));
    assert!(al.is_path_ignored(".\\tests\\fixtures\\test.txt"));
    assert!(!al.is_path_ignored("src\\main.rs"));
}

#[test]
fn gitleaks_hash_case_insensitive() {
    let lower = "hash:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    let upper = "hash:9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08";
    let mixed = "hash:9F86D081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    let al_lower = Allowlist::parse(lower);
    let al_upper = Allowlist::parse(upper);
    let al_mixed = Allowlist::parse(mixed);

    // Lookups must succeed regardless of how the hex was cased on either side
    // (allowlist file entry, lookup query). All three forms decode to the
    // same 32 bytes.
    let lookup_lower = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    let lookup_upper = "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08";
    assert!(al_lower.is_hash_allowed(lookup_lower));
    assert!(al_upper.is_hash_allowed(lookup_lower));
    assert!(al_mixed.is_hash_allowed(lookup_lower));
    assert!(al_lower.is_hash_allowed(lookup_upper));
}

#[test]
fn raw_hash_lookup_accepts_hex_hashes_directly() {
    let content = "hash:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    let al = Allowlist::parse(content);
    assert!(al.is_hash_allowed("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
    assert!(
        al.is_raw_hash_ignored("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
    );
}
