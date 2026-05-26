//! Regression gate for #16: a single secret on a single line of a .env
//! file must not surface as a primary location PLUS a duplicate additional
//! location at an offset past EOF on the source file.
//!
//! Root cause (two compounding bugs):
//!   1. preprocess_multiline appended `joined_text` to `final_text` even
//!      when no line-joining actually happened (single-line input ending
//!      in `\n` → `joined_text` lost the trailing newline → `joined_text
//!      != text` was true → eager append). Fix in preprocessor.rs.
//!   2. The structured-format preprocessor (`structured/mod.rs::preprocess`)
//!      detects `.env` / `kind: Secret` / docker-compose / .tfstate /
//!      .ipynb files, extracts (key, value) pairs, and appends them as
//!      synthetic `"key: value"` lines so detectors that need keyword
//!      context can still match. The bootstrap-token regex matches both
//!      the original `KEY=value` AND the synthetic `KEY: value`. Pre-fix,
//!      dedup kept the original as primary and added the synthetic as
//!      `additional_locations[0]` with `offset = original_end + synth_offset`
//!      — which lands PAST the source file's EOF. Fix in core/dedup.rs:
//!      drop additional_locations that share (file, line, source, commit)
//!      with the primary.
//!
//! These tests assert:
//!   - The dedup output has exactly one DedupedMatch per (detector, credential).
//!   - That DedupedMatch's additional_locations does NOT contain a same-
//!     (file, line) duplicate of the primary.
//!   - Every reported offset is inside the source file (< file_len).

use keyhog_core::{dedup_matches, Chunk, ChunkMetadata, DedupScope};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

fn make_chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

#[test]
fn single_line_k8s_bootstrap_token_dedups_to_one_finding_no_phantom_offsets() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let text = "KUBERNETES_BOOTSTRAP_TOKEN=k3m9zq.4r8w2nq3p6vt5b1z\n";
    let file_len = text.len();
    let chunk = make_chunk(text, "k8s-single-line.env");

    let results = scanner.scan_coalesced(std::slice::from_ref(&chunk));
    let raw: Vec<_> = results.into_iter().flatten().collect();
    let deduped = dedup_matches(raw, &DedupScope::Credential);

    let bootstrap: Vec<_> = deduped
        .iter()
        .filter(|m| m.detector_id.as_ref() == "kubernetes-bootstrap-token")
        .collect();
    assert_eq!(
        bootstrap.len(),
        1,
        "exactly one DedupedMatch for kubernetes-bootstrap-token. Got: {:?}",
        deduped
            .iter()
            .map(|m| (m.detector_id.as_ref().to_string(), m.primary_location.offset))
            .collect::<Vec<_>>(),
    );

    let m = bootstrap[0];
    assert!(
        m.primary_location.offset < file_len,
        "primary offset {} must be inside the file (len {})",
        m.primary_location.offset,
        file_len,
    );
    // Pre-fix: additional_locations.len() == 1, with offset == 80 in a
    // 51-byte file (the structured-preprocessor synthetic-line alias of
    // the same finding). Post-fix: same (file, line) → suppressed.
    for loc in &m.additional_locations {
        assert!(
            loc.offset < file_len,
            "additional location offset {} must be inside the file (len {})",
            loc.offset,
            file_len,
        );
        let same_line = loc.line == m.primary_location.line;
        let same_file = loc.file_path == m.primary_location.file_path;
        assert!(
            !(same_line && same_file),
            "additional_locations must not include same-(file, line) duplicate \
             of primary. Primary line={:?} file={:?}; duplicate line={:?} file={:?}",
            m.primary_location.line,
            m.primary_location.file_path,
            loc.line,
            loc.file_path,
        );
    }
}

#[test]
fn single_line_env_secret_no_offsets_past_eof_across_dedup() {
    // Broader gate: ANY detector that fires on a single-line .env input
    // must produce a DedupedMatch whose primary and additional_locations
    // all carry offsets within the source file. The structured-preprocessor
    // appends synthetic lines past EOF on every value it extracts; if a
    // detector's regex matches the synthetic alias, the offset lands at
    // ~file_len + small_delta — outside any reader that opens the file
    // and seeks to it. #16 regression.
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let text = "GITHUB_TOKEN=ghp_thiscanbeplausiblylongenoughtoactuallyfire1234\n";
    let file_len = text.len();
    let chunk = make_chunk(text, "github-single-line.env");

    let results = scanner.scan_coalesced(std::slice::from_ref(&chunk));
    let raw: Vec<_> = results.into_iter().flatten().collect();
    let deduped = dedup_matches(raw, &DedupScope::Credential);
    for m in &deduped {
        assert!(
            m.primary_location.offset < file_len,
            "detector {} primary offset {} past file len {}",
            m.detector_id.as_ref(),
            m.primary_location.offset,
            file_len,
        );
        for loc in &m.additional_locations {
            assert!(
                loc.offset < file_len,
                "detector {} additional offset {} past file len {}",
                m.detector_id.as_ref(),
                loc.offset,
                file_len,
            );
        }
    }
}

#[test]
fn dedup_suppresses_same_file_same_line_additional_location() {
    // Direct unit test of the dedup change: synthesize two RawMatches
    // for the same detector + credential + (file, line) and verify dedup
    // produces ONE DedupedMatch with zero additional_locations.
    use keyhog_core::{MatchLocation, RawMatch, Severity};
    use std::collections::HashMap;
    use std::sync::Arc;
    let primary = RawMatch {
        credential_hash: "h".to_string(),
        detector_id: Arc::from("test-detector"),
        detector_name: Arc::from("Test Detector"),
        service: Arc::from("test"),
        severity: Severity::High,
        credential: Arc::from("creds"),
        companions: HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("/tmp/test.env")),
            line: Some(1),
            offset: 27,
            commit: None,
            author: None,
            date: None,
        },
        entropy: Some(4.5),
        confidence: Some(0.9),
    };
    let alias = RawMatch {
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("/tmp/test.env")),
            line: Some(1),
            offset: 80, // past EOF — synthetic preprocessor alias
            commit: None,
            author: None,
            date: None,
        },
        ..primary.clone()
    };
    let deduped = dedup_matches(vec![primary, alias], &DedupScope::Credential);
    assert_eq!(deduped.len(), 1);
    assert!(
        deduped[0].additional_locations.is_empty(),
        "same-(file, line) alias must not appear in additional_locations; got {:?}",
        deduped[0].additional_locations,
    );
}
