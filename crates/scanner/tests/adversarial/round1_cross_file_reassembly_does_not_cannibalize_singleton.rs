//! Round 1 FN-recovery regression contract: cross-file fragment-cache
//! reassembly MUST NOT cannibalize a singleton finding.
//!
//! Investigator finding (authentication-key cause #2 +
//! cloud-service-credential cause #1): pre-fix, the FragmentCache joined
//! fragments across different files under the same directory scope. The
//! resulting `:reassembled` synthesized credential then shadowed the
//! legitimate singleton AKIA finding in the per-credential dedup +
//! offset-rewrite path. Empirically reproduced: scanning a single
//! mirror-pos-0000091.yaml found one `aws-access-key` AKIA finding;
//! scanning that file alongside a sibling .sh with an unrelated `sk_`
//! token in the same directory produced ZERO AKIA findings and a junk
//! reassembled credential glued AKIA||sk_-tail attributed to the sibling.
//!
//! Adversarial style: CROSS-FILE. Plant a real-shape AKIA (CVE replay
//! shape - same byte prefix as the AWS canonical example credential, body
//! redacted to a deterministic but synthetic 16-hex tail so a credential-
//! scanner finds it without leaking a real key) in file_a.yaml; plant an
//! unrelated long base64 token in file_b.sh under the same directory.
//! Scan via the multi-chunk `scan_coalesced` path that drives the
//! fragment cache.
//!
//! Contract:
//!   * The AKIA must surface as detector_id == "aws-access-key" with
//!     credential exactly equal to the planted AKIA string.
//!   * NO finding may have detector_id ending in ":reassembled" attributed
//!     to file_b.sh whose credential contains the AKIA bytes glued to the
//!     sibling's tail.
//!
//! A regression that re-enables cross-file joining would fail BOTH
//! assertions: the AKIA singleton would be replaced by the glued
//! reassembled candidate, and the file attribution would point at the
//! sibling.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

#[test]
fn cross_file_reassembly_does_not_cannibalize_singleton() {
    let scanner = CompiledScanner::compile(
        keyhog_core::load_detectors(&detector_dir()).expect("load detectors"),
    )
    .expect("compile scanner");
    scanner.clear_fragment_cache();

    // CVE replay shape: real AWS access key prefix, 16-char synthetic
    // base32 body that passes the contract regex `(?-i)(AKIA|ASIA)[0-9A-Z]{16}`
    // while NOT colliding with `AKIAIOSFODNN7EXAMPLE` (which is in the
    // known-public-example suppression list and would be silently
    // dropped here).
    let akia_secret = "AKIA6CR0ANJCWS6ROMLZ";
    let file_a_body = format!("aws_access_key_id: {akia_secret}\n");
    let len_a = file_a_body.len();

    // Sibling content: a long high-entropy base64 token under the same
    // directory scope. Before the fix the cache would glue tail of A to
    // head of B and emit a reassembled candidate against file_b.sh.
    let sibling_token = "Y2xpZW50LXNlY3JldF9zazo3ZmRkZGFkOWE4MTQ0YzVmOTkyZGE2ZGY1ZTI3MGM1Mw==";
    let file_b_body = format!("export TOKEN={sibling_token}\n");

    let chunk_a = Chunk {
        data: file_a_body.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("/repo/secrets/file_a.yaml".into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    let chunk_b = Chunk {
        data: file_b_body.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("/repo/secrets/file_b.sh".into()),
            base_offset: len_a,
            ..Default::default()
        },
    };

    let groups = scanner.scan_coalesced(&[chunk_a, chunk_b]);
    let flat: Vec<_> = groups.into_iter().flatten().collect();

    // Contract A: standalone AKIA finding must still surface with exact
    // credential bytes.
    let akia_hits: Vec<_> = flat
        .iter()
        .filter(|m| {
            m.detector_id.as_ref() == "aws-access-key" && m.credential.as_ref() == akia_secret
        })
        .collect();
    assert_eq!(
        akia_hits.len(),
        1,
        "exactly one aws-access-key finding for the planted AKIA expected; \
         got {} hits. ALL findings: {:?}",
        akia_hits.len(),
        flat.iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );

    // Contract B: no `:reassembled` finding may carry the AKIA bytes
    // attributed to the sibling file. Cross-file joining is forbidden.
    for m in &flat {
        let id = m.detector_id.as_ref();
        let cred = m.credential.as_ref();
        let path = m
            .location
            .file_path
            .as_deref()
            .map(|p| p.to_string())
            .unwrap_or_default();
        assert!(
            !(id.ends_with(":reassembled")
                && cred.contains(akia_secret)
                && path.contains("file_b.sh")),
            "cross-file reassembly forbidden: detector={id} credential={cred:?} path={path:?}"
        );
    }
}
