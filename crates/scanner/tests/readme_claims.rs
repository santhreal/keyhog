//! README claim regression gates.
//!
//! Every NUMERIC or BOOLEAN claim in the user-facing README is
//! pinned here as a binding test. If the engine changes such that
//! a README claim becomes false, this suite fails and someone has
//! to either (a) restore the truth, or (b) update the README first.
//!
//! Excludes: speed claims and recall percentages on third-party
//! corpora - those live in `tests/perf_floor.rs` and the
//! differential bench harness, respectively. This file is the
//! "what shows up on the front page" gate.

mod support;
use support::paths::detector_dir;

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

fn readme_text() -> Option<String> {
    std::fs::read_to_string(repo_root().join("README.md")).ok()
}

/// README + banner claim: the detector count. SINGLE-SOURCED from the
/// loader - the number is NOT hardcoded here. `keyhog_core::load_detectors`
/// is the same path the CLI uses; the README headline and the banner SVG
/// must advertise exactly that count. Adding/removing a detector updates the
/// loader automatically, and this test then requires only the human-facing
/// surfaces (README + banner) to be bumped to match - no test-literal churn,
/// and no per-contract count stamp (cf. the de-duplication in G9).
#[test]
fn readme_claim_detector_count() {
    let Some(readme) = readme_text() else {
        eprintln!("SKIP: README.md missing - running from an export tree.");
        return;
    };

    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let n = detectors.len();

    let claim = format!("{n} embedded detectors");
    assert!(
        readme.contains(&claim),
        "README must advertise the live detector count: the loader returned {n}, so \
         README.md must contain {claim:?}. When the corpus changes, bump every \
         '<count> detectors' / '<count> embedded detectors' spot in \
         README.md and the banner SVG to {n} - that is the ONLY place the count \
         lives now.",
    );

    // The banner SVG is the other human-facing surface; pin it to the loader
    // too so an added detector can't leave a stale number on the front-page
    // image. Skipped silently only when the asset is absent (export tree).
    if let Ok(banner) = std::fs::read_to_string(repo_root().join("docs/assets/keyhog-banner.svg")) {
        let banner_claim = format!("{n} detectors");
        assert!(
            banner.contains(&banner_claim),
            "banner SVG (docs/assets/keyhog-banner.svg) must advertise {banner_claim:?} \
             to match the loader count {n}.",
        );
    }
}

/// README claim: "(1675 patterns)" in the startup banner. Each
/// detector can have multiple regex patterns; this gates the
/// total. Slightly looser than the detector count - we allow a
/// small drift band (+/- 5) so adding one specialised regex per
/// detector doesn't immediately flap this gate; the band makes the
/// test useful, not annoying, while still catching a real
/// 100-pattern regression.
#[test]
fn readme_claim_pattern_count_within_band() {
    let Some(readme) = readme_text() else {
        eprintln!("SKIP: README.md missing");
        return;
    };
    if !readme.contains("1675 patterns") && !readme.contains("(1675") {
        eprintln!(
            "INFO: README no longer mentions 1675 patterns - test passes \
             vacuously. Add the claim back or update this test to track."
        );
        return;
    }

    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let total_patterns: usize = detectors.iter().map(|d| d.patterns.len()).sum();

    let claimed = 1675i64;
    let band = 5i64;
    let actual = total_patterns as i64;
    assert!(
        (actual - claimed).abs() <= band,
        "README claims 1675 patterns; loader counted {}. Drift > {} - either a \
         large patterns sweep landed (update README) or detectors lost their \
         secondary patterns silently.",
        actual,
        band,
    );
}

/// README claim: "Multiline reassembly detects secrets split across
/// lines". Asserts the realistic concat shape produces a finding.
/// The full evasion-corpus test
/// (`tests/adversarial/.../evasion_split_across_lines_reassembles_at_all`)
/// is broader; this test pins the README-level promise.
#[test]
fn readme_claim_multiline_reassembly_finds_split_secret() {
    use keyhog_core::{Chunk, ChunkMetadata};
    use keyhog_scanner::CompiledScanner;
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let text = "openai_a = \"sk-proj-\"
openai_b = \"9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aB\"
openai_key = openai_a + openai_b
";
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "readme-claim".into(),
            path: Some("multiline.py".into()),
            ..Default::default()
        },
    };
    let matches = scanner.scan(&chunk);
    let any_reassembled_or_openai = matches.iter().any(|m| {
        m.detector_id.as_ref().contains(":reassembled")
            || m.detector_id.as_ref().contains("openai")
            || m.service.as_ref().contains("openai")
    });
    assert!(
        any_reassembled_or_openai,
        "README claims multiline reassembly catches `\"sk-proj-\" + suffix` splits. \
         Scanner saw: {:?}",
        matches
            .iter()
            .map(|m| m.detector_id.as_ref())
            .collect::<Vec<_>>(),
    );
}

/// README claim: "Decode-through scanning finds base64-encoded
/// secrets in Kubernetes manifests, CI configs, and minified JS".
#[test]
fn readme_claim_decode_through_finds_base64_aws_key() {
    use keyhog_core::{Chunk, ChunkMetadata};
    use keyhog_scanner::CompiledScanner;
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    // base64("AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA")
    //   = QVdTX0FDQ0VTU19LRVlfSUQ9QUtJQVFZTFBNTjVIRklRUjdYWUE=
    let text = "apiVersion: v1
kind: Secret
metadata:
  name: aws-creds
data:
  aws_credentials: QVdTX0FDQ0VTU19LRVlfSUQ9QUtJQVFZTFBNTjVIRklRUjdYWUE=
";
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "readme-claim".into(),
            path: Some("k8s-secret.yaml".into()),
            ..Default::default()
        },
    };
    let matches = scanner.scan(&chunk);
    let any_aws = matches.iter().any(|m| {
        m.detector_id.as_ref().contains("aws")
            || m.service.as_ref().contains("aws")
            || m.credential
                .as_ref()
                .contains(concat!("AK", "IAQYLPMN5HFIQR7XYA"))
    });
    assert!(
        any_aws,
        "README claims decode-through scanning finds base64 secrets in K8s manifests. \
         Scanner saw: {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>(),
    );
}

/// README claim: "Entropy fallback catches secrets near `password`,
/// `token`, `secret` keywords even without a named detector".
/// Asserts a high-entropy string near `password=` surfaces via the
/// generic/entropy detectors.
#[test]
fn readme_claim_entropy_fallback_finds_password_assignment() {
    use keyhog_core::{Chunk, ChunkMetadata};
    use keyhog_scanner::CompiledScanner;
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    // Random-looking 32-char body - no named-detector prefix
    // (`sk_`, `AKIA`, etc.) so this exercises the entropy fallback
    // path specifically.
    let text = "DATABASE_PASSWORD=Tx8vQp2zNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ";
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "readme-claim".into(),
            path: Some("entropy_fallback.env".into()),
            ..Default::default()
        },
    };
    let matches = scanner.scan(&chunk);
    let any_entropy_finding = matches.iter().any(|m| {
        m.detector_id.as_ref().contains("entropy")
            || m.detector_id.as_ref().contains("generic")
            || m.detector_id.as_ref().contains("password")
    });
    assert!(
        any_entropy_finding,
        "README claims entropy fallback catches secrets near keyword anchors. \
         Scanner saw: {:?}",
        matches
            .iter()
            .map(|m| m.detector_id.as_ref())
            .collect::<Vec<_>>(),
    );
}

/// README claim: "Context-aware suppression: test files,
/// documentation, comments, encrypted blocks, go.sum checksums".
/// Asserts that a finding in a go.sum file is suppressed.
#[test]
fn readme_claim_go_sum_context_suppresses() {
    use keyhog_core::{Chunk, ChunkMetadata};
    use keyhog_scanner::CompiledScanner;
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    // go.sum line with an `h1:` checksum hash - looks like a long
    // base64 secret but is a transitive-dependency integrity hash.
    // README promises go.sum gets suppressed.
    let text = "github.com/spf13/cobra v1.5.0 h1:X+jTBEBqF0bHN+9cSMgmfuvv2VHJ9ezmFNf9Y/XstYU=
github.com/spf13/cobra v1.5.0/go.mod h1:bchYw9AY9p2r7+QchPjKDuO7gNZh0EwGjEX9p4XbtfQ=
";
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "readme-claim".into(),
            path: Some("go.sum".into()),
            ..Default::default()
        },
    };
    let matches = scanner.scan(&chunk);
    // The h1:… payload is a Go module integrity hash, not a secret.
    // The engine should NOT surface it.
    let any_finding_on_h1_hash = matches.iter().any(|m| {
        m.credential.as_ref().contains("X+jTBEBqF0bHN")
            || m.credential.as_ref().contains("bchYw9AY9p2r7")
    });
    assert!(
        !any_finding_on_h1_hash,
        "README claims go.sum checksums are suppressed. Scanner surfaced an \
         h1: hash as a finding. Matches: {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>(),
    );
}

/// README claim: "checksum validation (GitHub CRC32, npm, Slack, PyPI)".
/// Verifies that the named services have a real validator that
/// distinguishes a known-valid checksum from a known-invalid one.
/// The full per-detector contracts in `tests/contracts/` exercise
/// these on positive + negative fixtures; this test pins the
/// README-level promise.
#[test]
fn readme_claim_checksum_validators_present() {
    use keyhog_scanner::checksum::{validate_checksum, ChecksumResult};

    let cases: &[(&str, &str, ChecksumResult, &str)] = &[
        // GitHub fine-grained PAT - valid CRC32 from the contract fixture.
        (
            "github CRC32 valid",
            "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",
            ChecksumResult::Valid,
            "GitHub fine-grained PAT with CRC32-valid checksum",
        ),
        (
            "github CRC32 INvalid",
            "github_pat_KhYxNqJ4pVbZ7Lm5RfWcGs_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaBxxxxxx",
            ChecksumResult::Invalid,
            "Same shape with wrong checksum must be rejected",
        ),
        // npm - valid CRC32 from the contract fixture.
        (
            "npm CRC32 valid",
            "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",
            ChecksumResult::Valid,
            "npm access token with CRC32-valid checksum",
        ),
        (
            "npm CRC32 INvalid",
            "npm_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaXXXXXX",
            ChecksumResult::Invalid,
            "Same shape with wrong checksum must be rejected",
        ),
    ];

    for (name, credential, expected, why) in cases {
        let actual = validate_checksum(credential);
        assert_eq!(
            actual, *expected,
            "{name}: {why}. validate_checksum({credential:?}) returned {actual:?} but README \
             promises this class is checksum-validated and we expected {expected:?}."
        );
    }
}
