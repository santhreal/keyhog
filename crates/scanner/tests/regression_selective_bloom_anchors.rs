use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::testing::BigramBloom;
use keyhog_scanner::{BigramPrefilterState, CompiledScanner, ScanBackend};

fn bloom(literals: &[&str]) -> BigramBloom {
    let literals: Vec<String> = literals
        .iter()
        .map(|literal| (*literal).to_owned())
        .collect();
    BigramBloom::from_literal_prefixes(&literals)
}

fn chunk(index: usize, data: String) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            source_type: "selective-bloom-regression".into(),
            path: Some(format!("generated/selective-bloom-{index}.txt").into()),
            ..Default::default()
        },
    }
}

fn padded_chunk(index: usize, credential: &str) -> Chunk {
    chunk(
        index,
        format!("{}{}{}", "!".repeat(29), credential, "~".repeat(41)),
    )
}

fn selective_alternation_scanner() -> CompiledScanner {
    let detector = DetectorSpec {
        tests: Vec::new(),
        id: "selective-bloom-alternatives".into(),
        name: "Selective Bloom Alternatives".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            // The first two alternatives have different direct mandatory literals.
            // The third has no literal at all and therefore exercises the explicit
            // always-admit/no-hit lane rather than borrowing another branch's anchor.
            regex: concat!(
                r"ALPHA_[A-Za-z0-9]{24}",
                r"|OMEGA_[A-Za-z0-9]{24}",
                r"|[A-Z]{4}[0-9]{4}[a-z]{4}[0-9]{4}[A-Z]{4}[0-9]{4}"
            )
            .into(),
            ..Default::default()
        }],
        companions: Vec::new(),
        verify: None,
        keywords: Vec::new(),
        min_confidence: Some(0.0),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };

    CompiledScanner::compile(vec![detector]).expect("compile selective-alternation detector")
}

fn deterministic_token(mut state: u64, len: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut token = String::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        token.push(ALPHABET[(state as usize) % ALPHABET.len()] as char);
    }
    token
}

#[test]
fn full_literal_is_admitted_and_unrelated_bytes_are_rejected() {
    let filter = bloom(&["ghp_"]);

    assert!(
        filter.maybe_overlaps(b"prefix=ghp_7b3e5d8c1a9f4e2b"),
        "a chunk containing the complete mandatory literal must be admitted"
    );
    assert!(
        !filter.maybe_overlaps(b"completely unrelated source text"),
        "a healthy selective filter must reject a chunk with no selected ngram"
    );
    assert_eq!(filter.status().state, BigramPrefilterState::Healthy);
}

#[test]
fn production_corpus_boundary_is_exactly_sixty_four_bytes() {
    let filter = bloom(&["ANCHOR_1234"]);
    let below = vec![b'z'; 63];
    let boundary = vec![b'z'; 64];
    let inputs = [below.as_slice(), boundary.as_slice()];

    let unrestricted = filter.corpus_status("63-and-64-unrestricted", inputs);
    assert_eq!(unrestricted.input_count, 2);
    assert_eq!(unrestricted.eligible_inputs, 2);
    assert_eq!(unrestricted.rejected_inputs, 2);

    let production = filter.production_corpus_status("63-and-64-production", inputs);
    assert_eq!(production.input_count, 2);
    assert_eq!(
        production.eligible_inputs, 1,
        "only the 64-byte input is eligible"
    );
    assert_eq!(
        production.rejected_inputs, 1,
        "the eligible 64-byte miss is rejected"
    );
    assert_eq!(production.rejection_basis_points, 5_000);
}

#[test]
fn ascii_case_insensitive_variants_of_the_selected_ngram_are_admitted() {
    let filter = bloom(&["Ab9_"]);

    for candidate in [&b"Ab9_"[..], &b"ab9_"[..], &b"AB9_"[..], &b"aB9_"[..]] {
        assert!(
            filter.maybe_overlaps(candidate),
            "ASCII-case variant {candidate:?} must remain reachable"
        );
    }
    assert!(
        !filter.maybe_overlaps(b"ab8_"),
        "a non-case near miss must reject"
    );
}

#[test]
fn utf8_literal_bytes_admit_the_literal_but_reject_a_near_miss() {
    // Both code points occupy exactly four UTF-8 bytes and differ only in the
    // final byte, so the assertion observes byte-exact ngram membership.
    let filter = bloom(&["🔑"]);

    assert!(filter.maybe_overlaps("🔑".as_bytes()));
    assert!(
        !filter.maybe_overlaps("🔒".as_bytes()),
        "a neighboring UTF-8 scalar must not alias the selected literal bytes"
    );
}

#[test]
fn an_empty_unanchorable_alternative_forces_fail_open() {
    let filter = bloom(&["SAFE_ANCHOR", ""]);

    assert_eq!(
        filter.status().state,
        BigramPrefilterState::Invalid,
        "an unanchorable alternative cannot support a sound rejection proof"
    );
    assert!(
        filter.maybe_overlaps(b"bytes unrelated to SAFE_ANCHOR"),
        "an unanchorable alternative must fail open rather than reject"
    );
}

#[test]
fn every_adversarial_top_level_alternative_remains_reachable() {
    let scanner = selective_alternation_scanner();
    let credentials = [
        format!("ALPHA_{}", deterministic_token(0xA11C_E001, 24)),
        format!("OMEGA_{}", deterministic_token(0x0A4E_6A02, 24)),
        "QWER1234tyui5678ASDF9012".to_owned(),
    ];
    let chunks: Vec<Chunk> = credentials
        .iter()
        .enumerate()
        .map(|(index, credential)| padded_chunk(index, credential))
        .collect();

    scanner.clear_fragment_cache();
    let findings = scanner
        .scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback)
        .expect("scan every top-level alternative");

    for (index, credential) in credentials.iter().enumerate() {
        assert!(
            findings[index].iter().any(|finding| {
                finding.detector_id.as_ref() == "selective-bloom-alternatives"
                    && finding.credential.as_ref() == credential
            }),
            "alternative {index} was unreachable for credential {credential:?}; findings={:?}",
            findings[index]
        );
    }
}

#[test]
fn enabled_and_bypassed_scans_are_exactly_equal_on_generated_chunks() {
    let scanner = selective_alternation_scanner();
    let mut chunks = Vec::new();
    let mut expected_credentials: Vec<Option<String>> = Vec::new();

    for index in 0..48usize {
        let credential = match index % 4 {
            0 => Some(format!(
                "ALPHA_{}",
                deterministic_token(0x51EC_7100_u64.wrapping_add(index as u64), 24)
            )),
            1 => Some(format!(
                "OMEGA_{}",
                deterministic_token(0x51EC_7200_u64.wrapping_add(index as u64), 24)
            )),
            2 => Some(format!(
                "{}{:04}{}{:04}{}{:04}",
                "QWER",
                1000 + index,
                "tyui",
                2000 + index,
                "ASDF",
                3000 + index
            )),
            _ => None,
        };

        let generated = match credential.as_deref() {
            Some(value) => padded_chunk(index, value),
            None => chunk(
                index,
                format!(
                    "{}negative-case-{index:04}-contains-letters-and-digits-but-no-credential{}",
                    "!".repeat(17),
                    "~".repeat(31)
                ),
            ),
        };
        chunks.push(generated);
        expected_credentials.push(credential);
    }

    scanner.clear_fragment_cache();
    let enabled = scanner
        .scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback)
        .expect("scan generated corpus with the production Bloom gate");
    scanner.clear_fragment_cache();
    let bypassed = scanner
        .scan_chunks_with_backend_bypassing_bigram_for_diagnostics(
            &chunks,
            ScanBackend::CpuFallback,
        )
        .expect("scan generated corpus with the Bloom gate bypassed");

    assert_eq!(
        enabled, bypassed,
        "the selective Bloom gate changed finding identity, location, or scoring"
    );

    for (index, expected) in expected_credentials.iter().enumerate() {
        match expected {
            Some(credential) => assert!(
                enabled[index]
                    .iter()
                    .any(|finding| finding.credential.as_ref() == credential),
                "generated positive {index} did not exercise a finding; findings={:?}",
                enabled[index]
            ),
            None => assert!(
                enabled[index].is_empty(),
                "generated negative {index} unexpectedly matched: {:?}",
                enabled[index]
            ),
        }
    }
}
