use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use proptest::prelude::*;
use std::sync::LazyLock;

const PINNED_ELASTICSEARCH_SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../benchmarks/corpora/creddata/CredData/data/387016a6/test/src/tool/setting/eedec1c5.java"
));
const LIVE_POSITIVE: &str = "AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\n";
const LIVE_CREDENTIAL: &str = "AKIAQYLPMN5HFIQR7XYA";

static SCANNER: LazyLock<CompiledScanner> = LazyLock::new(|| {
    CompiledScanner::compile(keyhog_core::embedded_detector_specs().to_vec())
        .expect("embedded detector corpus compiles")
});

fn chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "detector-policy-utf8-regression".into(),
            path: Some("eedec1c5.java".into()),
            ..Default::default()
        },
    }
}

fn scan_simd(text: &str) -> Vec<RawMatch> {
    let mut per_chunk = SCANNER
        .scan_chunks_with_backend(&[chunk(text)], ScanBackend::SimdCpu)
        .expect("SIMD scan returns normally");
    assert_eq!(per_chunk.len(), 1, "one input must return one result slot");
    per_chunk.pop().expect("single result slot")
}

#[test]
fn pinned_creddata_elasticsearch_simd_scan_has_exact_results_and_host_stays_live() {
    // This exact CredData source made a worker slice past the source end and
    // abort the host with exit 134, so exercise the production SIMD entry point
    // and then reuse the same scanner to prove the worker remains live.
    let findings = scan_simd(PINNED_ELASTICSEARCH_SOURCE);
    let mut actual = findings
        .iter()
        .map(|finding| {
            (
                finding.detector_id.as_ref(),
                finding.location.offset,
                finding.location.line,
            )
        })
        .collect::<Vec<_>>();
    actual.sort_unstable_by_key(|(_, offset, _)| *offset);
    assert_eq!(
        actual,
        vec![
            ("generic-password", 1441, Some(45)),
            ("generic-password", 3073, Some(86)),
            ("generic-password", 3395, Some(95)),
            ("generic-password", 3734, Some(104)),
            ("generic-password", 4101, Some(114)),
            ("generic-password", 4446, Some(123)),
            ("generic-password", 4834, Some(132)),
            ("generic-password", 5160, Some(141)),
            ("generic-password", 5542, Some(150)),
            ("generic-password", 6097, Some(163)),
            ("generic-password", 6454, Some(172)),
            ("generic-password", 6819, Some(181)),
            ("generic-password", 7163, Some(190)),
            ("generic-password", 7553, Some(199)),
            ("generic-password", 7944, Some(208)),
            ("generic-password", 8446, Some(219)),
            ("generic-password", 9116, Some(234)),
        ]
    );

    let followup = scan_simd(LIVE_POSITIVE);
    assert_eq!(followup.len(), 1);
    assert_eq!(followup[0].detector_id.as_ref(), "aws-access-key");
    assert_eq!(followup[0].credential.as_ref(), LIVE_CREDENTIAL);
    assert_eq!(
        followup[0].location.offset,
        LIVE_POSITIVE.find(LIVE_CREDENTIAL).expect("credential offset")
    );
}

#[cfg(feature = "multiline")]
#[test]
fn pinned_appended_mapping_resolves_the_exact_original_credential_span() {
    const CREDENTIAL: &str = "tvggidtsquylrrxc";
    let config = crate::multiline::MultilineConfig::default();
    let cache = crate::fragment_cache::FragmentCache::new(1024);
    let preprocessed =
        crate::multiline::preprocess_multiline(PINNED_ELASTICSEARCH_SOURCE, &config, &cache);
    let appended_start = preprocessed
        .original_end
        .checked_add(1)
        .expect("appended offset");
    let appended = preprocessed
        .text
        .get(appended_start..)
        .expect("appended preprocessing region");
    let candidate_start = appended_start
        + appended
            .find(CREDENTIAL)
            .expect("credential in appended preprocessing region");
    let source_start = preprocessed.source_offset_for_match(
        PINNED_ELASTICSEARCH_SOURCE,
        candidate_start,
        CREDENTIAL,
    );
    let expected_start = PINNED_ELASTICSEARCH_SOURCE
        .find(CREDENTIAL)
        .expect("credential in original source");

    // Empty joined lines used to advance the synthesized text but not its
    // mapping cursor, eventually turning this exact span into source.len() - 1.
    assert_eq!(source_start, expected_start);
    assert_eq!(
        PINNED_ELASTICSEARCH_SOURCE.get(source_start..source_start + CREDENTIAL.len()),
        Some(CREDENTIAL)
    );
}

#[test]
fn multibyte_candidates_at_requested_window_boundaries_keep_whole_byte_spans() {
    let data = "api_key=\"é🔑尾\";";
    let value = "é🔑尾";
    let value_start = data.find(value).expect("multibyte value");
    let value_end = value_start + value.len();
    let requested_end = value_start + "é".len() + 1;
    assert!(!data.is_char_boundary(requested_end));

    let rounded_end = crate::engine::window_end_offset(data, 0, requested_end);
    assert_eq!(rounded_end, value_start + "é🔑".len());
    let window = data.get(..rounded_end).expect("UTF-8-aligned window");
    let window_span = crate::detector_execution_policy::whole_assignment_value(
        window,
        value_start + 1,
        requested_end,
    );
    assert_eq!(window_span.start, value_start);
    assert_eq!(window_span.end, rounded_end);
    assert_eq!(window_span.as_str(window), "é🔑");

    // Every byte position inside a scalar is a possible malformed mapped
    // boundary; the detector still owns the complete quoted value byte span.
    for byte_offset in value_start..value_end {
        let span = crate::detector_execution_policy::whole_assignment_value(
            data,
            byte_offset,
            byte_offset + 1,
        );
        assert_eq!(span.start, value_start);
        assert_eq!(span.end, value_end);
        assert_eq!(span.as_str(data), value);
    }
}

#[test]
fn shortest_and_maximum_scan_window_sources_have_canonical_spans() {
    let empty = crate::detector_execution_policy::whole_assignment_value(
        "",
        usize::MAX,
        usize::MAX,
    );
    assert_eq!((empty.start, empty.end, empty.covered_end), (0, 0, 0));
    assert_eq!(empty.as_str(""), "");

    let value = "é🔑Z";
    let prefix_len = crate::types::MAX_SCAN_CHUNK_BYTES - value.len();
    let mut longest = String::with_capacity(crate::types::MAX_SCAN_CHUNK_BYTES);
    longest.extend(std::iter::repeat_n(' ', prefix_len));
    longest.push_str(value);
    assert_eq!(longest.len(), crate::types::MAX_SCAN_CHUNK_BYTES);

    // Start one byte into `é` and end beyond the allocation: canonicalization
    // must recover the full final scalar sequence without changing byte offsets
    // for already-valid detector matches.
    let span = crate::detector_execution_policy::whole_assignment_value(
        &longest,
        prefix_len + 1,
        usize::MAX,
    );
    assert_eq!(span.start, prefix_len);
    assert_eq!(span.end, longest.len());
    assert_eq!(span.as_str(&longest), value);
}

#[test]
fn malformed_byte_source_twin_returns_one_finding_and_allows_followup_scan() {
    let mut raw = b"invalid-prefix=".to_vec();
    raw.extend_from_slice(&[0xf0, 0x28, 0x8c, 0x28]);
    raw.extend_from_slice(b"\nAWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\n");
    let decoded = String::from_utf8_lossy(&raw).into_owned();
    assert!(decoded.contains('\u{fffd}'));

    // Chunk data is UTF-8 by contract, so source adapters use this same lossy
    // conversion for malformed bytes; it must neither drop the valid neighbor
    // nor poison the scanner instance used by the following scan.
    let findings = scan_simd(&decoded);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].detector_id.as_ref(), "aws-access-key");
    assert_eq!(findings[0].credential.as_ref(), LIVE_CREDENTIAL);
    assert_eq!(
        findings[0].location.offset,
        decoded.find(LIVE_CREDENTIAL).expect("credential offset")
    );

    let followup = scan_simd(LIVE_POSITIVE);
    assert_eq!(followup.len(), 1);
    assert_eq!(followup[0].credential.as_ref(), LIVE_CREDENTIAL);
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 10_240,
        max_shrink_iters: 512,
        ..ProptestConfig::default()
    })]

    /// Arbitrary Unicode plus wholly arbitrary byte offsets must always produce
    /// an in-bounds UTF-8 span. Volume matters because only continuation-byte
    /// offsets exercise the former abort path.
    #[test]
    fn arbitrary_unicode_byte_offsets_are_canonical(
        chars in proptest::collection::vec(any::<char>(), 0..129),
        candidate_start in any::<usize>(),
        candidate_end in any::<usize>(),
    ) {
        let data = chars.into_iter().collect::<String>();
        let span = crate::detector_execution_policy::whole_assignment_value(
            &data,
            candidate_start,
            candidate_end,
        );

        prop_assert!(span.start <= span.end);
        prop_assert!(span.end <= data.len());
        prop_assert!(span.end <= span.covered_end);
        prop_assert!(span.covered_end <= data.len());
        prop_assert!(data.is_char_boundary(span.start));
        prop_assert!(data.is_char_boundary(span.end));
        prop_assert!(data.is_char_boundary(span.covered_end));
        let bytes = data
            .as_bytes()
            .get(span.start..span.end)
            .expect("canonical byte span");
        prop_assert_eq!(span.as_str(&data).as_bytes(), bytes);
    }
}
