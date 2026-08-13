//! Coverage for the encoded-blob DISCOVERY primitives (#177): the candidate
//! predicate and the `find_*_strings` scanners that locate embedded base64/hex
//! runs in free text (the front door of the decode-and-rescan pipeline).

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::decode::{
    base64_decode, find_base64_strings, find_hex_strings, hex_decode, is_base64_candidate_byte,
};
use keyhog_scanner::testing::decode_admission_sketch_with_custom_unknown;
use keyhog_scanner::{CompiledScanner, ScanBackend};

#[test]
fn base64_candidate_byte_accepts_the_full_alphabet_and_rejects_others() {
    // Standard + URL-safe alphabet + padding.
    for b in [
        b'A', b'Z', b'a', b'z', b'0', b'9', b'+', b'/', b'=', b'-', b'_',
    ] {
        assert!(
            is_base64_candidate_byte(b),
            "{} must be a candidate",
            b as char
        );
    }
    // Clear non-alphabet bytes.
    for b in [b' ', b'!', b'.', b'\n', b'#', b'@', b':', b'"'] {
        assert!(
            !is_base64_candidate_byte(b),
            "{} must NOT be a candidate",
            b as char
        );
    }
}

#[test]
fn find_base64_strings_extracts_the_value_of_an_assignment() {
    // `find_base64_strings` runs STRUCTURAL value extraction, not naive run
    // finding: it pulls the base64 VALUE out of a `key=value` assignment. So
    // `token=aGVsbG8=` yields the payload `aGVsbG8=` (→ "hello"), not the merged
    // `token=aGVsbG8=` run.
    let found = find_base64_strings("token=aGVsbG8= end", 8);
    assert!(
        found
            .iter()
            .any(|e| base64_decode(&e.value).ok().as_deref() == Some(&b"hello"[..])),
        "expected the assignment value to decode to `hello`, got: {:?}",
        found.iter().map(|e| &e.value).collect::<Vec<_>>()
    );
}

#[test]
fn find_base64_strings_honors_the_min_length_floor() {
    // "YWI=" decodes to "ab" (a 4-char base64 run). With a high floor it must
    // not be reported.
    let short = find_base64_strings("x YWI= y", 32);
    assert!(
        !short
            .iter()
            .any(|e| base64_decode(&e.value).ok().as_deref() == Some(&b"ab"[..])),
        "a 4-char run must be filtered out by min_length=32"
    );
}

#[test]
fn find_hex_strings_locates_an_embedded_token_that_round_trips() {
    // 48656c6c6f = "Hello".
    let text = "sha=48656c6c6f;";
    let found = find_hex_strings(text, 8);
    assert!(
        found
            .iter()
            .any(|e| hex_decode(&e.value).ok().as_deref() == Some(&b"Hello"[..])),
        "expected a discovered hex run decoding to `Hello`, got: {:?}",
        found.iter().map(|e| &e.value).collect::<Vec<_>>()
    );
}

#[test]
fn find_strings_return_nothing_for_text_without_encoded_runs() {
    assert!(find_base64_strings("just some plain english words here", 16).is_empty());
    assert!(find_hex_strings("no hex digits in this sentence!!", 16).is_empty());
}

fn ordinary_assignment_chunk(bytes: usize, source_type: &'static str) -> Chunk {
    let seed = "ordinary source\nconst ordinary_value = 1234567890;\n";
    let mut text = seed.repeat(bytes.div_ceil(seed.len()));
    text.truncate(bytes);
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: source_type.into(),
            path: Some("ordinary.txt".into()),
            ..ChunkMetadata::default()
        },
    }
}

/// WHY: repeated ordinary assignments must not enter every decoder merely
/// because the chunk contains printable source text.
#[test]
fn ordinary_assignment_corpus_has_no_builtin_decode_candidates() {
    let chunk = ordinary_assignment_chunk(100 * 1024, "filesystem");

    let sketch = decode_admission_sketch_with_custom_unknown(&chunk);
    assert_eq!(
        sketch.kind_mask(),
        0,
        "built-in decoders admitted ordinary assignment text"
    );
    assert!(sketch.has_unknown(), "custom decoder must remain fail-open");
}

/// WHY: a negative admission proof must prevent decoder output, not merely
/// prevent findings after a full rescan. The decode pipeline may execute
/// (it measures admission per-decoder, not per-pipeline-invocation), but
/// ordinary assignment text must produce zero decoded children.
#[test]
fn ordinary_assignment_corpus_skips_decode_generation() {
    let scanner = CompiledScanner::compile(keyhog_core::embedded_detector_specs().to_vec())
        .expect("compile embedded detector corpus");
    let chunks = [
        ordinary_assignment_chunk(100 * 1024, "filesystem"),
        ordinary_assignment_chunk(1024 * 1024, "filesystem/windowed"),
    ];
    let runtime = keyhog_profile::Runtime::new();
    runtime.scope(|| {
        let findings = scanner
            .scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback)
            .expect("ordinary assignment scans succeed");
        assert!(
            findings.iter().all(Vec::is_empty),
            "ordinary assignment text produced findings: {findings:?}"
        );
    });
}
