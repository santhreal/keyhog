//! Regression coverage for KH-1239: built-in decoders used to materialize their
//! complete `Vec<Chunk>` before the pipeline enforced its shared 1,000-chunk / 64
//! MiB budget. Adversarial fan-out could therefore allocate far past the budget,
//! and wrapper decoders could lose source attribution when output was cut later.

use keyhog_core::{Chunk, ChunkMetadata, SensitiveString};
use keyhog_scanner::decode::{try_register_decoder, DecodeOutputSink, Decoder};
use keyhog_scanner::telemetry::decode_truncation_count;
use keyhog_scanner::testing::decode_chunk;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    LazyLock, Mutex, MutexGuard,
};

const MAX_DECODED_BYTES: usize = 64 * 1024 * 1024;
const MAX_DECODED_CHUNKS: usize = 1_000;
const STREAM_TAG: &str = "kh1239-stream";
const MODE_OFF: usize = 0;
const MODE_COUNT_BOUNDARY: usize = 1;
const MODE_BYTE_BOUNDARY: usize = 2;
const MODE_OVERSIZE_AFTER_SAFE: usize = 3;

static MODE: AtomicUsize = AtomicUsize::new(MODE_OFF);
static PRODUCTION_CALLS: AtomicUsize = AtomicUsize::new(0);
static TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
static REGISTER_PROBE: LazyLock<()> = LazyLock::new(|| {
    try_register_decoder(Box::new(BudgetProbe))
        .expect("KH-1239 streaming probe must register exactly once");
});

struct ScenarioGuard {
    _lock: MutexGuard<'static, ()>,
    truncations_before: usize,
}

impl Drop for ScenarioGuard {
    fn drop(&mut self) {
        MODE.store(MODE_OFF, Ordering::Relaxed);
    }
}

fn scenario(mode: usize) -> ScenarioGuard {
    let lock = match TEST_LOCK.lock() {
        Ok(lock) => lock,
        Err(poisoned) => poisoned.into_inner(),
    };
    LazyLock::force(&REGISTER_PROBE);
    PRODUCTION_CALLS.store(0, Ordering::Relaxed);
    MODE.store(mode, Ordering::Relaxed);
    ScenarioGuard {
        _lock: lock,
        truncations_before: decode_truncation_count(),
    }
}


fn inert_root() -> Chunk {
    Chunk {
        data: SensitiveString::from("alpha.bravo.charlie.delta"),
        metadata: ChunkMetadata {
            source_type: "kh1239-root".into(),
            path: Some("fixtures/kh1239.txt".into()),
            ..Default::default()
        },
    }
}

fn emitted_chunk(parent: &Chunk, data: String) -> Chunk {
    Chunk {
        data: SensitiveString::from(data),
        metadata: ChunkMetadata {
            source_type: format!("{}/{STREAM_TAG}", parent.metadata.source_type).into(),
            path: parent.metadata.path.clone(),
            ..Default::default()
        },
    }
}

struct BudgetProbe;

impl Decoder for BudgetProbe {
    fn name(&self) -> &'static str {
        "kh1239-budget-probe"
    }


    fn decode_chunk_into(&self, chunk: &Chunk, sink: &mut dyn DecodeOutputSink) {
        if chunk.metadata.source_type.contains(STREAM_TAG) {
            return;
        }
        match MODE.load(Ordering::Relaxed) {
            MODE_COUNT_BOUNDARY => {
                for index in 0..MAX_DECODED_CHUNKS + 50 {
                    PRODUCTION_CALLS.fetch_add(1, Ordering::Relaxed);
                    if !sink.push(emitted_chunk(chunk, format!("probe.{index:04}.end"))) {
                        break;
                    }
                }
            }
            MODE_BYTE_BOUNDARY => {
                PRODUCTION_CALLS.fetch_add(1, Ordering::Relaxed);
                if !sink.push(emitted_chunk(chunk, "X".repeat(MAX_DECODED_BYTES))) {
                    return;
                }
                PRODUCTION_CALLS.fetch_add(1, Ordering::Relaxed);
                let _ = sink.push(emitted_chunk(chunk, "past.exact.boundary".to_owned()));
            }
            MODE_OVERSIZE_AFTER_SAFE => {
                PRODUCTION_CALLS.fetch_add(1, Ordering::Relaxed);
                if !sink.push(emitted_chunk(chunk, "safe.sibling.finding".to_owned())) {
                    return;
                }
                PRODUCTION_CALLS.fetch_add(1, Ordering::Relaxed);
                if !sink.push(emitted_chunk(chunk, "X".repeat(MAX_DECODED_BYTES))) {
                    return;
                }
                PRODUCTION_CALLS.fetch_add(1, Ordering::Relaxed);
                let _ = sink.push(emitted_chunk(chunk, "must.not.be.produced".to_owned()));
            }
            _ => {}
        }
    }
}

/// Regression: the old vector-returning boundary let a decoder produce every
/// adversarial sibling before the 1,000-chunk cap was observed. The shared sink
/// must close on the exact accepted boundary, without requesting candidate 1001.
#[test]
fn chunk_budget_stops_production_at_the_exact_boundary() {
    let _scenario = scenario(MODE_COUNT_BOUNDARY);
    let decoded = decode_chunk(&inert_root(), 1, false, None, None);
    let tagged = decoded
        .iter()
        .filter(|chunk| chunk.metadata.source_type.contains(STREAM_TAG))
        .count();
    assert_eq!(tagged, MAX_DECODED_CHUNKS);
    assert_eq!(PRODUCTION_CALLS.load(Ordering::Relaxed), MAX_DECODED_CHUNKS);
    assert_eq!(
        decode_truncation_count(),
        _scenario.truncations_before + 1
    );
}

/// Regression: direct custom-decoder callers previously reached an unbounded
/// compatibility collector even though production used a bounded sink. The
/// fallible helper must retain at most 1,000 chunks, return an explicit budget
/// error, and close before the producer materializes the remaining fan-out.
#[test]
fn direct_collection_is_bounded_fallible_and_stops_the_producer() {
    let _scenario = scenario(MODE_COUNT_BOUNDARY);
    let error = BudgetProbe
        .decode_chunk(&inert_root())
        .expect_err("direct collection must report fan-out beyond the shared cap");
    assert_eq!(error.produced, MAX_DECODED_CHUNKS);
    assert_eq!(error.max_chunks, MAX_DECODED_CHUNKS);
    assert_eq!(
        PRODUCTION_CALLS.load(Ordering::Relaxed),
        MAX_DECODED_CHUNKS + 1,
        "the rejected boundary probe is touched once; later siblings are never produced"
    );
}

/// Regression: a decoded payload exactly equal to the 64 MiB byte budget was
/// previously accepted only after full fan-out materialization. It remains an
/// accepted boundary value, and closing the sink prevents the next allocation.
#[test]
fn byte_budget_accepts_exact_boundary_then_closes_sink() {
    let _scenario = scenario(MODE_BYTE_BOUNDARY);

    let decoded = decode_chunk(&inert_root(), 1, false, None, None);
    let boundary = decoded
        .iter()
        .find(|chunk| chunk.metadata.source_type.contains(STREAM_TAG))
        .expect("exact-boundary output must be retained");
    assert_eq!(boundary.data.len(), MAX_DECODED_BYTES);
    assert_eq!(PRODUCTION_CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(
        decode_truncation_count(),
        _scenario.truncations_before + 1
    );
}

/// Regression: when an oversized decoded candidate follows a valid sibling,
/// late vector truncation could discard the already-safe sibling together with
/// the rest of the fan-out. The bounded sink retains accepted work, rejects the
/// oversize candidate, and never asks the producer for a later candidate.
#[test]
fn oversized_stream_preserves_safe_sibling_and_stops_immediately() {
    let _scenario = scenario(MODE_OVERSIZE_AFTER_SAFE);

    let decoded = decode_chunk(&inert_root(), 1, false, None, None);
    assert!(decoded.iter().any(|chunk| chunk.data.as_str() == "safe.sibling.finding"));
    assert!(!decoded.iter().any(|chunk| chunk.data.as_str() == "must.not.be.produced"));
    assert_eq!(PRODUCTION_CALLS.load(Ordering::Relaxed), 2);
    assert_eq!(
        decode_truncation_count(),
        _scenario.truncations_before + 1
    );
}

/// Regression: streaming URL, JSON, and MIME-wrapper producers must preserve
/// the decoded positives and their exact absolute source starts. This guards
/// against a bounded-sink refactor emitting bare values that lose wrapper
/// context, path identity, or splice offsets.
#[test]
fn wrapper_streaming_preserves_positives_and_exact_source_attribution() {
    let _scenario = scenario(MODE_OFF);
    let url_line = "endpoint=ghp%5FABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    let json_line = r#"{"token":"ghp\u005fABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"}"#;
    let mime_word = "=?UTF-8?B?Z2hwX0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MA==?=";
    let mime_line = format!("Authorization: {mime_word}");
    let source = format!("{url_line}\n{json_line}\n{mime_line}");
    let root_base = 4_096usize;
    let path = "fixtures/wrapped-secrets.txt";
    let root = Chunk {
        data: SensitiveString::from(source.clone()),
        metadata: ChunkMetadata {
            base_offset: root_base,
            base_line: 17,
            source_type: "fixture".into(),
            path: Some(path.into()),
            ..Default::default()
        },
    };

    let decoded = decode_chunk(&root, 1, false, None, None);
    let expected = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    for (decoder, source_start, source_line) in [
        ("url", 0usize, 17usize),
        ("json", url_line.len() + 1, 18usize),
        (
            "mime-encoded-word",
            url_line.len() + 1 + json_line.len() + 1 + "Authorization: ".len(),
            19usize,
        ),
    ] {
        let output = decoded
            .iter()
            .find(|chunk| {
                chunk.metadata.source_type.ends_with(&format!("/{decoder}"))
                    && chunk.data.contains(expected)
            })
            .unwrap_or_else(|| panic!("missing streamed {decoder} positive"));
        assert_eq!(output.metadata.path.as_deref(), Some(path));
        let (decoded_start, decoded_end) = output
            .metadata
            .decoded_span
            .expect("wrapper output must retain a decoded span");
        let decoded_line = output.metadata.base_line
            + output.data.as_bytes()[..decoded_start]
                .iter()
                .filter(|&&byte| byte == b'\n')
                .count();
        assert_eq!(decoded_line, source_line);
        assert!(decoded_end > decoded_start);
        assert!(output.data[decoded_start..decoded_end].contains(expected));
        assert_eq!(output.metadata.base_offset + decoded_start, root_base + source_start);
    }
}
