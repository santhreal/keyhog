//! Decode-through must report a finding at its REAL, in-bounds source offset —
//! never the structured preprocessor's appended synthetic copy.
//!
//! `build_preprocessed_text` appends a copy of an assignment's value after the
//! original text (at `original_end + 1`) so keyword-context detectors still see
//! it. When the value is base64, decode-through decodes BOTH the original run
//! and the appended copy, surfacing the SAME (detector, credential) at two
//! offsets: the real one inside the chunk and a synthetic one PAST the chunk's
//! end. The (detector, credential) dedup keeps one alias; it must keep the real
//! (lowest) offset, not whichever the scan/`Ord` iteration order reaches first.
//!
//! Regression: the determinism total-order on `RawMatch` (offset/line tie-break)
//! made the dedup deterministically prefer the HIGHER synthetic-append offset.
//! That offset points past the real chunk, so the cross-chunk boundary straddle
//! filter (`boundary.rs`) silently dropped the finding — `base64_akia_splice_
//! across_chunks` went to zero matches. The fix sorts decode candidates
//! offset-ascending before the dedup so the real occurrence always wins.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

#[test]
fn decode_through_reports_real_in_bounds_offset_not_synthetic_alias() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    let scanner = CompiledScanner::compile(keyhog_core::load_detectors(&d).expect("detectors"))
        .expect("compile");

    let secret = "AKIAQYLPMN5HFIQR7XYA";
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        secret.as_bytes(),
    );
    // Single chunk: `CONFIG_B64=<base64-of-AKIA>`. This is exactly the buffer
    // the cross-chunk boundary scan synthesizes, so it reproduces the offset
    // misattribution without the two-chunk dance.
    let prefix = "CONFIG_B64=";
    let data = format!("{prefix}{encoded}");
    let data_len = data.len();
    let base64_start = prefix.len(); // where the real base64 run begins

    let chunk = Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some("b64.env".into()),
            base_offset: 0,
            ..Default::default()
        },
    };

    let matches = scanner.scan(&chunk);
    let aws: Vec<_> = matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == "aws-access-key" && m.credential.as_ref() == secret)
        .collect();

    assert_eq!(
        aws.len(),
        1,
        "exactly one aws-access-key AKIA finding expected, got {}: {:#?}",
        aws.len(),
        matches
    );
    let m = aws[0];

    // The finding MUST point inside the real chunk bytes, never into the
    // synthesized preprocessor-append region (offset >= data_len).
    assert!(
        m.location.offset < data_len,
        "decode-through finding offset {} must be inside the {}-byte chunk, not \
         the synthetic preprocessor-append alias (>= chunk end)",
        m.location.offset,
        data_len
    );
    // Specifically, it lands at the real base64 source span.
    assert_eq!(
        m.location.offset, base64_start,
        "decode-through finding must be attributed to the real base64 run at \
         offset {base64_start}, not a synthetic alias"
    );
}
