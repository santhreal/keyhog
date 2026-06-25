#[test]
fn decode_pipeline_debug_truncation_paths_record_typed_coverage_gap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/decode/pipeline.rs");
    let source = std::fs::read_to_string(path).expect("decode pipeline source readable");

    for marker in [
        "decode caller deadline exhausted; stopping decode-through",
        "decode caller deadline exhausted mid-fan-out; stopping decode-through",
        "decode caller deadline exhausted while consuming decoder output",
        "decode depth/size cap reached: chunk truncated to limit",
    ] {
        let tail = source
            .split(marker)
            .nth(1)
            .unwrap_or_else(|| panic!("decode truncation marker missing: {marker}"));
        let branch = tail
            .split("return decoded_chunks")
            .next()
            .unwrap_or(tail)
            .split("break;")
            .next()
            .unwrap_or(tail);
        assert!(
            branch.contains("crate::telemetry::record_decode_truncation();"),
            "decode truncation marker must record typed coverage telemetry before exiting: {marker}"
        );
    }

    assert_eq!(
        source.matches("record_decode_truncation();").count(),
        4,
        "every decode pipeline truncation exit should be explicitly accounted for here"
    );
}
