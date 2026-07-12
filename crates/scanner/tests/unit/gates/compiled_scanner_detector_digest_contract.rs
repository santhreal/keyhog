#[test]
fn compiled_scanner_detector_digest_uses_stable_length_delimited_blake3() {
    let source = include_str!("../../../src/engine/compiled_api.rs");
    let start = source
        .find("pub(crate) fn detector_digest(&self) -> u64")
        .expect("detector_digest function present");
    let end = source[start..]
        .find("/// Identifier of the GPU backend acquired at compile time")
        .map(|offset| start + offset)
        .expect("detector_digest function boundary present");
    let body = &source[start..end];
    let helper_start = source
        .find("fn detector_digest_update(hasher: &mut blake3::Hasher")
        .expect("detector digest length-tag helper present");
    let helper = &source[helper_start..];

    assert!(
        body.contains("blake3::Hasher::new()")
            && body.contains("keyhog-scanner-detector-digest-v1")
            && body.contains("pattern_count")
            && body.contains("src.as_bytes()")
            && helper.contains("(tag.len() as u64).to_le_bytes()")
            && helper.contains("(value.len() as u64).to_le_bytes()")
            && helper.contains("fn detector_digest_update_u64")
            && !body.contains("DefaultHasher")
            && !body.contains("std::hash"),
        "CompiledScanner::detector_digest feeds autoroute cache identity; it must use stable, domain-separated, length-delimited BLAKE3 rather than Rust DefaultHasher"
    );
}
