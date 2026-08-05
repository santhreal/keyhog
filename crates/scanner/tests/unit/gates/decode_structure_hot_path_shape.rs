//! Gate decode-structure hot path: one cached decode pass feeds all predicates.

use super::support::{read, scanner_src, uncommented_code};

#[test]
fn decode_structure_uses_one_fact_cache() {
    let prod = uncommented_code(&read(&scanner_src().join("decode_structure.rs")));

    assert!(
        prod.contains("struct DecodeEvidence")
            && prod.contains("static DECODE_FACTS_CACHE")
            && prod.contains("pub(crate) fn evidence(candidate: &str) -> DecodeEvidence")
            && prod.contains("fn compute_decode_facts(candidate: &str) -> DecodeEvidence"),
        "decode_structure should cache one decoded fact record per candidate"
    );
    assert!(
        prod.matches("thread_local!").count() == 1,
        "decode_structure must not restore separate thread-local caches per predicate"
    );
    assert!(
        !prod.contains("fn compute_decoded_is_base64_blob")
            && !prod.contains("fn compute_decoded_contains_placeholder")
            && !prod.contains("static CACHE: RefCell<HashMap<u64, bool>>"),
        "decode_structure predicates must not re-decode through private bool caches"
    );
}

#[test]
fn decode_structure_reuses_shared_hex_and_protobuf_tables() {
    let prod = uncommented_code(&read(&scanner_src().join("decode_structure.rs")));

    assert!(
        prod.matches("crate::decode::hex_decode(s).ok()").count() == 2,
        "decode_structure hex decoding must reuse the scanner hex decoder"
    );
    assert!(
        !prod.contains("to_digit(16)") && !prod.contains("out.push(((hi << 4) | lo) as u8)"),
        "decode_structure must not restore a private hex parser"
    );
    assert!(
        prod.contains("const FIXED_WIRE_WIDTHS: [usize; 8] = [0, 8, 0, 0, 0, 4, 0, 0];")
            && prod.contains("FIXED_WIRE_WIDTHS[wire as usize]"),
        "protobuf fixed-width handling should use one wire-width table"
    );
}
