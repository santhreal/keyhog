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
fn decode_evidence_feeds_ml_confidence_and_fallback_paths() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = |relative: &str| {
        std::fs::read_to_string(manifest.join(relative))
            .unwrap_or_else(|e| panic!("{relative} not readable: {e}"))
    };
    let uncommented = |src: &str| {
        src.lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let ml_features = uncommented(&source("src/ml_scorer/ml_features.rs"));
    assert!(
        ml_features.contains("crate::decode_structure::evidence(text).is_binary_payload()")
            && !ml_features.contains("crate::decode_structure::is_encoded_binary(text)"),
        "ML decode feature must read the shared decoded-evidence record, not a private bool wrapper"
    );

    for relative in [
        "src/confidence/penalties.rs",
        "src/engine/phase2_entropy/gates.rs",
        "src/generic_assignment_shape.rs",
    ] {
        let code = uncommented(&source(relative));
        assert!(
            code.contains("let decode_evidence = crate::decode_structure::evidence("),
            "{relative} must bind one decode-evidence record before consuming decode-through predicates"
        );
        for forbidden in [
            "crate::decode_structure::is_encoded_binary(",
            "crate::decode_structure::decoded_contains_placeholder(",
            "crate::decode_structure::decoded_contains_nul_byte(",
            "crate::decode_structure::decoded_is_base64_blob(",
        ] {
            assert!(
                !code.contains(forbidden),
                "{relative} must not restore duplicate decode predicate wrapper call {forbidden}"
            );
        }
    }
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
