//! Keywords shorter than 4 chars are excluded from fallback AC.

use keyhog_scanner::compiler::build_fallback_keyword_ac;
use keyhog_scanner::types::{CompiledPattern, LazyRegex};

#[test]
fn compiler_fallback_keyword_skips_short() {
    let pattern = CompiledPattern {
        detector_index: 0,
        regex: LazyRegex::detector("key=[a-z0-9]{16}"),
        group: None,
        client_safe: false,
        homoglyph_variant: false,
    };
    let fallback = vec![(pattern, vec!["id".into(), "token".into()])];
    let (ac, mapping) = build_fallback_keyword_ac(&fallback);
    assert!(ac.is_some(), "token keyword must build AC");
    assert_eq!(mapping.len(), 1, "only token (len>=4) should be indexed");
}
