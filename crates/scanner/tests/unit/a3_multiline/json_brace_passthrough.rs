use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn json_shaped_invalid_json_concat_is_preprocessed() {
    // `{"key": "part1" + "part2"}` LOOKS like JSON but the `+` makes it INVALID
    // JSON — a JS/TS object literal. The old blanket leading-`{` reject passed it
    // through (Law 10: a whole concat surface silently skipped on a shape
    // heuristic); the strict-JSON disambiguation now fails fast for it, so it is
    // PREPROCESSED (its string literals joined and appended for scanning) instead
    // of skipped — no longer a byte-for-byte passthrough.
    let text = "{\"key\": \"part1\" + \"part2\"}";
    let pre = preprocess_multiline(text, &MultilineConfig::default(), &FragmentCache::new(100));
    assert_ne!(
        pre.text, text,
        "invalid-JSON concat must be preprocessed, not passed through"
    );
    assert!(
        pre.text.starts_with(text),
        "original bytes preserved as prefix"
    );
}

#[test]
fn genuine_json_object_passes_through_without_append() {
    // A strict-JSON object with no concat surface is genuine data owned by the
    // JSON parser (the concat gate never trips) and passes through byte-for-byte
    // with no appended reassembly.
    let text = "{\"key\": \"part1part2\"}";
    let pre = preprocess_multiline(text, &MultilineConfig::default(), &FragmentCache::new(100));
    assert_eq!(pre.text, text);
}
