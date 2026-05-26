//! Multi-line plus concatenation joins split secret literals across lines.

use keyhog_scanner::fragment_cache::FragmentCache;
use keyhog_scanner::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn multiline_plus_concat_joins_split_secret() {
    let text = "api_key = \"sk-\" +\n    \"live_abcdef123456\";";
    let pre = preprocess_multiline(text, &MultilineConfig::default(), &FragmentCache::new(100));
    assert!(
        pre.text.contains("sk-live_abcdef123456"),
        "multiline plus concat must reassemble split secret; got:\n{}",
        pre.text
    );
}
