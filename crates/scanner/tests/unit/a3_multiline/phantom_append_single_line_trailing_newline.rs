//! Regression: single-line input with trailing newline must not duplicate text past EOF.

use keyhog_scanner::fragment_cache::FragmentCache;
use keyhog_scanner::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn single_line_trailing_newline_no_phantom_append() {
    let text = "GITHUB_TOKEN=ghp_thiscanbeplausiblylongenoughtoactuallyfire1234\n";
    let pre = preprocess_multiline(text, &MultilineConfig::default(), &FragmentCache::new(100));
    assert_eq!(
        pre.text.len(),
        text.len(),
        "must not append duplicate joined text for single-line input; got len {} vs {}",
        pre.text.len(),
        text.len()
    );
    assert_eq!(pre.original_end, text.len());
}
