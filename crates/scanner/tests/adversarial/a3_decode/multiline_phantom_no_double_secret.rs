//! Adversarial: passthrough .env line must not duplicate secret text in appended region.

use keyhog_scanner::fragment_cache::FragmentCache;
use keyhog_scanner::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn env_single_line_secret_not_duplicated_in_text() {
    let secret = "ghp_thiscanbeplausiblylongenoughtoactuallyfire1234";
    let text = format!("GITHUB_TOKEN={secret}\n");
    let pre = preprocess_multiline(&text, &MultilineConfig::default(), &FragmentCache::new(100));
    let occurrences = pre.text.matches(secret).count();
    assert_eq!(
        occurrences, 1,
        "secret must appear exactly once, got {occurrences} in:\n{}",
        pre.text
    );
}
