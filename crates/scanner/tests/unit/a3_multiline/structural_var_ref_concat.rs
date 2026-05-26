use keyhog_scanner::fragment_cache::FragmentCache;
use keyhog_scanner::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn structural_var_ref_concat_reassembles_split_key() {
    let text = "head = \"TESTKEY_\"\n                tail = \"aK7xP9mQ2wE5rT8yU1iO\"\n                token = head + tail\n";
    let pre = preprocess_multiline(text, &MultilineConfig::default(), &FragmentCache::new(100));
    assert!(pre.text.contains("TESTKEY_aK7xP9mQ2wE5rT8yU1iO"));
}
