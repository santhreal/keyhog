use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn large_file_with_secret_keyword_but_no_concat_passthrough() {
    let filler = "fn ordinary_function() { let x = compute_value(42); println!(\"{}\", x); }\n";
    let secret_line = "const api_key = \"sk_live_0123456789abcdefghijklmnopqrstuv\";\n";
    let mut text = String::new();
    while text.len() <= 64 * 1024 {
        text.push_str(filler);
    }
    text.push_str(secret_line);
    assert!(text.len() > 4096);

    let pre = preprocess_multiline(&text, &MultilineConfig::default(), &FragmentCache::new(100));

    assert_eq!(pre.text, text);
}
