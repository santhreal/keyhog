//! Inline-array reassembly joins only the literals INSIDE `[...]`, never a
//! quoted LHS key. Regression for join_inline_array_strings scanning the whole
//! line and splicing the key (`"api_secret"`) into the reassembled value.

use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::multiline::{preprocess_multiline, MultilineConfig};

#[test]
fn inline_array_quoted_key_is_not_spliced_into_value() {
    // The `url` `+`-concat supplies the concatenation indicator so the
    // structural array pass runs on the quoted-key array line below.
    let text = concat!(
        "url = \"https://\" +\n",
        "      \"example.com\"\n",
        "\"api_secret\": [\"AKIAIOSF\", \"ODNN7EXAMPLE12\"]\n",
    );
    let pre = preprocess_multiline(text, &MultilineConfig::default(), &FragmentCache::new(100));
    assert!(
        pre.text.contains("AKIAIOSFODNN7EXAMPLE12"),
        "array body must reassemble; got:\n{}",
        pre.text
    );
    assert!(
        !pre.text.contains("api_secretAKIAIOSF"),
        "quoted key must not be spliced into the reassembled value; got:\n{}",
        pre.text
    );
}
