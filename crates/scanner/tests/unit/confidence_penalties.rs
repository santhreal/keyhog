use keyhog_scanner::confidence::{
    apply_post_ml_penalties, char_diversity, contains_placeholder_word, max_repeat_run,
};
#[test]
fn placeholder_words_detected_case_insensitive() {
    assert!(contains_placeholder_word("ghp_example_0001"));
    assert!(!contains_placeholder_word("MY_TEST_KEY")); // "test" not a placeholder
    assert!(contains_placeholder_word("dummy_value"));
    assert!(contains_placeholder_word("fake_token"));
    assert!(contains_placeholder_word("sample_secret"));
    assert!(!contains_placeholder_word("ghp_real_key_123"));
}

#[test]
fn char_diversity_values() {
    assert!((char_diversity("aaa") - 1.0 / 3.0).abs() < 1e-9);
    assert!((char_diversity("abcdef") - 1.0).abs() < 1e-9);
    assert!((char_diversity("") - 1.0).abs() < 1e-9);
}

#[test]
fn max_repeat_run_values() {
    assert!((max_repeat_run("aaaa") - 1.0).abs() < 1e-9);
    assert!((max_repeat_run("aabba") - 0.4).abs() < 1e-9);
    assert_eq!(max_repeat_run(""), 0.0);
}

#[test]
fn post_ml_penalties_crush_placeholders() {
    let score = apply_post_ml_penalties(0.9, "ghp_example_0001_xxxxxxxxxxxxxxxxxxxx");
    assert!(score < 0.1, "score was {}", score);

    let score = apply_post_ml_penalties(0.9, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(score < 0.1, "score was {}", score);

    let score = apply_post_ml_penalties(0.9, "abc");
    assert!((score - 0.9).abs() < 1e-9, "score was {}", score);
}
