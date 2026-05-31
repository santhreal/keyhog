use base64::Engine as _;
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
    let score = apply_post_ml_penalties(0.9, "ghp_example_0001_xxxxxxxxxxxxxxxxxxxx", false);
    assert!(score < 0.1, "score was {}", score);

    let score = apply_post_ml_penalties(0.9, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false);
    assert!(score < 0.1, "score was {}", score);

    let score = apply_post_ml_penalties(0.9, "abc", false);
    assert!((score - 0.9).abs() < 1e-9, "score was {}", score);
}

#[test]
fn named_credential_url_survives_example_host_placeholder() {
    let url = "redis://:8sxOrMFOSe0ZoWJwIG1Gj1gCRedSY6MO@hljexttaoc.example.org:6379";

    let named = apply_post_ml_penalties(0.9, url, true);
    assert!(
        (named - 0.9).abs() < 1e-9,
        "named credential-bearing URL must not be crushed by example.org host; got {named}"
    );

    let generic = apply_post_ml_penalties(0.9, url, false);
    assert!(
        generic < 0.1,
        "generic URL shape still treats example.org as placeholder evidence; got {generic}"
    );
}

#[test]
fn named_credential_url_placeholder_password_still_penalized() {
    let score = apply_post_ml_penalties(
        0.9,
        "postgres://user:fake_password@example.org:5432/app",
        true,
    );

    assert!(
        score < 0.1,
        "placeholder words inside URL userinfo must still be crushed; got {score}"
    );
}

#[test]
fn post_ml_penalties_slam_double_base64_for_generic() {
    let inner = "NbrnTP3fAbnFbmOHnKYaXRvj7uff0LYTH8xIZM1J";
    let outer = base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
    let pre = 0.9_f64;
    let post = apply_post_ml_penalties(pre, &outer, false);
    assert!(
        post <= pre * 0.05,
        "generic finding whose value is base64-of-base64 must be slammed; got {post} from {pre}",
    );
}

#[test]
fn post_ml_penalties_preserve_named_double_base64() {
    let inner = "NbrnTP3fAbnFbmOHnKYaXRvj7uff0LYTH8xIZM1J";
    let outer = base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
    let pre = 0.9_f64;
    let post = apply_post_ml_penalties(pre, &outer, true);
    assert!(
        post >= pre - 1e-9,
        "named detector match with base64-of-base64 shape must not be slammed; got {post} from {pre}",
    );
}
