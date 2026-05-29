//! Part 99 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates jfrog, jitsu, jotform, jumio, jw, jwt, kafka, kafka, kakaotalk, kaltura detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. JFROG API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv99_jfrog_api_key_normal_must_fire() {
    assert_detector_fires(
        "jfrog-api-key",
        "AKCp8RQwP3EiFJyJ7RheUfKWvbbor0VgYr8Sr",
        "AKCp8RQwP3EiFJyJ7RheUfKWvbbor0VgYr8Sr",
    );
}

#[test]
fn adv99_jfrog_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "jfrog-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv99_jfrog_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "jfrog-api-key",
        "AKCp8RQwP3EiFJyJ7R\u{200B}heUfKWvbbor0VgYr8Sr",
        "AKCp8RQwP3EiFJyJ7RheUfKWvbbor0VgYr8Sr",
    );
}

#[test]
fn adv99_jfrog_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "jfrog-api-key",
        "AKCp8RQwP3EiFJyJ7R\u{00AD}heUfKWvbbor0VgYr8Sr",
        "AKCp8RQwP3EiFJyJ7RheUfKWvbbor0VgYr8Sr",
    );
}

#[test]
fn adv99_jfrog_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "jfrog-api-key",
        "AKCp8RQwP3EiFJyJ7R\u{200C}heUfKWvbbor0VgYr8Sr",
        "AKCp8RQwP3EiFJyJ7RheUfKWvbbor0VgYr8Sr",
    );
}

#[test]
fn adv99_jfrog_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "jfrog-api-key",
        "AKCp8RQwP3EiFJyJ7R\u{200D}heUfKWvbbor0VgYr8Sr",
        "AKCp8RQwP3EiFJyJ7RheUfKWvbbor0VgYr8Sr",
    );
}

#[test]
fn adv99_jfrog_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "jfrog-api-key",
        "AKCp8RQwP3EiFJyJ7R\u{FEFF}heUfKWvbbor0VgYr8Sr",
        "AKCp8RQwP3EiFJyJ7RheUfKWvbbor0VgYr8Sr",
    );
}

#[test]
fn adv99_jfrog_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "jfrog-api-key",
        "AKCp8RQwP3EiFJyJ7R\u{2060}heUfKWvbbor0VgYr8Sr",
        "AKCp8RQwP3EiFJyJ7RheUfKWvbbor0VgYr8Sr",
    );
}

#[test]
fn adv99_jfrog_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "jfrog-api-key",
        "AKCp8RQwP3EiFJyJ7R\u{180E}heUfKWvbbor0VgYr8Sr",
        "AKCp8RQwP3EiFJyJ7RheUfKWvbbor0VgYr8Sr",
    );
}

#[test]
fn adv99_jfrog_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "jfrog-api-key",
        "AKCp8RQwP3EiFJyJ7R\u{202E}heUfKWvbbor0VgYr8Sr",
        "AKCp8RQwP3EiFJyJ7RheUfKWvbbor0VgYr8Sr",
    );
}

#[test]
fn adv99_jfrog_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "jfrog-api-key",
        "AKCp8RQwP3EiFJyJ7R\u{202C}heUfKWvbbor0VgYr8Sr",
        "AKCp8RQwP3EiFJyJ7RheUfKWvbbor0VgYr8Sr",
    );
}

#[test]
fn adv99_jfrog_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "jfrog-api-key",
        "AKCp8RQwP3EiFJyJ7R\u{200E}heUfKWvbbor0VgYr8Sr",
        "AKCp8RQwP3EiFJyJ7RheUfKWvbbor0VgYr8Sr",
    );
}

// =========================================================================
// 2. JITSU API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv99_jitsu_api_key_normal_must_fire() {
    assert_detector_fires(
        "jitsu-api-key",
        "JITSU_API_KEY=x9sOFf4U7wNLtG1T",
        "x9sOFf4U7wNLtG1T",
    );
}

#[test]
fn adv99_jitsu_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "jitsu-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv99_jitsu_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "jitsu-api-key",
        "JITSU_API_KEY=x9sOFf4U\u{200B}7wNLtG1T",
        "x9sOFf4U7wNLtG1T",
    );
}

#[test]
fn adv99_jitsu_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "jitsu-api-key",
        "JITSU_API_KEY=x9sOFf4U\u{00AD}7wNLtG1T",
        "x9sOFf4U7wNLtG1T",
    );
}

#[test]
fn adv99_jitsu_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "jitsu-api-key",
        "JITSU_API_KEY=x9sOFf4U\u{200C}7wNLtG1T",
        "x9sOFf4U7wNLtG1T",
    );
}

#[test]
fn adv99_jitsu_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "jitsu-api-key",
        "JITSU_API_KEY=x9sOFf4U\u{200D}7wNLtG1T",
        "x9sOFf4U7wNLtG1T",
    );
}

#[test]
fn adv99_jitsu_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "jitsu-api-key",
        "JITSU_API_KEY=x9sOFf4U\u{FEFF}7wNLtG1T",
        "x9sOFf4U7wNLtG1T",
    );
}

#[test]
fn adv99_jitsu_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "jitsu-api-key",
        "JITSU_API_KEY=x9sOFf4U\u{2060}7wNLtG1T",
        "x9sOFf4U7wNLtG1T",
    );
}

#[test]
fn adv99_jitsu_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "jitsu-api-key",
        "JITSU_API_KEY=x9sOFf4U\u{180E}7wNLtG1T",
        "x9sOFf4U7wNLtG1T",
    );
}

#[test]
fn adv99_jitsu_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "jitsu-api-key",
        "JITSU_API_KEY=x9sOFf4U\u{202E}7wNLtG1T",
        "x9sOFf4U7wNLtG1T",
    );
}

#[test]
fn adv99_jitsu_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "jitsu-api-key",
        "JITSU_API_KEY=x9sOFf4U\u{202C}7wNLtG1T",
        "x9sOFf4U7wNLtG1T",
    );
}

#[test]
fn adv99_jitsu_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "jitsu-api-key",
        "JITSU_API_KEY=x9sOFf4U\u{200E}7wNLtG1T",
        "x9sOFf4U7wNLtG1T",
    );
}

// =========================================================================
// 3. JOTFORM API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv99_jotform_api_key_normal_must_fire() {
    assert_detector_fires(
        "jotform-api-key",
        "jotform api_key 2963950e3ed2e3dc49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

#[test]
fn adv99_jotform_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "jotform-api-key",
        "dummyorm api_key xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv99_jotform_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "jotform-api-key",
        "jotform api_key 2963950e3ed2e3dc\u{200B}49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

#[test]
fn adv99_jotform_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "jotform-api-key",
        "jotform api_key 2963950e3ed2e3dc\u{00AD}49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

#[test]
fn adv99_jotform_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "jotform-api-key",
        "jotform api_key 2963950e3ed2e3dc\u{200C}49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

#[test]
fn adv99_jotform_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "jotform-api-key",
        "jotform api_key 2963950e3ed2e3dc\u{200D}49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

#[test]
fn adv99_jotform_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "jotform-api-key",
        "jotform api_key 2963950e3ed2e3dc\u{FEFF}49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

#[test]
fn adv99_jotform_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "jotform-api-key",
        "jotform api_key 2963950e3ed2e3dc\u{2060}49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

#[test]
fn adv99_jotform_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "jotform-api-key",
        "jotform api_key 2963950e3ed2e3dc\u{180E}49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

#[test]
fn adv99_jotform_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "jotform-api-key",
        "jotform api_key 2963950e3ed2e3dc\u{202E}49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

#[test]
fn adv99_jotform_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "jotform-api-key",
        "jotform api_key 2963950e3ed2e3dc\u{202C}49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

#[test]
fn adv99_jotform_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "jotform-api-key",
        "jotform api_key 2963950e3ed2e3dc\u{200E}49d5740982bac6a9",
        "2963950e3ed2e3dc49d5740982bac6a9",
    );
}

// =========================================================================
// 4. JUMIO API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv99_jumio_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "jumio-api-credentials",
        "jumio api_token=\"H_ZM9TBrKrmGsNmjQ8mT3OA94HhblZaQFP",
        "H_ZM9TBrKrmGsNmjQ8mT3OA94HhblZaQFP",
    );
}

#[test]
fn adv99_jumio_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "jumio-api-credentials",
        "dummy_prefix_0 =\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv99_jumio_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "jumio-api-credentials",
        "jumio api_token=\"H_ZM9TBrKrmGsNmjQ\u{200B}8mT3OA94HhblZaQFP",
        "H_ZM9TBrKrmGsNmjQ8mT3OA94HhblZaQFP",
    );
}

#[test]
fn adv99_jumio_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "jumio-api-credentials",
        "jumio api_token=\"H_ZM9TBrKrmGsNmjQ\u{00AD}8mT3OA94HhblZaQFP",
        "H_ZM9TBrKrmGsNmjQ8mT3OA94HhblZaQFP",
    );
}

#[test]
fn adv99_jumio_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "jumio-api-credentials",
        "jumio api_token=\"H_ZM9TBrKrmGsNmjQ\u{200C}8mT3OA94HhblZaQFP",
        "H_ZM9TBrKrmGsNmjQ8mT3OA94HhblZaQFP",
    );
}

#[test]
fn adv99_jumio_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "jumio-api-credentials",
        "jumio api_token=\"H_ZM9TBrKrmGsNmjQ\u{200D}8mT3OA94HhblZaQFP",
        "H_ZM9TBrKrmGsNmjQ8mT3OA94HhblZaQFP",
    );
}

#[test]
fn adv99_jumio_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "jumio-api-credentials",
        "jumio api_token=\"H_ZM9TBrKrmGsNmjQ\u{FEFF}8mT3OA94HhblZaQFP",
        "H_ZM9TBrKrmGsNmjQ8mT3OA94HhblZaQFP",
    );
}

#[test]
fn adv99_jumio_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "jumio-api-credentials",
        "jumio api_token=\"H_ZM9TBrKrmGsNmjQ\u{2060}8mT3OA94HhblZaQFP",
        "H_ZM9TBrKrmGsNmjQ8mT3OA94HhblZaQFP",
    );
}

#[test]
fn adv99_jumio_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "jumio-api-credentials",
        "jumio api_token=\"H_ZM9TBrKrmGsNmjQ\u{180E}8mT3OA94HhblZaQFP",
        "H_ZM9TBrKrmGsNmjQ8mT3OA94HhblZaQFP",
    );
}

#[test]
fn adv99_jumio_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "jumio-api-credentials",
        "jumio api_token=\"H_ZM9TBrKrmGsNmjQ\u{202E}8mT3OA94HhblZaQFP",
        "H_ZM9TBrKrmGsNmjQ8mT3OA94HhblZaQFP",
    );
}

#[test]
fn adv99_jumio_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "jumio-api-credentials",
        "jumio api_token=\"H_ZM9TBrKrmGsNmjQ\u{202C}8mT3OA94HhblZaQFP",
        "H_ZM9TBrKrmGsNmjQ8mT3OA94HhblZaQFP",
    );
}

#[test]
fn adv99_jumio_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "jumio-api-credentials",
        "jumio api_token=\"H_ZM9TBrKrmGsNmjQ\u{200E}8mT3OA94HhblZaQFP",
        "H_ZM9TBrKrmGsNmjQ8mT3OA94HhblZaQFP",
    );
}

// =========================================================================
// 5. JW PLAYER API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv99_jw_player_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "jw-player-api-credentials",
        "jwplayersecret=NhmHzQ4gpTIlduEQY1lNWAyzRTzOjB1K",
        "NhmHzQ4gpTIlduEQY1lNWAyzRTzOjB1K",
    );
}

#[test]
fn adv99_jw_player_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "jw-player-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv99_jw_player_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "jw-player-api-credentials",
        "jwplayersecret=NhmHzQ4gpTIlduEQ\u{200B}Y1lNWAyzRTzOjB1K",
        "NhmHzQ4gpTIlduEQY1lNWAyzRTzOjB1K",
    );
}

#[test]
fn adv99_jw_player_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "jw-player-api-credentials",
        "jwplayersecret=NhmHzQ4gpTIlduEQ\u{00AD}Y1lNWAyzRTzOjB1K",
        "NhmHzQ4gpTIlduEQY1lNWAyzRTzOjB1K",
    );
}

#[test]
fn adv99_jw_player_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "jw-player-api-credentials",
        "jwplayersecret=NhmHzQ4gpTIlduEQ\u{200C}Y1lNWAyzRTzOjB1K",
        "NhmHzQ4gpTIlduEQY1lNWAyzRTzOjB1K",
    );
}

#[test]
fn adv99_jw_player_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "jw-player-api-credentials",
        "jwplayersecret=NhmHzQ4gpTIlduEQ\u{200D}Y1lNWAyzRTzOjB1K",
        "NhmHzQ4gpTIlduEQY1lNWAyzRTzOjB1K",
    );
}

#[test]
fn adv99_jw_player_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "jw-player-api-credentials",
        "jwplayersecret=NhmHzQ4gpTIlduEQ\u{FEFF}Y1lNWAyzRTzOjB1K",
        "NhmHzQ4gpTIlduEQY1lNWAyzRTzOjB1K",
    );
}

#[test]
fn adv99_jw_player_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "jw-player-api-credentials",
        "jwplayersecret=NhmHzQ4gpTIlduEQ\u{2060}Y1lNWAyzRTzOjB1K",
        "NhmHzQ4gpTIlduEQY1lNWAyzRTzOjB1K",
    );
}

#[test]
fn adv99_jw_player_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "jw-player-api-credentials",
        "jwplayersecret=NhmHzQ4gpTIlduEQ\u{180E}Y1lNWAyzRTzOjB1K",
        "NhmHzQ4gpTIlduEQY1lNWAyzRTzOjB1K",
    );
}

#[test]
fn adv99_jw_player_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "jw-player-api-credentials",
        "jwplayersecret=NhmHzQ4gpTIlduEQ\u{202E}Y1lNWAyzRTzOjB1K",
        "NhmHzQ4gpTIlduEQY1lNWAyzRTzOjB1K",
    );
}

#[test]
fn adv99_jw_player_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "jw-player-api-credentials",
        "jwplayersecret=NhmHzQ4gpTIlduEQ\u{202C}Y1lNWAyzRTzOjB1K",
        "NhmHzQ4gpTIlduEQY1lNWAyzRTzOjB1K",
    );
}

#[test]
fn adv99_jw_player_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "jw-player-api-credentials",
        "jwplayersecret=NhmHzQ4gpTIlduEQ\u{200E}Y1lNWAyzRTzOjB1K",
        "NhmHzQ4gpTIlduEQY1lNWAyzRTzOjB1K",
    );
}

// =========================================================================
// 6. JWT TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv99_jwt_token_normal_must_fire() {
    assert_detector_fires(
        "jwt-token",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
    );
}

#[test]
fn adv99_jwt_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "jwt-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv99_jwt_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "jwt-token",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V\u{200B}5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
    );
}

#[test]
fn adv99_jwt_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "jwt-token",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V\u{00AD}5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
    );
}

#[test]
fn adv99_jwt_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "jwt-token",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V\u{200C}5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
    );
}

#[test]
fn adv99_jwt_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "jwt-token",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V\u{200D}5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
    );
}

#[test]
fn adv99_jwt_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "jwt-token",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V\u{FEFF}5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
    );
}

#[test]
fn adv99_jwt_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "jwt-token",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V\u{2060}5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
    );
}

#[test]
fn adv99_jwt_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "jwt-token",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V\u{180E}5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
    );
}

#[test]
fn adv99_jwt_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "jwt-token",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V\u{202E}5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
    );
}

#[test]
fn adv99_jwt_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "jwt-token",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V\u{202C}5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
    );
}

#[test]
fn adv99_jwt_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "jwt-token",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V\u{200E}5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w",
    );
}

// =========================================================================
// 7. KAFKA CONNECT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv99_kafka_connect_credentials_normal_must_fire() {
    assert_detector_fires(
        "kafka-connect-credentials",
        "CONNECT_PASSWORD=KafkaConnectPass123",
        "KafkaConnectPass123",
    );
}

#[test]
fn adv99_kafka_connect_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "kafka-connect-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv99_kafka_connect_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "kafka-connect-credentials",
        "CONNECT_PASSWORD=KafkaConn\u{200B}ectPass123",
        "KafkaConnectPass123",
    );
}

#[test]
fn adv99_kafka_connect_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "kafka-connect-credentials",
        "CONNECT_PASSWORD=KafkaConn\u{00AD}ectPass123",
        "KafkaConnectPass123",
    );
}

#[test]
fn adv99_kafka_connect_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "kafka-connect-credentials",
        "CONNECT_PASSWORD=KafkaConn\u{200C}ectPass123",
        "KafkaConnectPass123",
    );
}

#[test]
fn adv99_kafka_connect_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "kafka-connect-credentials",
        "CONNECT_PASSWORD=KafkaConn\u{200D}ectPass123",
        "KafkaConnectPass123",
    );
}

#[test]
fn adv99_kafka_connect_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "kafka-connect-credentials",
        "CONNECT_PASSWORD=KafkaConn\u{FEFF}ectPass123",
        "KafkaConnectPass123",
    );
}

#[test]
fn adv99_kafka_connect_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "kafka-connect-credentials",
        "CONNECT_PASSWORD=KafkaConn\u{2060}ectPass123",
        "KafkaConnectPass123",
    );
}

#[test]
fn adv99_kafka_connect_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "kafka-connect-credentials",
        "CONNECT_PASSWORD=KafkaConn\u{180E}ectPass123",
        "KafkaConnectPass123",
    );
}

#[test]
fn adv99_kafka_connect_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "kafka-connect-credentials",
        "CONNECT_PASSWORD=KafkaConn\u{202E}ectPass123",
        "KafkaConnectPass123",
    );
}

#[test]
fn adv99_kafka_connect_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "kafka-connect-credentials",
        "CONNECT_PASSWORD=KafkaConn\u{202C}ectPass123",
        "KafkaConnectPass123",
    );
}

#[test]
fn adv99_kafka_connect_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "kafka-connect-credentials",
        "CONNECT_PASSWORD=KafkaConn\u{200E}ectPass123",
        "KafkaConnectPass123",
    );
}

// =========================================================================
// 8. KAFKA SASL CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv99_kafka_sasl_credentials_normal_must_fire() {
    assert_detector_fires(
        "kafka-sasl-credentials",
        "KAFKA_SASL_PASSWORD=SecretPass123456",
        "SecretPass123456",
    );
}

#[test]
fn adv99_kafka_sasl_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "kafka-sasl-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv99_kafka_sasl_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "kafka-sasl-credentials",
        "KAFKA_SASL_PASSWORD=SecretPa\u{200B}ss123456",
        "SecretPass123456",
    );
}

#[test]
fn adv99_kafka_sasl_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "kafka-sasl-credentials",
        "KAFKA_SASL_PASSWORD=SecretPa\u{00AD}ss123456",
        "SecretPass123456",
    );
}

#[test]
fn adv99_kafka_sasl_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "kafka-sasl-credentials",
        "KAFKA_SASL_PASSWORD=SecretPa\u{200C}ss123456",
        "SecretPass123456",
    );
}

#[test]
fn adv99_kafka_sasl_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "kafka-sasl-credentials",
        "KAFKA_SASL_PASSWORD=SecretPa\u{200D}ss123456",
        "SecretPass123456",
    );
}

#[test]
fn adv99_kafka_sasl_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "kafka-sasl-credentials",
        "KAFKA_SASL_PASSWORD=SecretPa\u{FEFF}ss123456",
        "SecretPass123456",
    );
}

#[test]
fn adv99_kafka_sasl_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "kafka-sasl-credentials",
        "KAFKA_SASL_PASSWORD=SecretPa\u{2060}ss123456",
        "SecretPass123456",
    );
}

#[test]
fn adv99_kafka_sasl_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "kafka-sasl-credentials",
        "KAFKA_SASL_PASSWORD=SecretPa\u{180E}ss123456",
        "SecretPass123456",
    );
}

#[test]
fn adv99_kafka_sasl_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "kafka-sasl-credentials",
        "KAFKA_SASL_PASSWORD=SecretPa\u{202E}ss123456",
        "SecretPass123456",
    );
}

#[test]
fn adv99_kafka_sasl_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "kafka-sasl-credentials",
        "KAFKA_SASL_PASSWORD=SecretPa\u{202C}ss123456",
        "SecretPass123456",
    );
}

#[test]
fn adv99_kafka_sasl_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "kafka-sasl-credentials",
        "KAFKA_SASL_PASSWORD=SecretPa\u{200E}ss123456",
        "SecretPass123456",
    );
}

// =========================================================================
// 9. KAKAOTALK API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv99_kakaotalk_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "kakaotalk-api-credentials",
        "KakaoAK 5d72afa427ade31a777ec0e7ec6b303e",
        "KakaoAK 5d72afa427ade31a777ec0e7ec6b303e",
    );
}

#[test]
fn adv99_kakaotalk_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "kakaotalk-api-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv99_kakaotalk_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "kakaotalk-api-credentials",
        "KakaoAK 5d72afa427ad\u{200B}e31a777ec0e7ec6b303e",
        "KakaoAK 5d72afa427ade31a777ec0e7ec6b303e",
    );
}

#[test]
fn adv99_kakaotalk_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "kakaotalk-api-credentials",
        "KakaoAK 5d72afa427ad\u{00AD}e31a777ec0e7ec6b303e",
        "KakaoAK 5d72afa427ade31a777ec0e7ec6b303e",
    );
}

#[test]
fn adv99_kakaotalk_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "kakaotalk-api-credentials",
        "KakaoAK 5d72afa427ad\u{200C}e31a777ec0e7ec6b303e",
        "KakaoAK 5d72afa427ade31a777ec0e7ec6b303e",
    );
}

#[test]
fn adv99_kakaotalk_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "kakaotalk-api-credentials",
        "KakaoAK 5d72afa427ad\u{200D}e31a777ec0e7ec6b303e",
        "KakaoAK 5d72afa427ade31a777ec0e7ec6b303e",
    );
}

#[test]
fn adv99_kakaotalk_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "kakaotalk-api-credentials",
        "KakaoAK 5d72afa427ad\u{FEFF}e31a777ec0e7ec6b303e",
        "KakaoAK 5d72afa427ade31a777ec0e7ec6b303e",
    );
}

#[test]
fn adv99_kakaotalk_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "kakaotalk-api-credentials",
        "KakaoAK 5d72afa427ad\u{2060}e31a777ec0e7ec6b303e",
        "KakaoAK 5d72afa427ade31a777ec0e7ec6b303e",
    );
}

#[test]
fn adv99_kakaotalk_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "kakaotalk-api-credentials",
        "KakaoAK 5d72afa427ad\u{180E}e31a777ec0e7ec6b303e",
        "KakaoAK 5d72afa427ade31a777ec0e7ec6b303e",
    );
}

#[test]
fn adv99_kakaotalk_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "kakaotalk-api-credentials",
        "KakaoAK 5d72afa427ad\u{202E}e31a777ec0e7ec6b303e",
        "KakaoAK 5d72afa427ade31a777ec0e7ec6b303e",
    );
}

#[test]
fn adv99_kakaotalk_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "kakaotalk-api-credentials",
        "KakaoAK 5d72afa427ad\u{202C}e31a777ec0e7ec6b303e",
        "KakaoAK 5d72afa427ade31a777ec0e7ec6b303e",
    );
}

#[test]
fn adv99_kakaotalk_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "kakaotalk-api-credentials",
        "KakaoAK 5d72afa427ad\u{200E}e31a777ec0e7ec6b303e",
        "KakaoAK 5d72afa427ade31a777ec0e7ec6b303e",
    );
}

// =========================================================================
// 10. KALTURA API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv99_kaltura_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "kaltura-api-credentials",
        "KALTURA admin_secret=f503022fc2f47fcf4f8fefe42c30bba9",
        "f503022fc2f47fcf4f8fefe42c30bba9",
    );
}

#[test]
fn adv99_kaltura_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "kaltura-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv99_kaltura_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "kaltura-api-credentials",
        "KALTURA admin_secret=f503022fc2f47fcf\u{200B}4f8fefe42c30bba9",
        "f503022fc2f47fcf4f8fefe42c30bba9",
    );
}

#[test]
fn adv99_kaltura_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "kaltura-api-credentials",
        "KALTURA admin_secret=f503022fc2f47fcf\u{00AD}4f8fefe42c30bba9",
        "f503022fc2f47fcf4f8fefe42c30bba9",
    );
}

#[test]
fn adv99_kaltura_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "kaltura-api-credentials",
        "KALTURA admin_secret=f503022fc2f47fcf\u{200C}4f8fefe42c30bba9",
        "f503022fc2f47fcf4f8fefe42c30bba9",
    );
}

#[test]
fn adv99_kaltura_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "kaltura-api-credentials",
        "KALTURA admin_secret=f503022fc2f47fcf\u{200D}4f8fefe42c30bba9",
        "f503022fc2f47fcf4f8fefe42c30bba9",
    );
}

#[test]
fn adv99_kaltura_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "kaltura-api-credentials",
        "KALTURA admin_secret=f503022fc2f47fcf\u{FEFF}4f8fefe42c30bba9",
        "f503022fc2f47fcf4f8fefe42c30bba9",
    );
}

#[test]
fn adv99_kaltura_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "kaltura-api-credentials",
        "KALTURA admin_secret=f503022fc2f47fcf\u{2060}4f8fefe42c30bba9",
        "f503022fc2f47fcf4f8fefe42c30bba9",
    );
}

#[test]
fn adv99_kaltura_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "kaltura-api-credentials",
        "KALTURA admin_secret=f503022fc2f47fcf\u{180E}4f8fefe42c30bba9",
        "f503022fc2f47fcf4f8fefe42c30bba9",
    );
}

#[test]
fn adv99_kaltura_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "kaltura-api-credentials",
        "KALTURA admin_secret=f503022fc2f47fcf\u{202E}4f8fefe42c30bba9",
        "f503022fc2f47fcf4f8fefe42c30bba9",
    );
}

#[test]
fn adv99_kaltura_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "kaltura-api-credentials",
        "KALTURA admin_secret=f503022fc2f47fcf\u{202C}4f8fefe42c30bba9",
        "f503022fc2f47fcf4f8fefe42c30bba9",
    );
}

#[test]
fn adv99_kaltura_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "kaltura-api-credentials",
        "KALTURA admin_secret=f503022fc2f47fcf\u{200E}4f8fefe42c30bba9",
        "f503022fc2f47fcf4f8fefe42c30bba9",
    );
}


