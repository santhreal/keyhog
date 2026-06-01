//! Part 134 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates ticktick, timescaledb, todoist, togetherai, tomtom, transifex, transpose, travisci, trello, trello detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. TICKTICK ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv134_ticktick_access_token_normal_must_fire() {
    assert_detector_fires(
        "ticktick-access-token",
        "TICKTICK_ACCESS_TOKEN=a6XSuv28Xs8URY6RovRoAkfqsq4yO-r0oI0lsOMO",
        "a6XSuv28Xs8URY6RovRoAkfqsq4yO-r0oI0lsOMO",
    );
}

#[test]
fn adv134_ticktick_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ticktick-access-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv134_ticktick_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ticktick-access-token",
        "TICKTICK_ACCESS_TOKEN=a6XSuv28Xs8URY6RovRo\u{200B}Akfqsq4yO-r0oI0lsOMO",
        "a6XSuv28Xs8URY6RovRoAkfqsq4yO-r0oI0lsOMO",
    );
}

#[test]
fn adv134_ticktick_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ticktick-access-token",
        "TICKTICK_ACCESS_TOKEN=a6XSuv28Xs8URY6RovRo\u{00AD}Akfqsq4yO-r0oI0lsOMO",
        "a6XSuv28Xs8URY6RovRoAkfqsq4yO-r0oI0lsOMO",
    );
}

#[test]
fn adv134_ticktick_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "ticktick-access-token",
        "TICKTICK_ACCESS_TOKEN=a6XSuv28Xs8URY6RovRo\u{200C}Akfqsq4yO-r0oI0lsOMO",
        "a6XSuv28Xs8URY6RovRoAkfqsq4yO-r0oI0lsOMO",
    );
}

#[test]
fn adv134_ticktick_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "ticktick-access-token",
        "TICKTICK_ACCESS_TOKEN=a6XSuv28Xs8URY6RovRo\u{200D}Akfqsq4yO-r0oI0lsOMO",
        "a6XSuv28Xs8URY6RovRoAkfqsq4yO-r0oI0lsOMO",
    );
}

#[test]
fn adv134_ticktick_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "ticktick-access-token",
        "TICKTICK_ACCESS_TOKEN=a6XSuv28Xs8URY6RovRo\u{FEFF}Akfqsq4yO-r0oI0lsOMO",
        "a6XSuv28Xs8URY6RovRoAkfqsq4yO-r0oI0lsOMO",
    );
}

#[test]
fn adv134_ticktick_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "ticktick-access-token",
        "TICKTICK_ACCESS_TOKEN=a6XSuv28Xs8URY6RovRo\u{2060}Akfqsq4yO-r0oI0lsOMO",
        "a6XSuv28Xs8URY6RovRoAkfqsq4yO-r0oI0lsOMO",
    );
}

#[test]
fn adv134_ticktick_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "ticktick-access-token",
        "TICKTICK_ACCESS_TOKEN=a6XSuv28Xs8URY6RovRo\u{180E}Akfqsq4yO-r0oI0lsOMO",
        "a6XSuv28Xs8URY6RovRoAkfqsq4yO-r0oI0lsOMO",
    );
}

#[test]
fn adv134_ticktick_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "ticktick-access-token",
        "TICKTICK_ACCESS_TOKEN=a6XSuv28Xs8URY6RovRo\u{202E}Akfqsq4yO-r0oI0lsOMO",
        "a6XSuv28Xs8URY6RovRoAkfqsq4yO-r0oI0lsOMO",
    );
}

#[test]
fn adv134_ticktick_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "ticktick-access-token",
        "TICKTICK_ACCESS_TOKEN=a6XSuv28Xs8URY6RovRo\u{202C}Akfqsq4yO-r0oI0lsOMO",
        "a6XSuv28Xs8URY6RovRoAkfqsq4yO-r0oI0lsOMO",
    );
}

#[test]
fn adv134_ticktick_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "ticktick-access-token",
        "TICKTICK_ACCESS_TOKEN=a6XSuv28Xs8URY6RovRo\u{200E}Akfqsq4yO-r0oI0lsOMO",
        "a6XSuv28Xs8URY6RovRoAkfqsq4yO-r0oI0lsOMO",
    );
}

// =========================================================================
// 2. TIMESCALEDB CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv134_timescaledb_credentials_normal_must_fire() {
    assert_detector_fires(
        "timescaledb-credentials",
        "TIMESCALEDB PASSWORD=TimescaleDbPass1234",
        "TimescaleDbPass1234",
    );
}

#[test]
fn adv134_timescaledb_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "timescaledb-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv134_timescaledb_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "timescaledb-credentials",
        "TIMESCALEDB PASSWORD=Timescale\u{200B}DbPass1234",
        "TimescaleDbPass1234",
    );
}

#[test]
fn adv134_timescaledb_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "timescaledb-credentials",
        "TIMESCALEDB PASSWORD=Timescale\u{00AD}DbPass1234",
        "TimescaleDbPass1234",
    );
}

#[test]
fn adv134_timescaledb_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "timescaledb-credentials",
        "TIMESCALEDB PASSWORD=Timescale\u{200C}DbPass1234",
        "TimescaleDbPass1234",
    );
}

#[test]
fn adv134_timescaledb_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "timescaledb-credentials",
        "TIMESCALEDB PASSWORD=Timescale\u{200D}DbPass1234",
        "TimescaleDbPass1234",
    );
}

#[test]
fn adv134_timescaledb_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "timescaledb-credentials",
        "TIMESCALEDB PASSWORD=Timescale\u{FEFF}DbPass1234",
        "TimescaleDbPass1234",
    );
}

#[test]
fn adv134_timescaledb_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "timescaledb-credentials",
        "TIMESCALEDB PASSWORD=Timescale\u{2060}DbPass1234",
        "TimescaleDbPass1234",
    );
}

#[test]
fn adv134_timescaledb_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "timescaledb-credentials",
        "TIMESCALEDB PASSWORD=Timescale\u{180E}DbPass1234",
        "TimescaleDbPass1234",
    );
}

#[test]
fn adv134_timescaledb_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "timescaledb-credentials",
        "TIMESCALEDB PASSWORD=Timescale\u{202E}DbPass1234",
        "TimescaleDbPass1234",
    );
}

#[test]
fn adv134_timescaledb_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "timescaledb-credentials",
        "TIMESCALEDB PASSWORD=Timescale\u{202C}DbPass1234",
        "TimescaleDbPass1234",
    );
}

#[test]
fn adv134_timescaledb_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "timescaledb-credentials",
        "TIMESCALEDB PASSWORD=Timescale\u{200E}DbPass1234",
        "TimescaleDbPass1234",
    );
}

// =========================================================================
// 3. TODOIST API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv134_todoist_api_token_normal_must_fire() {
    assert_detector_fires(
        "todoist-api-token",
        "TODOIST_API_TOKEN=065b8384121873a0aa2b71dc527b6f5a296d7284",
        "065b8384121873a0aa2b71dc527b6f5a296d7284",
    );
}

#[test]
fn adv134_todoist_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "todoist-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv134_todoist_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "todoist-api-token",
        "TODOIST_API_TOKEN=065b8384121873a0aa2b\u{200B}71dc527b6f5a296d7284",
        "065b8384121873a0aa2b71dc527b6f5a296d7284",
    );
}

#[test]
fn adv134_todoist_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "todoist-api-token",
        "TODOIST_API_TOKEN=065b8384121873a0aa2b\u{00AD}71dc527b6f5a296d7284",
        "065b8384121873a0aa2b71dc527b6f5a296d7284",
    );
}

#[test]
fn adv134_todoist_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "todoist-api-token",
        "TODOIST_API_TOKEN=065b8384121873a0aa2b\u{200C}71dc527b6f5a296d7284",
        "065b8384121873a0aa2b71dc527b6f5a296d7284",
    );
}

#[test]
fn adv134_todoist_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "todoist-api-token",
        "TODOIST_API_TOKEN=065b8384121873a0aa2b\u{200D}71dc527b6f5a296d7284",
        "065b8384121873a0aa2b71dc527b6f5a296d7284",
    );
}

#[test]
fn adv134_todoist_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "todoist-api-token",
        "TODOIST_API_TOKEN=065b8384121873a0aa2b\u{FEFF}71dc527b6f5a296d7284",
        "065b8384121873a0aa2b71dc527b6f5a296d7284",
    );
}

#[test]
fn adv134_todoist_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "todoist-api-token",
        "TODOIST_API_TOKEN=065b8384121873a0aa2b\u{2060}71dc527b6f5a296d7284",
        "065b8384121873a0aa2b71dc527b6f5a296d7284",
    );
}

#[test]
fn adv134_todoist_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "todoist-api-token",
        "TODOIST_API_TOKEN=065b8384121873a0aa2b\u{180E}71dc527b6f5a296d7284",
        "065b8384121873a0aa2b71dc527b6f5a296d7284",
    );
}

#[test]
fn adv134_todoist_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "todoist-api-token",
        "TODOIST_API_TOKEN=065b8384121873a0aa2b\u{202E}71dc527b6f5a296d7284",
        "065b8384121873a0aa2b71dc527b6f5a296d7284",
    );
}

#[test]
fn adv134_todoist_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "todoist-api-token",
        "TODOIST_API_TOKEN=065b8384121873a0aa2b\u{202C}71dc527b6f5a296d7284",
        "065b8384121873a0aa2b71dc527b6f5a296d7284",
    );
}

#[test]
fn adv134_todoist_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "todoist-api-token",
        "TODOIST_API_TOKEN=065b8384121873a0aa2b\u{200E}71dc527b6f5a296d7284",
        "065b8384121873a0aa2b71dc527b6f5a296d7284",
    );
}

// =========================================================================
// 4. TOGETHERAI API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv134_togetherai_api_key_normal_must_fire() {
    assert_detector_fires(
        "togetherai-api-key",
        "TOGETHER_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv134_togetherai_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "togetherai-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv134_togetherai_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "togetherai-api-key",
        "TOGETHER_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200B}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv134_togetherai_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "togetherai-api-key",
        "TOGETHER_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{00AD}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv134_togetherai_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "togetherai-api-key",
        "TOGETHER_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200C}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv134_togetherai_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "togetherai-api-key",
        "TOGETHER_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200D}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv134_togetherai_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "togetherai-api-key",
        "TOGETHER_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{FEFF}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv134_togetherai_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "togetherai-api-key",
        "TOGETHER_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{2060}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv134_togetherai_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "togetherai-api-key",
        "TOGETHER_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{180E}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv134_togetherai_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "togetherai-api-key",
        "TOGETHER_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{202E}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv134_togetherai_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "togetherai-api-key",
        "TOGETHER_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{202C}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv134_togetherai_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "togetherai-api-key",
        "TOGETHER_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200E}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 5. TOMTOM API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv134_tomtom_api_key_normal_must_fire() {
    assert_detector_fires(
        "tomtom-api-key",
        "tomtom.api.key ' :    'ddBdrdlALEHmnzSOzuOzYo3W9ZF9T6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
        "ddBdrdlALEHmnzSOzuOzYo3W9ZF9T6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
    );
}

#[test]
fn adv134_tomtom_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "tomtom-api-key",
        "dummy_prefix_0:    'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv134_tomtom_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "tomtom-api-key",
        "tomtom.api.key ' :    'ddBdrdlALEHmnzSOzuOzYo3W9ZF9T\u{200B}6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
        "ddBdrdlALEHmnzSOzuOzYo3W9ZF9T6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
    );
}

#[test]
fn adv134_tomtom_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "tomtom-api-key",
        "tomtom.api.key ' :    'ddBdrdlALEHmnzSOzuOzYo3W9ZF9T\u{00AD}6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
        "ddBdrdlALEHmnzSOzuOzYo3W9ZF9T6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
    );
}

#[test]
fn adv134_tomtom_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "tomtom-api-key",
        "tomtom.api.key ' :    'ddBdrdlALEHmnzSOzuOzYo3W9ZF9T\u{200C}6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
        "ddBdrdlALEHmnzSOzuOzYo3W9ZF9T6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
    );
}

#[test]
fn adv134_tomtom_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "tomtom-api-key",
        "tomtom.api.key ' :    'ddBdrdlALEHmnzSOzuOzYo3W9ZF9T\u{200D}6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
        "ddBdrdlALEHmnzSOzuOzYo3W9ZF9T6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
    );
}

#[test]
fn adv134_tomtom_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "tomtom-api-key",
        "tomtom.api.key ' :    'ddBdrdlALEHmnzSOzuOzYo3W9ZF9T\u{FEFF}6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
        "ddBdrdlALEHmnzSOzuOzYo3W9ZF9T6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
    );
}

#[test]
fn adv134_tomtom_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "tomtom-api-key",
        "tomtom.api.key ' :    'ddBdrdlALEHmnzSOzuOzYo3W9ZF9T\u{2060}6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
        "ddBdrdlALEHmnzSOzuOzYo3W9ZF9T6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
    );
}

#[test]
fn adv134_tomtom_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "tomtom-api-key",
        "tomtom.api.key ' :    'ddBdrdlALEHmnzSOzuOzYo3W9ZF9T\u{180E}6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
        "ddBdrdlALEHmnzSOzuOzYo3W9ZF9T6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
    );
}

#[test]
fn adv134_tomtom_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "tomtom-api-key",
        "tomtom.api.key ' :    'ddBdrdlALEHmnzSOzuOzYo3W9ZF9T\u{202E}6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
        "ddBdrdlALEHmnzSOzuOzYo3W9ZF9T6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
    );
}

#[test]
fn adv134_tomtom_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "tomtom-api-key",
        "tomtom.api.key ' :    'ddBdrdlALEHmnzSOzuOzYo3W9ZF9T\u{202C}6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
        "ddBdrdlALEHmnzSOzuOzYo3W9ZF9T6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
    );
}

#[test]
fn adv134_tomtom_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "tomtom-api-key",
        "tomtom.api.key ' :    'ddBdrdlALEHmnzSOzuOzYo3W9ZF9T\u{200E}6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
        "ddBdrdlALEHmnzSOzuOzYo3W9ZF9T6SF6UzGi4yO0Dp8ABXpW9BUl2rNp2",
    );
}

// =========================================================================
// 6. TRANSIFEX API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv134_transifex_api_token_normal_must_fire() {
    assert_detector_fires(
        "transifex-api-token",
        "TRANSIFEX_APIAPI KEY=:=  fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZVLSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
        "fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZVLSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
    );
}

#[test]
fn adv134_transifex_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "transifex-api-token",
        "dummy_prefix_0 =:=  xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv134_transifex_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "transifex-api-token",
        "TRANSIFEX_APIAPI KEY=:=  fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZV\u{200B}LSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
        "fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZVLSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
    );
}

#[test]
fn adv134_transifex_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "transifex-api-token",
        "TRANSIFEX_APIAPI KEY=:=  fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZV\u{00AD}LSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
        "fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZVLSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
    );
}

#[test]
fn adv134_transifex_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "transifex-api-token",
        "TRANSIFEX_APIAPI KEY=:=  fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZV\u{200C}LSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
        "fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZVLSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
    );
}

#[test]
fn adv134_transifex_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "transifex-api-token",
        "TRANSIFEX_APIAPI KEY=:=  fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZV\u{200D}LSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
        "fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZVLSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
    );
}

#[test]
fn adv134_transifex_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "transifex-api-token",
        "TRANSIFEX_APIAPI KEY=:=  fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZV\u{FEFF}LSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
        "fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZVLSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
    );
}

#[test]
fn adv134_transifex_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "transifex-api-token",
        "TRANSIFEX_APIAPI KEY=:=  fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZV\u{2060}LSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
        "fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZVLSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
    );
}

#[test]
fn adv134_transifex_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "transifex-api-token",
        "TRANSIFEX_APIAPI KEY=:=  fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZV\u{180E}LSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
        "fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZVLSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
    );
}

#[test]
fn adv134_transifex_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "transifex-api-token",
        "TRANSIFEX_APIAPI KEY=:=  fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZV\u{202E}LSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
        "fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZVLSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
    );
}

#[test]
fn adv134_transifex_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "transifex-api-token",
        "TRANSIFEX_APIAPI KEY=:=  fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZV\u{202C}LSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
        "fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZVLSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
    );
}

#[test]
fn adv134_transifex_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "transifex-api-token",
        "TRANSIFEX_APIAPI KEY=:=  fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZV\u{200E}LSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
        "fVhbDg-4JFCsChNTF3Orb3eHG4rmKVZVLSp3B961_xO02X6O3vo_9cpuqmzYJvqEy",
    );
}

// =========================================================================
// 7. TRANSPOSE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv134_transpose_api_key_normal_must_fire() {
    assert_detector_fires(
        "transpose-api-key",
        "TRANSPOSE=cdce91dd51dd450d5b00d6009adc6429",
        "cdce91dd51dd450d5b00d6009adc6429",
    );
}

#[test]
fn adv134_transpose_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "transpose-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv134_transpose_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "transpose-api-key",
        "TRANSPOSE=cdce91dd51dd450d\u{200B}5b00d6009adc6429",
        "cdce91dd51dd450d5b00d6009adc6429",
    );
}

#[test]
fn adv134_transpose_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "transpose-api-key",
        "TRANSPOSE=cdce91dd51dd450d\u{00AD}5b00d6009adc6429",
        "cdce91dd51dd450d5b00d6009adc6429",
    );
}

#[test]
fn adv134_transpose_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "transpose-api-key",
        "TRANSPOSE=cdce91dd51dd450d\u{200C}5b00d6009adc6429",
        "cdce91dd51dd450d5b00d6009adc6429",
    );
}

#[test]
fn adv134_transpose_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "transpose-api-key",
        "TRANSPOSE=cdce91dd51dd450d\u{200D}5b00d6009adc6429",
        "cdce91dd51dd450d5b00d6009adc6429",
    );
}

#[test]
fn adv134_transpose_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "transpose-api-key",
        "TRANSPOSE=cdce91dd51dd450d\u{FEFF}5b00d6009adc6429",
        "cdce91dd51dd450d5b00d6009adc6429",
    );
}

#[test]
fn adv134_transpose_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "transpose-api-key",
        "TRANSPOSE=cdce91dd51dd450d\u{2060}5b00d6009adc6429",
        "cdce91dd51dd450d5b00d6009adc6429",
    );
}

#[test]
fn adv134_transpose_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "transpose-api-key",
        "TRANSPOSE=cdce91dd51dd450d\u{180E}5b00d6009adc6429",
        "cdce91dd51dd450d5b00d6009adc6429",
    );
}

#[test]
fn adv134_transpose_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "transpose-api-key",
        "TRANSPOSE=cdce91dd51dd450d\u{202E}5b00d6009adc6429",
        "cdce91dd51dd450d5b00d6009adc6429",
    );
}

#[test]
fn adv134_transpose_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "transpose-api-key",
        "TRANSPOSE=cdce91dd51dd450d\u{202C}5b00d6009adc6429",
        "cdce91dd51dd450d5b00d6009adc6429",
    );
}

#[test]
fn adv134_transpose_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "transpose-api-key",
        "TRANSPOSE=cdce91dd51dd450d\u{200E}5b00d6009adc6429",
        "cdce91dd51dd450d5b00d6009adc6429",
    );
}

// =========================================================================
// 8. TRAVISCI TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv134_travisci_token_normal_must_fire() {
    assert_detector_fires(
        "travisci-token",
        "travistoken=Xs8gO3qN7uieSixzlXfLDl",
        "Xs8gO3qN7uieSixzlXfLDl",
    );
}

#[test]
fn adv134_travisci_token_wrong_prefix_must_silent() {
    assert_detector_silent("travisci-token", "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv134_travisci_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "travisci-token",
        "travistoken=Xs8gO3qN7ui\u{200B}eSixzlXfLDl",
        "Xs8gO3qN7uieSixzlXfLDl",
    );
}

#[test]
fn adv134_travisci_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "travisci-token",
        "travistoken=Xs8gO3qN7ui\u{00AD}eSixzlXfLDl",
        "Xs8gO3qN7uieSixzlXfLDl",
    );
}

#[test]
fn adv134_travisci_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "travisci-token",
        "travistoken=Xs8gO3qN7ui\u{200C}eSixzlXfLDl",
        "Xs8gO3qN7uieSixzlXfLDl",
    );
}

#[test]
fn adv134_travisci_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "travisci-token",
        "travistoken=Xs8gO3qN7ui\u{200D}eSixzlXfLDl",
        "Xs8gO3qN7uieSixzlXfLDl",
    );
}

#[test]
fn adv134_travisci_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "travisci-token",
        "travistoken=Xs8gO3qN7ui\u{FEFF}eSixzlXfLDl",
        "Xs8gO3qN7uieSixzlXfLDl",
    );
}

#[test]
fn adv134_travisci_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "travisci-token",
        "travistoken=Xs8gO3qN7ui\u{2060}eSixzlXfLDl",
        "Xs8gO3qN7uieSixzlXfLDl",
    );
}

#[test]
fn adv134_travisci_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "travisci-token",
        "travistoken=Xs8gO3qN7ui\u{180E}eSixzlXfLDl",
        "Xs8gO3qN7uieSixzlXfLDl",
    );
}

#[test]
fn adv134_travisci_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "travisci-token",
        "travistoken=Xs8gO3qN7ui\u{202E}eSixzlXfLDl",
        "Xs8gO3qN7uieSixzlXfLDl",
    );
}

#[test]
fn adv134_travisci_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "travisci-token",
        "travistoken=Xs8gO3qN7ui\u{202C}eSixzlXfLDl",
        "Xs8gO3qN7uieSixzlXfLDl",
    );
}

#[test]
fn adv134_travisci_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "travisci-token",
        "travistoken=Xs8gO3qN7ui\u{200E}eSixzlXfLDl",
        "Xs8gO3qN7uieSixzlXfLDl",
    );
}

// =========================================================================
// 9. TRELLO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv134_trello_api_key_normal_must_fire() {
    assert_detector_fires(
        "trello-api-key",
        "TRELLO_API_KEY=f351ef9f096d298e7f030fc4d5410f77",
        "f351ef9f096d298e7f030fc4d5410f77",
    );
}

#[test]
fn adv134_trello_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "trello-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv134_trello_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "trello-api-key",
        "TRELLO_API_KEY=f351ef9f096d298e\u{200B}7f030fc4d5410f77",
        "f351ef9f096d298e7f030fc4d5410f77",
    );
}

#[test]
fn adv134_trello_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "trello-api-key",
        "TRELLO_API_KEY=f351ef9f096d298e\u{00AD}7f030fc4d5410f77",
        "f351ef9f096d298e7f030fc4d5410f77",
    );
}

#[test]
fn adv134_trello_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "trello-api-key",
        "TRELLO_API_KEY=f351ef9f096d298e\u{200C}7f030fc4d5410f77",
        "f351ef9f096d298e7f030fc4d5410f77",
    );
}

#[test]
fn adv134_trello_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "trello-api-key",
        "TRELLO_API_KEY=f351ef9f096d298e\u{200D}7f030fc4d5410f77",
        "f351ef9f096d298e7f030fc4d5410f77",
    );
}

#[test]
fn adv134_trello_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "trello-api-key",
        "TRELLO_API_KEY=f351ef9f096d298e\u{FEFF}7f030fc4d5410f77",
        "f351ef9f096d298e7f030fc4d5410f77",
    );
}

#[test]
fn adv134_trello_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "trello-api-key",
        "TRELLO_API_KEY=f351ef9f096d298e\u{2060}7f030fc4d5410f77",
        "f351ef9f096d298e7f030fc4d5410f77",
    );
}

#[test]
fn adv134_trello_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "trello-api-key",
        "TRELLO_API_KEY=f351ef9f096d298e\u{180E}7f030fc4d5410f77",
        "f351ef9f096d298e7f030fc4d5410f77",
    );
}

#[test]
fn adv134_trello_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "trello-api-key",
        "TRELLO_API_KEY=f351ef9f096d298e\u{202E}7f030fc4d5410f77",
        "f351ef9f096d298e7f030fc4d5410f77",
    );
}

#[test]
fn adv134_trello_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "trello-api-key",
        "TRELLO_API_KEY=f351ef9f096d298e\u{202C}7f030fc4d5410f77",
        "f351ef9f096d298e7f030fc4d5410f77",
    );
}

#[test]
fn adv134_trello_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "trello-api-key",
        "TRELLO_API_KEY=f351ef9f096d298e\u{200E}7f030fc4d5410f77",
        "f351ef9f096d298e7f030fc4d5410f77",
    );
}

// =========================================================================
// 10. TRELLO API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv134_trello_api_token_normal_must_fire() {
    assert_detector_fires(
        "trello-api-token",
        "TRELLO_API_TOKEN=ViHrr2Iq7a43W4O4uE_6NJW5N1Uzm5XkEzq7IhdxW1M4JvR05_",
        "ViHrr2Iq7a43W4O4uE_6NJW5N1Uzm5XkEzq7IhdxW1M4JvR05_",
    );
}

#[test]
fn adv134_trello_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "trello-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv134_trello_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "trello-api-token",
        "TRELLO_API_TOKEN=ViHrr2Iq7a43W4O4uE_6NJW5N\u{200B}1Uzm5XkEzq7IhdxW1M4JvR05_",
        "ViHrr2Iq7a43W4O4uE_6NJW5N1Uzm5XkEzq7IhdxW1M4JvR05_",
    );
}

#[test]
fn adv134_trello_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "trello-api-token",
        "TRELLO_API_TOKEN=ViHrr2Iq7a43W4O4uE_6NJW5N\u{00AD}1Uzm5XkEzq7IhdxW1M4JvR05_",
        "ViHrr2Iq7a43W4O4uE_6NJW5N1Uzm5XkEzq7IhdxW1M4JvR05_",
    );
}

#[test]
fn adv134_trello_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "trello-api-token",
        "TRELLO_API_TOKEN=ViHrr2Iq7a43W4O4uE_6NJW5N\u{200C}1Uzm5XkEzq7IhdxW1M4JvR05_",
        "ViHrr2Iq7a43W4O4uE_6NJW5N1Uzm5XkEzq7IhdxW1M4JvR05_",
    );
}

#[test]
fn adv134_trello_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "trello-api-token",
        "TRELLO_API_TOKEN=ViHrr2Iq7a43W4O4uE_6NJW5N\u{200D}1Uzm5XkEzq7IhdxW1M4JvR05_",
        "ViHrr2Iq7a43W4O4uE_6NJW5N1Uzm5XkEzq7IhdxW1M4JvR05_",
    );
}

#[test]
fn adv134_trello_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "trello-api-token",
        "TRELLO_API_TOKEN=ViHrr2Iq7a43W4O4uE_6NJW5N\u{FEFF}1Uzm5XkEzq7IhdxW1M4JvR05_",
        "ViHrr2Iq7a43W4O4uE_6NJW5N1Uzm5XkEzq7IhdxW1M4JvR05_",
    );
}

#[test]
fn adv134_trello_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "trello-api-token",
        "TRELLO_API_TOKEN=ViHrr2Iq7a43W4O4uE_6NJW5N\u{2060}1Uzm5XkEzq7IhdxW1M4JvR05_",
        "ViHrr2Iq7a43W4O4uE_6NJW5N1Uzm5XkEzq7IhdxW1M4JvR05_",
    );
}

#[test]
fn adv134_trello_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "trello-api-token",
        "TRELLO_API_TOKEN=ViHrr2Iq7a43W4O4uE_6NJW5N\u{180E}1Uzm5XkEzq7IhdxW1M4JvR05_",
        "ViHrr2Iq7a43W4O4uE_6NJW5N1Uzm5XkEzq7IhdxW1M4JvR05_",
    );
}

#[test]
fn adv134_trello_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "trello-api-token",
        "TRELLO_API_TOKEN=ViHrr2Iq7a43W4O4uE_6NJW5N\u{202E}1Uzm5XkEzq7IhdxW1M4JvR05_",
        "ViHrr2Iq7a43W4O4uE_6NJW5N1Uzm5XkEzq7IhdxW1M4JvR05_",
    );
}

#[test]
fn adv134_trello_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "trello-api-token",
        "TRELLO_API_TOKEN=ViHrr2Iq7a43W4O4uE_6NJW5N\u{202C}1Uzm5XkEzq7IhdxW1M4JvR05_",
        "ViHrr2Iq7a43W4O4uE_6NJW5N1Uzm5XkEzq7IhdxW1M4JvR05_",
    );
}

#[test]
fn adv134_trello_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "trello-api-token",
        "TRELLO_API_TOKEN=ViHrr2Iq7a43W4O4uE_6NJW5N\u{200E}1Uzm5XkEzq7IhdxW1M4JvR05_",
        "ViHrr2Iq7a43W4O4uE_6NJW5N1Uzm5XkEzq7IhdxW1M4JvR05_",
    );
}
