//! Part 120 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates pusher, pushover, pypi, qdrant, qualys, questdb, quire, rabbitmq, rabbitmq, radar detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. PUSHER APP KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv120_pusher_app_key_normal_must_fire() {
    assert_detector_fires(
        "pusher-app-key",
        "PUSHER=7a5c6e6b26ccfcb788cb",
        "7a5c6e6b26ccfcb788cb",
    );
}

#[test]
fn adv120_pusher_app_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pusher-app-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv120_pusher_app_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pusher-app-key",
        "PUSHER=7a5c6e6b26\u{200B}ccfcb788cb",
        "7a5c6e6b26ccfcb788cb",
    );
}

#[test]
fn adv120_pusher_app_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pusher-app-key",
        "PUSHER=7a5c6e6b26\u{00AD}ccfcb788cb",
        "7a5c6e6b26ccfcb788cb",
    );
}

#[test]
fn adv120_pusher_app_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "pusher-app-key",
        "PUSHER=7a5c6e6b26\u{200C}ccfcb788cb",
        "7a5c6e6b26ccfcb788cb",
    );
}

#[test]
fn adv120_pusher_app_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "pusher-app-key",
        "PUSHER=7a5c6e6b26\u{200D}ccfcb788cb",
        "7a5c6e6b26ccfcb788cb",
    );
}

#[test]
fn adv120_pusher_app_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "pusher-app-key",
        "PUSHER=7a5c6e6b26\u{FEFF}ccfcb788cb",
        "7a5c6e6b26ccfcb788cb",
    );
}

#[test]
fn adv120_pusher_app_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "pusher-app-key",
        "PUSHER=7a5c6e6b26\u{2060}ccfcb788cb",
        "7a5c6e6b26ccfcb788cb",
    );
}

#[test]
fn adv120_pusher_app_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "pusher-app-key",
        "PUSHER=7a5c6e6b26\u{180E}ccfcb788cb",
        "7a5c6e6b26ccfcb788cb",
    );
}

#[test]
fn adv120_pusher_app_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "pusher-app-key",
        "PUSHER=7a5c6e6b26\u{202E}ccfcb788cb",
        "7a5c6e6b26ccfcb788cb",
    );
}

#[test]
fn adv120_pusher_app_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "pusher-app-key",
        "PUSHER=7a5c6e6b26\u{202C}ccfcb788cb",
        "7a5c6e6b26ccfcb788cb",
    );
}

#[test]
fn adv120_pusher_app_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "pusher-app-key",
        "PUSHER=7a5c6e6b26\u{200E}ccfcb788cb",
        "7a5c6e6b26ccfcb788cb",
    );
}

// =========================================================================
// 2. PUSHOVER API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv120_pushover_api_token_normal_must_fire() {
    assert_detector_fires(
        "pushover-api-token",
        "PUSHOVER=l8dsz97oo5zeergzqx722ts6yr68z8",
        "l8dsz97oo5zeergzqx722ts6yr68z8",
    );
}

#[test]
fn adv120_pushover_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pushover-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv120_pushover_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pushover-api-token",
        "PUSHOVER=l8dsz97oo5zeerg\u{200B}zqx722ts6yr68z8",
        "l8dsz97oo5zeergzqx722ts6yr68z8",
    );
}

#[test]
fn adv120_pushover_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pushover-api-token",
        "PUSHOVER=l8dsz97oo5zeerg\u{00AD}zqx722ts6yr68z8",
        "l8dsz97oo5zeergzqx722ts6yr68z8",
    );
}

#[test]
fn adv120_pushover_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "pushover-api-token",
        "PUSHOVER=l8dsz97oo5zeerg\u{200C}zqx722ts6yr68z8",
        "l8dsz97oo5zeergzqx722ts6yr68z8",
    );
}

#[test]
fn adv120_pushover_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "pushover-api-token",
        "PUSHOVER=l8dsz97oo5zeerg\u{200D}zqx722ts6yr68z8",
        "l8dsz97oo5zeergzqx722ts6yr68z8",
    );
}

#[test]
fn adv120_pushover_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "pushover-api-token",
        "PUSHOVER=l8dsz97oo5zeerg\u{FEFF}zqx722ts6yr68z8",
        "l8dsz97oo5zeergzqx722ts6yr68z8",
    );
}

#[test]
fn adv120_pushover_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "pushover-api-token",
        "PUSHOVER=l8dsz97oo5zeerg\u{2060}zqx722ts6yr68z8",
        "l8dsz97oo5zeergzqx722ts6yr68z8",
    );
}

#[test]
fn adv120_pushover_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "pushover-api-token",
        "PUSHOVER=l8dsz97oo5zeerg\u{180E}zqx722ts6yr68z8",
        "l8dsz97oo5zeergzqx722ts6yr68z8",
    );
}

#[test]
fn adv120_pushover_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "pushover-api-token",
        "PUSHOVER=l8dsz97oo5zeerg\u{202E}zqx722ts6yr68z8",
        "l8dsz97oo5zeergzqx722ts6yr68z8",
    );
}

#[test]
fn adv120_pushover_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "pushover-api-token",
        "PUSHOVER=l8dsz97oo5zeerg\u{202C}zqx722ts6yr68z8",
        "l8dsz97oo5zeergzqx722ts6yr68z8",
    );
}

#[test]
fn adv120_pushover_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "pushover-api-token",
        "PUSHOVER=l8dsz97oo5zeerg\u{200E}zqx722ts6yr68z8",
        "l8dsz97oo5zeergzqx722ts6yr68z8",
    );
}

// =========================================================================
// 3. PYPI API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv120_pypi_api_token_normal_must_fire() {
    assert_detector_fires(
        "pypi-api-token",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
    );
}

#[test]
fn adv120_pypi_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pypi-api-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv120_pypi_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pypi-api-token",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn\u{200B}7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
    );
}

#[test]
fn adv120_pypi_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pypi-api-token",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn\u{00AD}7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
    );
}

#[test]
fn adv120_pypi_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "pypi-api-token",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn\u{200C}7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
    );
}

#[test]
fn adv120_pypi_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "pypi-api-token",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn\u{200D}7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
    );
}

#[test]
fn adv120_pypi_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "pypi-api-token",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn\u{FEFF}7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
    );
}

#[test]
fn adv120_pypi_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "pypi-api-token",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn\u{2060}7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
    );
}

#[test]
fn adv120_pypi_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "pypi-api-token",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn\u{180E}7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
    );
}

#[test]
fn adv120_pypi_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "pypi-api-token",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn\u{202E}7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
    );
}

#[test]
fn adv120_pypi_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "pypi-api-token",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn\u{202C}7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
    );
}

#[test]
fn adv120_pypi_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "pypi-api-token",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn\u{200E}7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
    );
}

// =========================================================================
// 4. QDRANT API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv120_qdrant_api_key_normal_must_fire() {
    assert_detector_fires(
        "qdrant-api-key",
        "QDRANT_API_KEY=qrp1jXxt6sBi2v6e",
        "qrp1jXxt6sBi2v6e",
    );
}

#[test]
fn adv120_qdrant_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "qdrant-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv120_qdrant_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "qdrant-api-key",
        "QDRANT_API_KEY=qrp1jXxt\u{200B}6sBi2v6e",
        "qrp1jXxt6sBi2v6e",
    );
}

#[test]
fn adv120_qdrant_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "qdrant-api-key",
        "QDRANT_API_KEY=qrp1jXxt\u{00AD}6sBi2v6e",
        "qrp1jXxt6sBi2v6e",
    );
}

#[test]
fn adv120_qdrant_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "qdrant-api-key",
        "QDRANT_API_KEY=qrp1jXxt\u{200C}6sBi2v6e",
        "qrp1jXxt6sBi2v6e",
    );
}

#[test]
fn adv120_qdrant_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "qdrant-api-key",
        "QDRANT_API_KEY=qrp1jXxt\u{200D}6sBi2v6e",
        "qrp1jXxt6sBi2v6e",
    );
}

#[test]
fn adv120_qdrant_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "qdrant-api-key",
        "QDRANT_API_KEY=qrp1jXxt\u{FEFF}6sBi2v6e",
        "qrp1jXxt6sBi2v6e",
    );
}

#[test]
fn adv120_qdrant_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "qdrant-api-key",
        "QDRANT_API_KEY=qrp1jXxt\u{2060}6sBi2v6e",
        "qrp1jXxt6sBi2v6e",
    );
}

#[test]
fn adv120_qdrant_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "qdrant-api-key",
        "QDRANT_API_KEY=qrp1jXxt\u{180E}6sBi2v6e",
        "qrp1jXxt6sBi2v6e",
    );
}

#[test]
fn adv120_qdrant_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "qdrant-api-key",
        "QDRANT_API_KEY=qrp1jXxt\u{202E}6sBi2v6e",
        "qrp1jXxt6sBi2v6e",
    );
}

#[test]
fn adv120_qdrant_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "qdrant-api-key",
        "QDRANT_API_KEY=qrp1jXxt\u{202C}6sBi2v6e",
        "qrp1jXxt6sBi2v6e",
    );
}

#[test]
fn adv120_qdrant_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "qdrant-api-key",
        "QDRANT_API_KEY=qrp1jXxt\u{200E}6sBi2v6e",
        "qrp1jXxt6sBi2v6e",
    );
}

// =========================================================================
// 5. QUALYS API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv120_qualys_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "qualys-api-credentials",
        "QUALYS: Ebbt5xjwLUIN",
        "Ebbt5xjwLUIN",
    );
}

#[test]
fn adv120_qualys_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "qualys-api-credentials",
        "dummy_prefix_0: xxxxxxxxxxxx",
    );
}

#[test]
fn adv120_qualys_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "qualys-api-credentials",
        "QUALYS: Ebbt5x\u{200B}jwLUIN",
        "Ebbt5xjwLUIN",
    );
}

#[test]
fn adv120_qualys_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "qualys-api-credentials",
        "QUALYS: Ebbt5x\u{00AD}jwLUIN",
        "Ebbt5xjwLUIN",
    );
}

#[test]
fn adv120_qualys_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "qualys-api-credentials",
        "QUALYS: Ebbt5x\u{200C}jwLUIN",
        "Ebbt5xjwLUIN",
    );
}

#[test]
fn adv120_qualys_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "qualys-api-credentials",
        "QUALYS: Ebbt5x\u{200D}jwLUIN",
        "Ebbt5xjwLUIN",
    );
}

#[test]
fn adv120_qualys_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "qualys-api-credentials",
        "QUALYS: Ebbt5x\u{FEFF}jwLUIN",
        "Ebbt5xjwLUIN",
    );
}

#[test]
fn adv120_qualys_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "qualys-api-credentials",
        "QUALYS: Ebbt5x\u{2060}jwLUIN",
        "Ebbt5xjwLUIN",
    );
}

#[test]
fn adv120_qualys_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "qualys-api-credentials",
        "QUALYS: Ebbt5x\u{180E}jwLUIN",
        "Ebbt5xjwLUIN",
    );
}

#[test]
fn adv120_qualys_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "qualys-api-credentials",
        "QUALYS: Ebbt5x\u{202E}jwLUIN",
        "Ebbt5xjwLUIN",
    );
}

#[test]
fn adv120_qualys_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "qualys-api-credentials",
        "QUALYS: Ebbt5x\u{202C}jwLUIN",
        "Ebbt5xjwLUIN",
    );
}

#[test]
fn adv120_qualys_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "qualys-api-credentials",
        "QUALYS: Ebbt5x\u{200E}jwLUIN",
        "Ebbt5xjwLUIN",
    );
}

// =========================================================================
// 6. QUESTDB CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv120_questdb_credentials_normal_must_fire() {
    assert_detector_fires(
        "questdb-credentials",
        "QUESTDB_URL=postgresql://quest:QuestPass123@db.example.com:8812/qdb",
        "QuestPass123",
    );
}

#[test]
fn adv120_questdb_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "questdb-credentials",
        "dummy_prefix_0 =xostgresql://quest:xxxxxxxxxxxx@db.example.com:8812/qdb",
    );
}

#[test]
fn adv120_questdb_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "questdb-credentials",
        "QUESTDB_URL=postgresql://quest:QuestP\u{200B}ass123@db.example.com:8812/qdb",
        "QuestPass123",
    );
}

#[test]
fn adv120_questdb_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "questdb-credentials",
        "QUESTDB_URL=postgresql://quest:QuestP\u{00AD}ass123@db.example.com:8812/qdb",
        "QuestPass123",
    );
}

#[test]
fn adv120_questdb_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "questdb-credentials",
        "QUESTDB_URL=postgresql://quest:QuestP\u{200C}ass123@db.example.com:8812/qdb",
        "QuestPass123",
    );
}

#[test]
fn adv120_questdb_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "questdb-credentials",
        "QUESTDB_URL=postgresql://quest:QuestP\u{200D}ass123@db.example.com:8812/qdb",
        "QuestPass123",
    );
}

#[test]
fn adv120_questdb_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "questdb-credentials",
        "QUESTDB_URL=postgresql://quest:QuestP\u{FEFF}ass123@db.example.com:8812/qdb",
        "QuestPass123",
    );
}

#[test]
fn adv120_questdb_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "questdb-credentials",
        "QUESTDB_URL=postgresql://quest:QuestP\u{2060}ass123@db.example.com:8812/qdb",
        "QuestPass123",
    );
}

#[test]
fn adv120_questdb_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "questdb-credentials",
        "QUESTDB_URL=postgresql://quest:QuestP\u{180E}ass123@db.example.com:8812/qdb",
        "QuestPass123",
    );
}

#[test]
fn adv120_questdb_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "questdb-credentials",
        "QUESTDB_URL=postgresql://quest:QuestP\u{202E}ass123@db.example.com:8812/qdb",
        "QuestPass123",
    );
}

#[test]
fn adv120_questdb_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "questdb-credentials",
        "QUESTDB_URL=postgresql://quest:QuestP\u{202C}ass123@db.example.com:8812/qdb",
        "QuestPass123",
    );
}

#[test]
fn adv120_questdb_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "questdb-credentials",
        "QUESTDB_URL=postgresql://quest:QuestP\u{200E}ass123@db.example.com:8812/qdb",
        "QuestPass123",
    );
}

// =========================================================================
// 7. QUIRE ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv120_quire_access_token_normal_must_fire() {
    assert_detector_fires(
        "quire-access-token",
        "QUIRE_ACCESS_TOKEN=eE8XKMnpZdyWVAXwaoLEANLxlrPMqNHPvp01FjDSnhwpVmwm",
        "eE8XKMnpZdyWVAXwaoLEANLxlrPMqNHPvp01FjDSnhwpVmwm",
    );
}

#[test]
fn adv120_quire_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "quire-access-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv120_quire_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "quire-access-token",
        "QUIRE_ACCESS_TOKEN=eE8XKMnpZdyWVAXwaoLEANLx\u{200B}lrPMqNHPvp01FjDSnhwpVmwm",
        "eE8XKMnpZdyWVAXwaoLEANLxlrPMqNHPvp01FjDSnhwpVmwm",
    );
}

#[test]
fn adv120_quire_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "quire-access-token",
        "QUIRE_ACCESS_TOKEN=eE8XKMnpZdyWVAXwaoLEANLx\u{00AD}lrPMqNHPvp01FjDSnhwpVmwm",
        "eE8XKMnpZdyWVAXwaoLEANLxlrPMqNHPvp01FjDSnhwpVmwm",
    );
}

#[test]
fn adv120_quire_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "quire-access-token",
        "QUIRE_ACCESS_TOKEN=eE8XKMnpZdyWVAXwaoLEANLx\u{200C}lrPMqNHPvp01FjDSnhwpVmwm",
        "eE8XKMnpZdyWVAXwaoLEANLxlrPMqNHPvp01FjDSnhwpVmwm",
    );
}

#[test]
fn adv120_quire_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "quire-access-token",
        "QUIRE_ACCESS_TOKEN=eE8XKMnpZdyWVAXwaoLEANLx\u{200D}lrPMqNHPvp01FjDSnhwpVmwm",
        "eE8XKMnpZdyWVAXwaoLEANLxlrPMqNHPvp01FjDSnhwpVmwm",
    );
}

#[test]
fn adv120_quire_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "quire-access-token",
        "QUIRE_ACCESS_TOKEN=eE8XKMnpZdyWVAXwaoLEANLx\u{FEFF}lrPMqNHPvp01FjDSnhwpVmwm",
        "eE8XKMnpZdyWVAXwaoLEANLxlrPMqNHPvp01FjDSnhwpVmwm",
    );
}

#[test]
fn adv120_quire_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "quire-access-token",
        "QUIRE_ACCESS_TOKEN=eE8XKMnpZdyWVAXwaoLEANLx\u{2060}lrPMqNHPvp01FjDSnhwpVmwm",
        "eE8XKMnpZdyWVAXwaoLEANLxlrPMqNHPvp01FjDSnhwpVmwm",
    );
}

#[test]
fn adv120_quire_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "quire-access-token",
        "QUIRE_ACCESS_TOKEN=eE8XKMnpZdyWVAXwaoLEANLx\u{180E}lrPMqNHPvp01FjDSnhwpVmwm",
        "eE8XKMnpZdyWVAXwaoLEANLxlrPMqNHPvp01FjDSnhwpVmwm",
    );
}

#[test]
fn adv120_quire_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "quire-access-token",
        "QUIRE_ACCESS_TOKEN=eE8XKMnpZdyWVAXwaoLEANLx\u{202E}lrPMqNHPvp01FjDSnhwpVmwm",
        "eE8XKMnpZdyWVAXwaoLEANLxlrPMqNHPvp01FjDSnhwpVmwm",
    );
}

#[test]
fn adv120_quire_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "quire-access-token",
        "QUIRE_ACCESS_TOKEN=eE8XKMnpZdyWVAXwaoLEANLx\u{202C}lrPMqNHPvp01FjDSnhwpVmwm",
        "eE8XKMnpZdyWVAXwaoLEANLxlrPMqNHPvp01FjDSnhwpVmwm",
    );
}

#[test]
fn adv120_quire_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "quire-access-token",
        "QUIRE_ACCESS_TOKEN=eE8XKMnpZdyWVAXwaoLEANLx\u{200E}lrPMqNHPvp01FjDSnhwpVmwm",
        "eE8XKMnpZdyWVAXwaoLEANLxlrPMqNHPvp01FjDSnhwpVmwm",
    );
}

// =========================================================================
// 8. RABBITMQ CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv120_rabbitmq_credentials_normal_must_fire() {
    assert_detector_fires(
        "rabbitmq-credentials",
        "amqp://user:SecretPass123456@rabbitmq.example.com:5672/vhost",
        "SecretPass123456",
    );
}

#[test]
fn adv120_rabbitmq_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rabbitmq-credentials",
        "dummy_prefix_0://user:xxxxxxxxxxxxxxxx@rabbitmq.example.com:5672/vhost",
    );
}

#[test]
fn adv120_rabbitmq_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rabbitmq-credentials",
        "amqp://user:SecretPa\u{200B}ss123456@rabbitmq.example.com:5672/vhost",
        "SecretPass123456",
    );
}

#[test]
fn adv120_rabbitmq_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rabbitmq-credentials",
        "amqp://user:SecretPa\u{00AD}ss123456@rabbitmq.example.com:5672/vhost",
        "SecretPass123456",
    );
}

#[test]
fn adv120_rabbitmq_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "rabbitmq-credentials",
        "amqp://user:SecretPa\u{200C}ss123456@rabbitmq.example.com:5672/vhost",
        "SecretPass123456",
    );
}

#[test]
fn adv120_rabbitmq_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "rabbitmq-credentials",
        "amqp://user:SecretPa\u{200D}ss123456@rabbitmq.example.com:5672/vhost",
        "SecretPass123456",
    );
}

#[test]
fn adv120_rabbitmq_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "rabbitmq-credentials",
        "amqp://user:SecretPa\u{FEFF}ss123456@rabbitmq.example.com:5672/vhost",
        "SecretPass123456",
    );
}

#[test]
fn adv120_rabbitmq_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "rabbitmq-credentials",
        "amqp://user:SecretPa\u{2060}ss123456@rabbitmq.example.com:5672/vhost",
        "SecretPass123456",
    );
}

#[test]
fn adv120_rabbitmq_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "rabbitmq-credentials",
        "amqp://user:SecretPa\u{180E}ss123456@rabbitmq.example.com:5672/vhost",
        "SecretPass123456",
    );
}

#[test]
fn adv120_rabbitmq_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "rabbitmq-credentials",
        "amqp://user:SecretPa\u{202E}ss123456@rabbitmq.example.com:5672/vhost",
        "SecretPass123456",
    );
}

#[test]
fn adv120_rabbitmq_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "rabbitmq-credentials",
        "amqp://user:SecretPa\u{202C}ss123456@rabbitmq.example.com:5672/vhost",
        "SecretPass123456",
    );
}

#[test]
fn adv120_rabbitmq_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "rabbitmq-credentials",
        "amqp://user:SecretPa\u{200E}ss123456@rabbitmq.example.com:5672/vhost",
        "SecretPass123456",
    );
}

// =========================================================================
// 9. RABBITMQ MANAGEMENT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv120_rabbitmq_management_credentials_normal_must_fire() {
    assert_detector_fires(
        "rabbitmq-management-credentials",
        "RABBITMQ_USER=`nsHW",
        "`nsHW",
    );
}

#[test]
fn adv120_rabbitmq_management_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rabbitmq-management-credentials",
        "dummy_prefix_0 =xxxxx",
    );
}

#[test]
fn adv120_rabbitmq_management_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rabbitmq-management-credentials",
        "RABBITMQ_USER=`n\u{200B}sHW",
        "`nsHW",
    );
}

#[test]
fn adv120_rabbitmq_management_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rabbitmq-management-credentials",
        "RABBITMQ_USER=`n\u{00AD}sHW",
        "`nsHW",
    );
}

#[test]
fn adv120_rabbitmq_management_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "rabbitmq-management-credentials",
        "RABBITMQ_USER=`n\u{200C}sHW",
        "`nsHW",
    );
}

#[test]
fn adv120_rabbitmq_management_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "rabbitmq-management-credentials",
        "RABBITMQ_USER=`n\u{200D}sHW",
        "`nsHW",
    );
}

#[test]
fn adv120_rabbitmq_management_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "rabbitmq-management-credentials",
        "RABBITMQ_USER=`n\u{FEFF}sHW",
        "`nsHW",
    );
}

#[test]
fn adv120_rabbitmq_management_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "rabbitmq-management-credentials",
        "RABBITMQ_USER=`n\u{2060}sHW",
        "`nsHW",
    );
}

#[test]
fn adv120_rabbitmq_management_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "rabbitmq-management-credentials",
        "RABBITMQ_USER=`n\u{180E}sHW",
        "`nsHW",
    );
}

#[test]
fn adv120_rabbitmq_management_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "rabbitmq-management-credentials",
        "RABBITMQ_USER=`n\u{202E}sHW",
        "`nsHW",
    );
}

#[test]
fn adv120_rabbitmq_management_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "rabbitmq-management-credentials",
        "RABBITMQ_USER=`n\u{202C}sHW",
        "`nsHW",
    );
}

#[test]
fn adv120_rabbitmq_management_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "rabbitmq-management-credentials",
        "RABBITMQ_USER=`n\u{200E}sHW",
        "`nsHW",
    );
}

// =========================================================================
// 10. RADAR IO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv120_radar_io_api_key_normal_must_fire() {
    assert_detector_fires(
        "radar-io-api-key",
        "prj_live_eZXI8wIQE11eWntR0gMwrohdFkqbTcI4npM6AovMe5Wowx31UK",
        "prj_live_eZXI8wIQE11eWntR0gMwrohdFkqbTcI4npM6AovMe5Wowx31UK",
    );
}

#[test]
fn adv120_radar_io_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "radar-io-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv120_radar_io_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "radar-io-api-key",
        "prj_live_eZXI8wIQE11eWntR0gMw\u{200B}rohdFkqbTcI4npM6AovMe5Wowx31UK",
        "prj_live_eZXI8wIQE11eWntR0gMwrohdFkqbTcI4npM6AovMe5Wowx31UK",
    );
}

#[test]
fn adv120_radar_io_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "radar-io-api-key",
        "prj_live_eZXI8wIQE11eWntR0gMw\u{00AD}rohdFkqbTcI4npM6AovMe5Wowx31UK",
        "prj_live_eZXI8wIQE11eWntR0gMwrohdFkqbTcI4npM6AovMe5Wowx31UK",
    );
}

#[test]
fn adv120_radar_io_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "radar-io-api-key",
        "prj_live_eZXI8wIQE11eWntR0gMw\u{200C}rohdFkqbTcI4npM6AovMe5Wowx31UK",
        "prj_live_eZXI8wIQE11eWntR0gMwrohdFkqbTcI4npM6AovMe5Wowx31UK",
    );
}

#[test]
fn adv120_radar_io_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "radar-io-api-key",
        "prj_live_eZXI8wIQE11eWntR0gMw\u{200D}rohdFkqbTcI4npM6AovMe5Wowx31UK",
        "prj_live_eZXI8wIQE11eWntR0gMwrohdFkqbTcI4npM6AovMe5Wowx31UK",
    );
}

#[test]
fn adv120_radar_io_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "radar-io-api-key",
        "prj_live_eZXI8wIQE11eWntR0gMw\u{FEFF}rohdFkqbTcI4npM6AovMe5Wowx31UK",
        "prj_live_eZXI8wIQE11eWntR0gMwrohdFkqbTcI4npM6AovMe5Wowx31UK",
    );
}

#[test]
fn adv120_radar_io_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "radar-io-api-key",
        "prj_live_eZXI8wIQE11eWntR0gMw\u{2060}rohdFkqbTcI4npM6AovMe5Wowx31UK",
        "prj_live_eZXI8wIQE11eWntR0gMwrohdFkqbTcI4npM6AovMe5Wowx31UK",
    );
}

#[test]
fn adv120_radar_io_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "radar-io-api-key",
        "prj_live_eZXI8wIQE11eWntR0gMw\u{180E}rohdFkqbTcI4npM6AovMe5Wowx31UK",
        "prj_live_eZXI8wIQE11eWntR0gMwrohdFkqbTcI4npM6AovMe5Wowx31UK",
    );
}

#[test]
fn adv120_radar_io_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "radar-io-api-key",
        "prj_live_eZXI8wIQE11eWntR0gMw\u{202E}rohdFkqbTcI4npM6AovMe5Wowx31UK",
        "prj_live_eZXI8wIQE11eWntR0gMwrohdFkqbTcI4npM6AovMe5Wowx31UK",
    );
}

#[test]
fn adv120_radar_io_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "radar-io-api-key",
        "prj_live_eZXI8wIQE11eWntR0gMw\u{202C}rohdFkqbTcI4npM6AovMe5Wowx31UK",
        "prj_live_eZXI8wIQE11eWntR0gMwrohdFkqbTcI4npM6AovMe5Wowx31UK",
    );
}

#[test]
fn adv120_radar_io_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "radar-io-api-key",
        "prj_live_eZXI8wIQE11eWntR0gMw\u{200E}rohdFkqbTcI4npM6AovMe5Wowx31UK",
        "prj_live_eZXI8wIQE11eWntR0gMwrohdFkqbTcI4npM6AovMe5Wowx31UK",
    );
}


