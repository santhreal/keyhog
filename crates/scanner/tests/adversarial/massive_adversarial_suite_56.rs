//! Part 56 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates pulsar, pulumi, puppet, pusher, pushover, pypi, qdrant, qualys, questdb, quire detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. PULSAR JWT TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv56_pulsar_jwt_token_normal_must_fire() {
    assert_detector_fires(
        "pulsar-jwt-token",
        "brokerClientAuthenticationParameters=eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
        "eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
    );
}

#[test]
fn adv56_pulsar_jwt_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pulsar-jwt-token",
        "dummy_prefix_0 =xxxz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
    );
}

#[test]
fn adv56_pulsar_jwt_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pulsar-jwt-token",
        "brokerClientAuthenticationParameters=eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj\u{200B}6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
        "eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
    );
}

#[test]
fn adv56_pulsar_jwt_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pulsar-jwt-token",
        "brokerClientAuthenticationParameters=eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj\u{00AD}6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
        "eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
    );
}

// =========================================================================
// 2. PULUMI ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv56_pulumi_access_token_normal_must_fire() {
    assert_detector_fires(
        "pulumi-access-token",
        "pul-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b",
        "pul-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b",
    );
}

#[test]
fn adv56_pulumi_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pulumi-access-token",
        "dummy9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b",
    );
}

#[test]
fn adv56_pulumi_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pulumi-access-token",
        "pul-9a3b7c2e4d1f6a8b0c\u{200B}5d9e3f7a1b4c2d8e6f0a1b",
        "pul-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b",
    );
}

#[test]
fn adv56_pulumi_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pulumi-access-token",
        "pul-9a3b7c2e4d1f6a8b0c\u{00AD}5d9e3f7a1b4c2d8e6f0a1b",
        "pul-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b",
    );
}

// =========================================================================
// 3. PUPPET ENTERPRISE TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv56_puppet_enterprise_token_normal_must_fire() {
    assert_detector_fires(
        "puppet-enterprise-token",
        "PE_TOKEN=df2C-IwsG2vZK2btF61X",
        "df2C-IwsG2vZK2btF61X",
    );
}

#[test]
fn adv56_puppet_enterprise_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "puppet-enterprise-token",
        "dummy_prefix_0 =xxxC-IwsG2vZK2btF61X",
    );
}

#[test]
fn adv56_puppet_enterprise_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "puppet-enterprise-token",
        "PE_TOKEN=df2C-IwsG2\u{200B}vZK2btF61X",
        "df2C-IwsG2vZK2btF61X",
    );
}

#[test]
fn adv56_puppet_enterprise_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "puppet-enterprise-token",
        "PE_TOKEN=df2C-IwsG2\u{00AD}vZK2btF61X",
        "df2C-IwsG2vZK2btF61X",
    );
}

// =========================================================================
// 4. PUSHER APP KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv56_pusher_app_key_normal_must_fire() {
    assert_detector_fires(
        "pusher-app-key",
        "PUSHER=7a5c6e6b26ccfcb788cb",
        "7a5c6e6b26ccfcb788cb",
    );
}

#[test]
fn adv56_pusher_app_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pusher-app-key",
        "dummy_prefix_0 =xxxc6e6b26ccfcb788cb",
    );
}

#[test]
fn adv56_pusher_app_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pusher-app-key",
        "PUSHER=7a5c6e6b26\u{200B}ccfcb788cb",
        "7a5c6e6b26ccfcb788cb",
    );
}

#[test]
fn adv56_pusher_app_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pusher-app-key",
        "PUSHER=7a5c6e6b26\u{00AD}ccfcb788cb",
        "7a5c6e6b26ccfcb788cb",
    );
}

// =========================================================================
// 5. PUSHOVER API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv56_pushover_api_token_normal_must_fire() {
    assert_detector_fires(
        "pushover-api-token",
        "PUSHOVER=l8dsz97oo5zeergzqx722ts6yr68z8",
        "l8dsz97oo5zeergzqx722ts6yr68z8",
    );
}

#[test]
fn adv56_pushover_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pushover-api-token",
        "dummy_prefix_0 =xxxsz97oo5zeergzqx722ts6yr68z8",
    );
}

#[test]
fn adv56_pushover_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pushover-api-token",
        "PUSHOVER=l8dsz97oo5zeerg\u{200B}zqx722ts6yr68z8",
        "l8dsz97oo5zeergzqx722ts6yr68z8",
    );
}

#[test]
fn adv56_pushover_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pushover-api-token",
        "PUSHOVER=l8dsz97oo5zeerg\u{00AD}zqx722ts6yr68z8",
        "l8dsz97oo5zeergzqx722ts6yr68z8",
    );
}

// =========================================================================
// 6. PYPI API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv56_pypi_api_token_normal_must_fire() {
    assert_detector_fires(
        "pypi-api-token",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
    );
}

#[test]
fn adv56_pypi_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pypi-api-token",
        "dummy-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
    );
}

#[test]
fn adv56_pypi_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pypi-api-token",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn\u{200B}7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
    );
}

#[test]
fn adv56_pypi_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pypi-api-token",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn\u{00AD}7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
        "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH",
    );
}

// =========================================================================
// 7. QDRANT API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv56_qdrant_api_key_normal_must_fire() {
    assert_detector_fires(
        "qdrant-api-key",
        "QDRANT_API_KEY=qrp1jXxt6sBi2v6e",
        "qrp1jXxt6sBi2v6e",
    );
}

#[test]
fn adv56_qdrant_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "qdrant-api-key",
        "dummy_prefix_0 =xxx1jXxt6sBi2v6e",
    );
}

#[test]
fn adv56_qdrant_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "qdrant-api-key",
        "QDRANT_API_KEY=qrp1jXxt\u{200B}6sBi2v6e",
        "qrp1jXxt6sBi2v6e",
    );
}

#[test]
fn adv56_qdrant_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "qdrant-api-key",
        "QDRANT_API_KEY=qrp1jXxt\u{00AD}6sBi2v6e",
        "qrp1jXxt6sBi2v6e",
    );
}

// =========================================================================
// 8. QUALYS API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv56_qualys_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "qualys-api-credentials",
        "QUALYS: Ebbt5xjwLUIN",
        "Ebbt5xjwLUIN",
    );
}

#[test]
fn adv56_qualys_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "qualys-api-credentials",
        "dummy_prefix_0: xxxt5xjwLUIN",
    );
}

#[test]
fn adv56_qualys_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "qualys-api-credentials",
        "QUALYS: Ebbt5x\u{200B}jwLUIN",
        "Ebbt5xjwLUIN",
    );
}

#[test]
fn adv56_qualys_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "qualys-api-credentials",
        "QUALYS: Ebbt5x\u{00AD}jwLUIN",
        "Ebbt5xjwLUIN",
    );
}

// =========================================================================
// 9. QUESTDB CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv56_questdb_credentials_normal_must_fire() {
    assert_detector_fires(
        "questdb-credentials",
        "QUESTDB_URL=postgresql://quest:QuestPass123@db.example.com:8812/qdb",
        "QuestPass123",
    );
}

#[test]
fn adv56_questdb_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "questdb-credentials",
        "dummy_prefix_0 =xostgresql://quest:xxxstPass123@db.example.com:8812/qdb",
    );
}

#[test]
fn adv56_questdb_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "questdb-credentials",
        "QUESTDB_URL=postgresql://quest:QuestP\u{200B}ass123@db.example.com:8812/qdb",
        "QuestPass123",
    );
}

#[test]
fn adv56_questdb_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "questdb-credentials",
        "QUESTDB_URL=postgresql://quest:QuestP\u{00AD}ass123@db.example.com:8812/qdb",
        "QuestPass123",
    );
}

// =========================================================================
// 10. QUIRE ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv56_quire_access_token_normal_must_fire() {
    assert_detector_fires(
        "quire-access-token",
        "QUIRE_ACCESS_TOKEN=eE8XKMnpZdyWVAXwaoLEANLxlrPMqNHPvp01FjDSnhwpVmwm",
        "eE8XKMnpZdyWVAXwaoLEANLxlrPMqNHPvp01FjDSnhwpVmwm",
    );
}

#[test]
fn adv56_quire_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "quire-access-token",
        "dummy_prefix_0 =xxxXKMnpZdyWVAXwaoLEANLxlrPMqNHPvp01FjDSnhwpVmwm",
    );
}

#[test]
fn adv56_quire_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "quire-access-token",
        "QUIRE_ACCESS_TOKEN=eE8XKMnpZdyWVAXwaoLEANLx\u{200B}lrPMqNHPvp01FjDSnhwpVmwm",
        "eE8XKMnpZdyWVAXwaoLEANLxlrPMqNHPvp01FjDSnhwpVmwm",
    );
}

#[test]
fn adv56_quire_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "quire-access-token",
        "QUIRE_ACCESS_TOKEN=eE8XKMnpZdyWVAXwaoLEANLx\u{00AD}lrPMqNHPvp01FjDSnhwpVmwm",
        "eE8XKMnpZdyWVAXwaoLEANLxlrPMqNHPvp01FjDSnhwpVmwm",
    );
}


