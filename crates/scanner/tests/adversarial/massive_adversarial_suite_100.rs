//! Part 100 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates kamatera, keycdn, keycloak, keystonejs, kiwi, klaviyo, kubernetes, kubernetes, lambdatest, langsmith detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. KAMATERA API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv100_kamatera_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "kamatera-api-credentials",
        "KAMATERA_API_CLIENT_ID=lPtOY5UwpbrP26wy",
        "lPtOY5UwpbrP26wy",
    );
}

#[test]
fn adv100_kamatera_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "kamatera-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv100_kamatera_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "kamatera-api-credentials",
        "KAMATERA_API_CLIENT_ID=lPtOY5Uw\u{200B}pbrP26wy",
        "lPtOY5UwpbrP26wy",
    );
}

#[test]
fn adv100_kamatera_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "kamatera-api-credentials",
        "KAMATERA_API_CLIENT_ID=lPtOY5Uw\u{00AD}pbrP26wy",
        "lPtOY5UwpbrP26wy",
    );
}

#[test]
fn adv100_kamatera_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "kamatera-api-credentials",
        "KAMATERA_API_CLIENT_ID=lPtOY5Uw\u{200C}pbrP26wy",
        "lPtOY5UwpbrP26wy",
    );
}

#[test]
fn adv100_kamatera_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "kamatera-api-credentials",
        "KAMATERA_API_CLIENT_ID=lPtOY5Uw\u{200D}pbrP26wy",
        "lPtOY5UwpbrP26wy",
    );
}

#[test]
fn adv100_kamatera_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "kamatera-api-credentials",
        "KAMATERA_API_CLIENT_ID=lPtOY5Uw\u{FEFF}pbrP26wy",
        "lPtOY5UwpbrP26wy",
    );
}

#[test]
fn adv100_kamatera_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "kamatera-api-credentials",
        "KAMATERA_API_CLIENT_ID=lPtOY5Uw\u{2060}pbrP26wy",
        "lPtOY5UwpbrP26wy",
    );
}

#[test]
fn adv100_kamatera_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "kamatera-api-credentials",
        "KAMATERA_API_CLIENT_ID=lPtOY5Uw\u{180E}pbrP26wy",
        "lPtOY5UwpbrP26wy",
    );
}

#[test]
fn adv100_kamatera_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "kamatera-api-credentials",
        "KAMATERA_API_CLIENT_ID=lPtOY5Uw\u{202E}pbrP26wy",
        "lPtOY5UwpbrP26wy",
    );
}

#[test]
fn adv100_kamatera_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "kamatera-api-credentials",
        "KAMATERA_API_CLIENT_ID=lPtOY5Uw\u{202C}pbrP26wy",
        "lPtOY5UwpbrP26wy",
    );
}

#[test]
fn adv100_kamatera_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "kamatera-api-credentials",
        "KAMATERA_API_CLIENT_ID=lPtOY5Uw\u{200E}pbrP26wy",
        "lPtOY5UwpbrP26wy",
    );
}

// =========================================================================
// 2. KEYCDN API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv100_keycdn_api_key_normal_must_fire() {
    assert_detector_fires(
        "keycdn-api-key",
        "KEYCDN_API_KEY=98a6d7ef4d61aa77f78b7f2ceec670e21f05783f",
        "98a6d7ef4d61aa77f78b7f2ceec670e21f05783f",
    );
}

#[test]
fn adv100_keycdn_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "keycdn-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv100_keycdn_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "keycdn-api-key",
        "KEYCDN_API_KEY=98a6d7ef4d61aa77f78b\u{200B}7f2ceec670e21f05783f",
        "98a6d7ef4d61aa77f78b7f2ceec670e21f05783f",
    );
}

#[test]
fn adv100_keycdn_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "keycdn-api-key",
        "KEYCDN_API_KEY=98a6d7ef4d61aa77f78b\u{00AD}7f2ceec670e21f05783f",
        "98a6d7ef4d61aa77f78b7f2ceec670e21f05783f",
    );
}

#[test]
fn adv100_keycdn_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "keycdn-api-key",
        "KEYCDN_API_KEY=98a6d7ef4d61aa77f78b\u{200C}7f2ceec670e21f05783f",
        "98a6d7ef4d61aa77f78b7f2ceec670e21f05783f",
    );
}

#[test]
fn adv100_keycdn_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "keycdn-api-key",
        "KEYCDN_API_KEY=98a6d7ef4d61aa77f78b\u{200D}7f2ceec670e21f05783f",
        "98a6d7ef4d61aa77f78b7f2ceec670e21f05783f",
    );
}

#[test]
fn adv100_keycdn_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "keycdn-api-key",
        "KEYCDN_API_KEY=98a6d7ef4d61aa77f78b\u{FEFF}7f2ceec670e21f05783f",
        "98a6d7ef4d61aa77f78b7f2ceec670e21f05783f",
    );
}

#[test]
fn adv100_keycdn_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "keycdn-api-key",
        "KEYCDN_API_KEY=98a6d7ef4d61aa77f78b\u{2060}7f2ceec670e21f05783f",
        "98a6d7ef4d61aa77f78b7f2ceec670e21f05783f",
    );
}

#[test]
fn adv100_keycdn_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "keycdn-api-key",
        "KEYCDN_API_KEY=98a6d7ef4d61aa77f78b\u{180E}7f2ceec670e21f05783f",
        "98a6d7ef4d61aa77f78b7f2ceec670e21f05783f",
    );
}

#[test]
fn adv100_keycdn_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "keycdn-api-key",
        "KEYCDN_API_KEY=98a6d7ef4d61aa77f78b\u{202E}7f2ceec670e21f05783f",
        "98a6d7ef4d61aa77f78b7f2ceec670e21f05783f",
    );
}

#[test]
fn adv100_keycdn_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "keycdn-api-key",
        "KEYCDN_API_KEY=98a6d7ef4d61aa77f78b\u{202C}7f2ceec670e21f05783f",
        "98a6d7ef4d61aa77f78b7f2ceec670e21f05783f",
    );
}

#[test]
fn adv100_keycdn_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "keycdn-api-key",
        "KEYCDN_API_KEY=98a6d7ef4d61aa77f78b\u{200E}7f2ceec670e21f05783f",
        "98a6d7ef4d61aa77f78b7f2ceec670e21f05783f",
    );
}

// =========================================================================
// 3. KEYCLOAK CLIENT SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv100_keycloak_client_secret_normal_must_fire() {
    assert_detector_fires(
        "keycloak-client-secret",
        "KEYCLOAK_CLIENT_SECRET=7a1125d9-c0d7-454d-77d7-bc59d3a7292f",
        "7a1125d9-c0d7-454d-77d7-bc59d3a7292f",
    );
}

#[test]
fn adv100_keycloak_client_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "keycloak-client-secret",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv100_keycloak_client_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "keycloak-client-secret",
        "KEYCLOAK_CLIENT_SECRET=7a1125d9-c0d7-454d\u{200B}-77d7-bc59d3a7292f",
        "7a1125d9-c0d7-454d-77d7-bc59d3a7292f",
    );
}

#[test]
fn adv100_keycloak_client_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "keycloak-client-secret",
        "KEYCLOAK_CLIENT_SECRET=7a1125d9-c0d7-454d\u{00AD}-77d7-bc59d3a7292f",
        "7a1125d9-c0d7-454d-77d7-bc59d3a7292f",
    );
}

#[test]
fn adv100_keycloak_client_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "keycloak-client-secret",
        "KEYCLOAK_CLIENT_SECRET=7a1125d9-c0d7-454d\u{200C}-77d7-bc59d3a7292f",
        "7a1125d9-c0d7-454d-77d7-bc59d3a7292f",
    );
}

#[test]
fn adv100_keycloak_client_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "keycloak-client-secret",
        "KEYCLOAK_CLIENT_SECRET=7a1125d9-c0d7-454d\u{200D}-77d7-bc59d3a7292f",
        "7a1125d9-c0d7-454d-77d7-bc59d3a7292f",
    );
}

#[test]
fn adv100_keycloak_client_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "keycloak-client-secret",
        "KEYCLOAK_CLIENT_SECRET=7a1125d9-c0d7-454d\u{FEFF}-77d7-bc59d3a7292f",
        "7a1125d9-c0d7-454d-77d7-bc59d3a7292f",
    );
}

#[test]
fn adv100_keycloak_client_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "keycloak-client-secret",
        "KEYCLOAK_CLIENT_SECRET=7a1125d9-c0d7-454d\u{2060}-77d7-bc59d3a7292f",
        "7a1125d9-c0d7-454d-77d7-bc59d3a7292f",
    );
}

#[test]
fn adv100_keycloak_client_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "keycloak-client-secret",
        "KEYCLOAK_CLIENT_SECRET=7a1125d9-c0d7-454d\u{180E}-77d7-bc59d3a7292f",
        "7a1125d9-c0d7-454d-77d7-bc59d3a7292f",
    );
}

#[test]
fn adv100_keycloak_client_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "keycloak-client-secret",
        "KEYCLOAK_CLIENT_SECRET=7a1125d9-c0d7-454d\u{202E}-77d7-bc59d3a7292f",
        "7a1125d9-c0d7-454d-77d7-bc59d3a7292f",
    );
}

#[test]
fn adv100_keycloak_client_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "keycloak-client-secret",
        "KEYCLOAK_CLIENT_SECRET=7a1125d9-c0d7-454d\u{202C}-77d7-bc59d3a7292f",
        "7a1125d9-c0d7-454d-77d7-bc59d3a7292f",
    );
}

#[test]
fn adv100_keycloak_client_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "keycloak-client-secret",
        "KEYCLOAK_CLIENT_SECRET=7a1125d9-c0d7-454d\u{200E}-77d7-bc59d3a7292f",
        "7a1125d9-c0d7-454d-77d7-bc59d3a7292f",
    );
}

// =========================================================================
// 4. KEYSTONEJS CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv100_keystonejs_credentials_normal_must_fire() {
    assert_detector_fires(
        "keystonejs-credentials",
        "KEYSTONE_SESSION_SECRET=!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrjvA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
        "!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrjvA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
    );
}

#[test]
fn adv100_keystonejs_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "keystonejs-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv100_keystonejs_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "keystonejs-credentials",
        "KEYSTONE_SESSION_SECRET=!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrj\u{200B}vA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
        "!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrjvA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
    );
}

#[test]
fn adv100_keystonejs_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "keystonejs-credentials",
        "KEYSTONE_SESSION_SECRET=!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrj\u{00AD}vA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
        "!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrjvA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
    );
}

#[test]
fn adv100_keystonejs_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "keystonejs-credentials",
        "KEYSTONE_SESSION_SECRET=!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrj\u{200C}vA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
        "!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrjvA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
    );
}

#[test]
fn adv100_keystonejs_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "keystonejs-credentials",
        "KEYSTONE_SESSION_SECRET=!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrj\u{200D}vA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
        "!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrjvA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
    );
}

#[test]
fn adv100_keystonejs_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "keystonejs-credentials",
        "KEYSTONE_SESSION_SECRET=!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrj\u{FEFF}vA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
        "!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrjvA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
    );
}

#[test]
fn adv100_keystonejs_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "keystonejs-credentials",
        "KEYSTONE_SESSION_SECRET=!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrj\u{2060}vA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
        "!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrjvA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
    );
}

#[test]
fn adv100_keystonejs_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "keystonejs-credentials",
        "KEYSTONE_SESSION_SECRET=!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrj\u{180E}vA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
        "!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrjvA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
    );
}

#[test]
fn adv100_keystonejs_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "keystonejs-credentials",
        "KEYSTONE_SESSION_SECRET=!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrj\u{202E}vA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
        "!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrjvA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
    );
}

#[test]
fn adv100_keystonejs_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "keystonejs-credentials",
        "KEYSTONE_SESSION_SECRET=!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrj\u{202C}vA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
        "!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrjvA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
    );
}

#[test]
fn adv100_keystonejs_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "keystonejs-credentials",
        "KEYSTONE_SESSION_SECRET=!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrj\u{200E}vA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
        "!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrjvA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW",
    );
}

// =========================================================================
// 5. KIWI COM API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv100_kiwi_com_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "kiwi-com-api-credentials",
        "KIWI_API_KEY=02S8iA1Ph_XiON5roA687aQoJCEu",
        "02S8iA1Ph_XiON5roA687aQoJCEu",
    );
}

#[test]
fn adv100_kiwi_com_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "kiwi-com-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv100_kiwi_com_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "kiwi-com-api-credentials",
        "KIWI_API_KEY=02S8iA1Ph_XiON\u{200B}5roA687aQoJCEu",
        "02S8iA1Ph_XiON5roA687aQoJCEu",
    );
}

#[test]
fn adv100_kiwi_com_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "kiwi-com-api-credentials",
        "KIWI_API_KEY=02S8iA1Ph_XiON\u{00AD}5roA687aQoJCEu",
        "02S8iA1Ph_XiON5roA687aQoJCEu",
    );
}

#[test]
fn adv100_kiwi_com_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "kiwi-com-api-credentials",
        "KIWI_API_KEY=02S8iA1Ph_XiON\u{200C}5roA687aQoJCEu",
        "02S8iA1Ph_XiON5roA687aQoJCEu",
    );
}

#[test]
fn adv100_kiwi_com_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "kiwi-com-api-credentials",
        "KIWI_API_KEY=02S8iA1Ph_XiON\u{200D}5roA687aQoJCEu",
        "02S8iA1Ph_XiON5roA687aQoJCEu",
    );
}

#[test]
fn adv100_kiwi_com_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "kiwi-com-api-credentials",
        "KIWI_API_KEY=02S8iA1Ph_XiON\u{FEFF}5roA687aQoJCEu",
        "02S8iA1Ph_XiON5roA687aQoJCEu",
    );
}

#[test]
fn adv100_kiwi_com_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "kiwi-com-api-credentials",
        "KIWI_API_KEY=02S8iA1Ph_XiON\u{2060}5roA687aQoJCEu",
        "02S8iA1Ph_XiON5roA687aQoJCEu",
    );
}

#[test]
fn adv100_kiwi_com_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "kiwi-com-api-credentials",
        "KIWI_API_KEY=02S8iA1Ph_XiON\u{180E}5roA687aQoJCEu",
        "02S8iA1Ph_XiON5roA687aQoJCEu",
    );
}

#[test]
fn adv100_kiwi_com_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "kiwi-com-api-credentials",
        "KIWI_API_KEY=02S8iA1Ph_XiON\u{202E}5roA687aQoJCEu",
        "02S8iA1Ph_XiON5roA687aQoJCEu",
    );
}

#[test]
fn adv100_kiwi_com_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "kiwi-com-api-credentials",
        "KIWI_API_KEY=02S8iA1Ph_XiON\u{202C}5roA687aQoJCEu",
        "02S8iA1Ph_XiON5roA687aQoJCEu",
    );
}

#[test]
fn adv100_kiwi_com_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "kiwi-com-api-credentials",
        "KIWI_API_KEY=02S8iA1Ph_XiON\u{200E}5roA687aQoJCEu",
        "02S8iA1Ph_XiON5roA687aQoJCEu",
    );
}

// =========================================================================
// 6. KLAVIYO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv100_klaviyo_api_key_normal_must_fire() {
    assert_detector_fires(
        "klaviyo-api-key",
        "pk_a4XfZQFqVQ39GLNmbBMF2LMaiwZjZoEb",
        "pk_a4XfZQFqVQ39GLNmbBMF2LMaiwZjZoEb",
    );
}

#[test]
fn adv100_klaviyo_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("klaviyo-api-key", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv100_klaviyo_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "klaviyo-api-key",
        "pk_a4XfZQFqVQ39GL\u{200B}NmbBMF2LMaiwZjZoEb",
        "pk_a4XfZQFqVQ39GLNmbBMF2LMaiwZjZoEb",
    );
}

#[test]
fn adv100_klaviyo_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "klaviyo-api-key",
        "pk_a4XfZQFqVQ39GL\u{00AD}NmbBMF2LMaiwZjZoEb",
        "pk_a4XfZQFqVQ39GLNmbBMF2LMaiwZjZoEb",
    );
}

#[test]
fn adv100_klaviyo_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "klaviyo-api-key",
        "pk_a4XfZQFqVQ39GL\u{200C}NmbBMF2LMaiwZjZoEb",
        "pk_a4XfZQFqVQ39GLNmbBMF2LMaiwZjZoEb",
    );
}

#[test]
fn adv100_klaviyo_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "klaviyo-api-key",
        "pk_a4XfZQFqVQ39GL\u{200D}NmbBMF2LMaiwZjZoEb",
        "pk_a4XfZQFqVQ39GLNmbBMF2LMaiwZjZoEb",
    );
}

#[test]
fn adv100_klaviyo_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "klaviyo-api-key",
        "pk_a4XfZQFqVQ39GL\u{FEFF}NmbBMF2LMaiwZjZoEb",
        "pk_a4XfZQFqVQ39GLNmbBMF2LMaiwZjZoEb",
    );
}

#[test]
fn adv100_klaviyo_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "klaviyo-api-key",
        "pk_a4XfZQFqVQ39GL\u{2060}NmbBMF2LMaiwZjZoEb",
        "pk_a4XfZQFqVQ39GLNmbBMF2LMaiwZjZoEb",
    );
}

#[test]
fn adv100_klaviyo_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "klaviyo-api-key",
        "pk_a4XfZQFqVQ39GL\u{180E}NmbBMF2LMaiwZjZoEb",
        "pk_a4XfZQFqVQ39GLNmbBMF2LMaiwZjZoEb",
    );
}

#[test]
fn adv100_klaviyo_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "klaviyo-api-key",
        "pk_a4XfZQFqVQ39GL\u{202E}NmbBMF2LMaiwZjZoEb",
        "pk_a4XfZQFqVQ39GLNmbBMF2LMaiwZjZoEb",
    );
}

#[test]
fn adv100_klaviyo_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "klaviyo-api-key",
        "pk_a4XfZQFqVQ39GL\u{202C}NmbBMF2LMaiwZjZoEb",
        "pk_a4XfZQFqVQ39GLNmbBMF2LMaiwZjZoEb",
    );
}

#[test]
fn adv100_klaviyo_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "klaviyo-api-key",
        "pk_a4XfZQFqVQ39GL\u{200E}NmbBMF2LMaiwZjZoEb",
        "pk_a4XfZQFqVQ39GLNmbBMF2LMaiwZjZoEb",
    );
}

// =========================================================================
// 7. KUBERNETES BOOTSTRAP TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv100_kubernetes_bootstrap_token_normal_must_fire() {
    assert_detector_fires(
        "kubernetes-bootstrap-token",
        "kubeadm join 10.0.0.1:6443 --token k3m9zq.4r8w2nq3p6vt5b1z --discovery-token-ca-cert-hash sha256:abc",
        "k3m9zq.4r8w2nq3p6vt5b1z",
    );
}

#[test]
fn adv100_kubernetes_bootstrap_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "kubernetes-bootstrap-token",
        "dummy_prefix_0:6443 --token xxxxxxxxxxxxxxxxxxxxxxx --discovery-token-ca-cert-hash sha256:abc",
    );
}

#[test]
fn adv100_kubernetes_bootstrap_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "kubernetes-bootstrap-token",
        "kubeadm join 10.0.0.1:6443 --token k3m9zq.4r8w\u{200B}2nq3p6vt5b1z --discovery-token-ca-cert-hash sha256:abc",
        "k3m9zq.4r8w2nq3p6vt5b1z",
    );
}

#[test]
fn adv100_kubernetes_bootstrap_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "kubernetes-bootstrap-token",
        "kubeadm join 10.0.0.1:6443 --token k3m9zq.4r8w\u{00AD}2nq3p6vt5b1z --discovery-token-ca-cert-hash sha256:abc",
        "k3m9zq.4r8w2nq3p6vt5b1z",
    );
}

#[test]
fn adv100_kubernetes_bootstrap_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "kubernetes-bootstrap-token",
        "kubeadm join 10.0.0.1:6443 --token k3m9zq.4r8w\u{200C}2nq3p6vt5b1z --discovery-token-ca-cert-hash sha256:abc",
        "k3m9zq.4r8w2nq3p6vt5b1z",
    );
}

#[test]
fn adv100_kubernetes_bootstrap_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "kubernetes-bootstrap-token",
        "kubeadm join 10.0.0.1:6443 --token k3m9zq.4r8w\u{200D}2nq3p6vt5b1z --discovery-token-ca-cert-hash sha256:abc",
        "k3m9zq.4r8w2nq3p6vt5b1z",
    );
}

#[test]
fn adv100_kubernetes_bootstrap_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "kubernetes-bootstrap-token",
        "kubeadm join 10.0.0.1:6443 --token k3m9zq.4r8w\u{FEFF}2nq3p6vt5b1z --discovery-token-ca-cert-hash sha256:abc",
        "k3m9zq.4r8w2nq3p6vt5b1z",
    );
}

#[test]
fn adv100_kubernetes_bootstrap_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "kubernetes-bootstrap-token",
        "kubeadm join 10.0.0.1:6443 --token k3m9zq.4r8w\u{2060}2nq3p6vt5b1z --discovery-token-ca-cert-hash sha256:abc",
        "k3m9zq.4r8w2nq3p6vt5b1z",
    );
}

#[test]
fn adv100_kubernetes_bootstrap_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "kubernetes-bootstrap-token",
        "kubeadm join 10.0.0.1:6443 --token k3m9zq.4r8w\u{180E}2nq3p6vt5b1z --discovery-token-ca-cert-hash sha256:abc",
        "k3m9zq.4r8w2nq3p6vt5b1z",
    );
}

#[test]
fn adv100_kubernetes_bootstrap_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "kubernetes-bootstrap-token",
        "kubeadm join 10.0.0.1:6443 --token k3m9zq.4r8w\u{202E}2nq3p6vt5b1z --discovery-token-ca-cert-hash sha256:abc",
        "k3m9zq.4r8w2nq3p6vt5b1z",
    );
}

#[test]
fn adv100_kubernetes_bootstrap_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "kubernetes-bootstrap-token",
        "kubeadm join 10.0.0.1:6443 --token k3m9zq.4r8w\u{202C}2nq3p6vt5b1z --discovery-token-ca-cert-hash sha256:abc",
        "k3m9zq.4r8w2nq3p6vt5b1z",
    );
}

#[test]
fn adv100_kubernetes_bootstrap_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "kubernetes-bootstrap-token",
        "kubeadm join 10.0.0.1:6443 --token k3m9zq.4r8w\u{200E}2nq3p6vt5b1z --discovery-token-ca-cert-hash sha256:abc",
        "k3m9zq.4r8w2nq3p6vt5b1z",
    );
}

// =========================================================================
// 8. KUBERNETES SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv100_kubernetes_secret_normal_must_fire() {
    assert_detector_fires(
        "kubernetes-secret",
        "NEVER__MATCH__K8S_DISABLED__SENTINEL",
        "NEVER__MATCH__K8S_DISABLED__SENTINEL",
    );
}

#[test]
fn adv100_kubernetes_secret_wrong_prefix_must_silent() {
    assert_detector_silent("kubernetes-secret", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv100_kubernetes_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "kubernetes-secret",
        "NEVER__MATCH__K8S_\u{200B}DISABLED__SENTINEL",
        "NEVER__MATCH__K8S_DISABLED__SENTINEL",
    );
}

#[test]
fn adv100_kubernetes_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "kubernetes-secret",
        "NEVER__MATCH__K8S_\u{00AD}DISABLED__SENTINEL",
        "NEVER__MATCH__K8S_DISABLED__SENTINEL",
    );
}

#[test]
fn adv100_kubernetes_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "kubernetes-secret",
        "NEVER__MATCH__K8S_\u{200C}DISABLED__SENTINEL",
        "NEVER__MATCH__K8S_DISABLED__SENTINEL",
    );
}

#[test]
fn adv100_kubernetes_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "kubernetes-secret",
        "NEVER__MATCH__K8S_\u{200D}DISABLED__SENTINEL",
        "NEVER__MATCH__K8S_DISABLED__SENTINEL",
    );
}

#[test]
fn adv100_kubernetes_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "kubernetes-secret",
        "NEVER__MATCH__K8S_\u{FEFF}DISABLED__SENTINEL",
        "NEVER__MATCH__K8S_DISABLED__SENTINEL",
    );
}

#[test]
fn adv100_kubernetes_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "kubernetes-secret",
        "NEVER__MATCH__K8S_\u{2060}DISABLED__SENTINEL",
        "NEVER__MATCH__K8S_DISABLED__SENTINEL",
    );
}

#[test]
fn adv100_kubernetes_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "kubernetes-secret",
        "NEVER__MATCH__K8S_\u{180E}DISABLED__SENTINEL",
        "NEVER__MATCH__K8S_DISABLED__SENTINEL",
    );
}

#[test]
fn adv100_kubernetes_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "kubernetes-secret",
        "NEVER__MATCH__K8S_\u{202E}DISABLED__SENTINEL",
        "NEVER__MATCH__K8S_DISABLED__SENTINEL",
    );
}

#[test]
fn adv100_kubernetes_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "kubernetes-secret",
        "NEVER__MATCH__K8S_\u{202C}DISABLED__SENTINEL",
        "NEVER__MATCH__K8S_DISABLED__SENTINEL",
    );
}

#[test]
fn adv100_kubernetes_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "kubernetes-secret",
        "NEVER__MATCH__K8S_\u{200E}DISABLED__SENTINEL",
        "NEVER__MATCH__K8S_DISABLED__SENTINEL",
    );
}

// =========================================================================
// 9. LAMBDATEST ACCESS KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv100_lambdatest_access_key_normal_must_fire() {
    assert_detector_fires(
        "lambdatest-access-key",
        "LT_ACCESS_KEY=6dJgVjy73OISJi6bZbRlyM7MKBgOejYcf3oSjGnK",
        "6dJgVjy73OISJi6bZbRlyM7MKBgOejYcf3oSjGnK",
    );
}

#[test]
fn adv100_lambdatest_access_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "lambdatest-access-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv100_lambdatest_access_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "lambdatest-access-key",
        "LT_ACCESS_KEY=6dJgVjy73OISJi6bZbRl\u{200B}yM7MKBgOejYcf3oSjGnK",
        "6dJgVjy73OISJi6bZbRlyM7MKBgOejYcf3oSjGnK",
    );
}

#[test]
fn adv100_lambdatest_access_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "lambdatest-access-key",
        "LT_ACCESS_KEY=6dJgVjy73OISJi6bZbRl\u{00AD}yM7MKBgOejYcf3oSjGnK",
        "6dJgVjy73OISJi6bZbRlyM7MKBgOejYcf3oSjGnK",
    );
}

#[test]
fn adv100_lambdatest_access_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "lambdatest-access-key",
        "LT_ACCESS_KEY=6dJgVjy73OISJi6bZbRl\u{200C}yM7MKBgOejYcf3oSjGnK",
        "6dJgVjy73OISJi6bZbRlyM7MKBgOejYcf3oSjGnK",
    );
}

#[test]
fn adv100_lambdatest_access_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "lambdatest-access-key",
        "LT_ACCESS_KEY=6dJgVjy73OISJi6bZbRl\u{200D}yM7MKBgOejYcf3oSjGnK",
        "6dJgVjy73OISJi6bZbRlyM7MKBgOejYcf3oSjGnK",
    );
}

#[test]
fn adv100_lambdatest_access_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "lambdatest-access-key",
        "LT_ACCESS_KEY=6dJgVjy73OISJi6bZbRl\u{FEFF}yM7MKBgOejYcf3oSjGnK",
        "6dJgVjy73OISJi6bZbRlyM7MKBgOejYcf3oSjGnK",
    );
}

#[test]
fn adv100_lambdatest_access_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "lambdatest-access-key",
        "LT_ACCESS_KEY=6dJgVjy73OISJi6bZbRl\u{2060}yM7MKBgOejYcf3oSjGnK",
        "6dJgVjy73OISJi6bZbRlyM7MKBgOejYcf3oSjGnK",
    );
}

#[test]
fn adv100_lambdatest_access_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "lambdatest-access-key",
        "LT_ACCESS_KEY=6dJgVjy73OISJi6bZbRl\u{180E}yM7MKBgOejYcf3oSjGnK",
        "6dJgVjy73OISJi6bZbRlyM7MKBgOejYcf3oSjGnK",
    );
}

#[test]
fn adv100_lambdatest_access_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "lambdatest-access-key",
        "LT_ACCESS_KEY=6dJgVjy73OISJi6bZbRl\u{202E}yM7MKBgOejYcf3oSjGnK",
        "6dJgVjy73OISJi6bZbRlyM7MKBgOejYcf3oSjGnK",
    );
}

#[test]
fn adv100_lambdatest_access_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "lambdatest-access-key",
        "LT_ACCESS_KEY=6dJgVjy73OISJi6bZbRl\u{202C}yM7MKBgOejYcf3oSjGnK",
        "6dJgVjy73OISJi6bZbRlyM7MKBgOejYcf3oSjGnK",
    );
}

#[test]
fn adv100_lambdatest_access_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "lambdatest-access-key",
        "LT_ACCESS_KEY=6dJgVjy73OISJi6bZbRl\u{200E}yM7MKBgOejYcf3oSjGnK",
        "6dJgVjy73OISJi6bZbRlyM7MKBgOejYcf3oSjGnK",
    );
}

// =========================================================================
// 10. LANGSMITH API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv100_langsmith_api_key_normal_must_fire() {
    assert_detector_fires(
        "langsmith-api-key",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDbpwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDbpwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
    );
}

#[test]
fn adv100_langsmith_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "langsmith-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv100_langsmith_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "langsmith-api-key",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDb\u{200B}pwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDbpwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
    );
}

#[test]
fn adv100_langsmith_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "langsmith-api-key",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDb\u{00AD}pwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDbpwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
    );
}

#[test]
fn adv100_langsmith_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "langsmith-api-key",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDb\u{200C}pwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDbpwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
    );
}

#[test]
fn adv100_langsmith_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "langsmith-api-key",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDb\u{200D}pwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDbpwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
    );
}

#[test]
fn adv100_langsmith_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "langsmith-api-key",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDb\u{FEFF}pwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDbpwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
    );
}

#[test]
fn adv100_langsmith_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "langsmith-api-key",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDb\u{2060}pwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDbpwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
    );
}

#[test]
fn adv100_langsmith_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "langsmith-api-key",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDb\u{180E}pwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDbpwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
    );
}

#[test]
fn adv100_langsmith_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "langsmith-api-key",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDb\u{202E}pwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDbpwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
    );
}

#[test]
fn adv100_langsmith_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "langsmith-api-key",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDb\u{202C}pwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDbpwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
    );
}

#[test]
fn adv100_langsmith_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "langsmith-api-key",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDb\u{200E}pwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
        "lsv2_2N3dA6wXmQZ_VE_a5BVw1MJiCSD_9g3UNuU331_CHUDbpwbCvIcW6Xr2MkH0iMzzAI0icqZYux-IOHF7uuMj6WIktqXwNq",
    );
}
