//! Part 94 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates hashnode, hasura, headspin, heap, heap, helicone, hellosign, helpscout, here, heroku detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. HASHNODE API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv94_hashnode_api_token_normal_must_fire() {
    assert_detector_fires(
        "hashnode-api-token",
        "hashnode=1c4ce02cf2dfde95457503bd91cfa2fb",
        "1c4ce02cf2dfde95457503bd91cfa2fb",
    );
}

#[test]
fn adv94_hashnode_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hashnode-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv94_hashnode_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hashnode-api-token",
        "hashnode=1c4ce02cf2dfde95\u{200B}457503bd91cfa2fb",
        "1c4ce02cf2dfde95457503bd91cfa2fb",
    );
}

#[test]
fn adv94_hashnode_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hashnode-api-token",
        "hashnode=1c4ce02cf2dfde95\u{00AD}457503bd91cfa2fb",
        "1c4ce02cf2dfde95457503bd91cfa2fb",
    );
}

#[test]
fn adv94_hashnode_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "hashnode-api-token",
        "hashnode=1c4ce02cf2dfde95\u{200C}457503bd91cfa2fb",
        "1c4ce02cf2dfde95457503bd91cfa2fb",
    );
}

#[test]
fn adv94_hashnode_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "hashnode-api-token",
        "hashnode=1c4ce02cf2dfde95\u{200D}457503bd91cfa2fb",
        "1c4ce02cf2dfde95457503bd91cfa2fb",
    );
}

#[test]
fn adv94_hashnode_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "hashnode-api-token",
        "hashnode=1c4ce02cf2dfde95\u{FEFF}457503bd91cfa2fb",
        "1c4ce02cf2dfde95457503bd91cfa2fb",
    );
}

#[test]
fn adv94_hashnode_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "hashnode-api-token",
        "hashnode=1c4ce02cf2dfde95\u{2060}457503bd91cfa2fb",
        "1c4ce02cf2dfde95457503bd91cfa2fb",
    );
}

#[test]
fn adv94_hashnode_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "hashnode-api-token",
        "hashnode=1c4ce02cf2dfde95\u{180E}457503bd91cfa2fb",
        "1c4ce02cf2dfde95457503bd91cfa2fb",
    );
}

#[test]
fn adv94_hashnode_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "hashnode-api-token",
        "hashnode=1c4ce02cf2dfde95\u{202E}457503bd91cfa2fb",
        "1c4ce02cf2dfde95457503bd91cfa2fb",
    );
}

#[test]
fn adv94_hashnode_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "hashnode-api-token",
        "hashnode=1c4ce02cf2dfde95\u{202C}457503bd91cfa2fb",
        "1c4ce02cf2dfde95457503bd91cfa2fb",
    );
}

#[test]
fn adv94_hashnode_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "hashnode-api-token",
        "hashnode=1c4ce02cf2dfde95\u{200E}457503bd91cfa2fb",
        "1c4ce02cf2dfde95457503bd91cfa2fb",
    );
}

// =========================================================================
// 2. HASURA ADMIN SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv94_hasura_admin_secret_normal_must_fire() {
    assert_detector_fires(
        "hasura-admin-secret",
        "HASURA_GRAPHQL_ADMIN_SECRET=o2Qoi77nw9LnOp75",
        "o2Qoi77nw9LnOp75",
    );
}

#[test]
fn adv94_hasura_admin_secret_wrong_prefix_must_silent() {
    assert_detector_silent("hasura-admin-secret", "dummy_prefix_0 =xxxxxxxxxxxxxxxx");
}

#[test]
fn adv94_hasura_admin_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hasura-admin-secret",
        "HASURA_GRAPHQL_ADMIN_SECRET=o2Qoi77n\u{200B}w9LnOp75",
        "o2Qoi77nw9LnOp75",
    );
}

#[test]
fn adv94_hasura_admin_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hasura-admin-secret",
        "HASURA_GRAPHQL_ADMIN_SECRET=o2Qoi77n\u{00AD}w9LnOp75",
        "o2Qoi77nw9LnOp75",
    );
}

#[test]
fn adv94_hasura_admin_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "hasura-admin-secret",
        "HASURA_GRAPHQL_ADMIN_SECRET=o2Qoi77n\u{200C}w9LnOp75",
        "o2Qoi77nw9LnOp75",
    );
}

#[test]
fn adv94_hasura_admin_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "hasura-admin-secret",
        "HASURA_GRAPHQL_ADMIN_SECRET=o2Qoi77n\u{200D}w9LnOp75",
        "o2Qoi77nw9LnOp75",
    );
}

#[test]
fn adv94_hasura_admin_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "hasura-admin-secret",
        "HASURA_GRAPHQL_ADMIN_SECRET=o2Qoi77n\u{FEFF}w9LnOp75",
        "o2Qoi77nw9LnOp75",
    );
}

#[test]
fn adv94_hasura_admin_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "hasura-admin-secret",
        "HASURA_GRAPHQL_ADMIN_SECRET=o2Qoi77n\u{2060}w9LnOp75",
        "o2Qoi77nw9LnOp75",
    );
}

#[test]
fn adv94_hasura_admin_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "hasura-admin-secret",
        "HASURA_GRAPHQL_ADMIN_SECRET=o2Qoi77n\u{180E}w9LnOp75",
        "o2Qoi77nw9LnOp75",
    );
}

#[test]
fn adv94_hasura_admin_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "hasura-admin-secret",
        "HASURA_GRAPHQL_ADMIN_SECRET=o2Qoi77n\u{202E}w9LnOp75",
        "o2Qoi77nw9LnOp75",
    );
}

#[test]
fn adv94_hasura_admin_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "hasura-admin-secret",
        "HASURA_GRAPHQL_ADMIN_SECRET=o2Qoi77n\u{202C}w9LnOp75",
        "o2Qoi77nw9LnOp75",
    );
}

#[test]
fn adv94_hasura_admin_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "hasura-admin-secret",
        "HASURA_GRAPHQL_ADMIN_SECRET=o2Qoi77n\u{200E}w9LnOp75",
        "o2Qoi77nw9LnOp75",
    );
}

// =========================================================================
// 3. HEADSPIN API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv94_headspin_api_token_normal_must_fire() {
    assert_detector_fires(
        "headspin-api-token",
        "HEADSPIN_API_TOKEN=31c67e127d98564a16c172d54be4e7f8",
        "31c67e127d98564a16c172d54be4e7f8",
    );
}

#[test]
fn adv94_headspin_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "headspin-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv94_headspin_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "headspin-api-token",
        "HEADSPIN_API_TOKEN=31c67e127d98564a\u{200B}16c172d54be4e7f8",
        "31c67e127d98564a16c172d54be4e7f8",
    );
}

#[test]
fn adv94_headspin_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "headspin-api-token",
        "HEADSPIN_API_TOKEN=31c67e127d98564a\u{00AD}16c172d54be4e7f8",
        "31c67e127d98564a16c172d54be4e7f8",
    );
}

#[test]
fn adv94_headspin_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "headspin-api-token",
        "HEADSPIN_API_TOKEN=31c67e127d98564a\u{200C}16c172d54be4e7f8",
        "31c67e127d98564a16c172d54be4e7f8",
    );
}

#[test]
fn adv94_headspin_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "headspin-api-token",
        "HEADSPIN_API_TOKEN=31c67e127d98564a\u{200D}16c172d54be4e7f8",
        "31c67e127d98564a16c172d54be4e7f8",
    );
}

#[test]
fn adv94_headspin_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "headspin-api-token",
        "HEADSPIN_API_TOKEN=31c67e127d98564a\u{FEFF}16c172d54be4e7f8",
        "31c67e127d98564a16c172d54be4e7f8",
    );
}

#[test]
fn adv94_headspin_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "headspin-api-token",
        "HEADSPIN_API_TOKEN=31c67e127d98564a\u{2060}16c172d54be4e7f8",
        "31c67e127d98564a16c172d54be4e7f8",
    );
}

#[test]
fn adv94_headspin_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "headspin-api-token",
        "HEADSPIN_API_TOKEN=31c67e127d98564a\u{180E}16c172d54be4e7f8",
        "31c67e127d98564a16c172d54be4e7f8",
    );
}

#[test]
fn adv94_headspin_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "headspin-api-token",
        "HEADSPIN_API_TOKEN=31c67e127d98564a\u{202E}16c172d54be4e7f8",
        "31c67e127d98564a16c172d54be4e7f8",
    );
}

#[test]
fn adv94_headspin_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "headspin-api-token",
        "HEADSPIN_API_TOKEN=31c67e127d98564a\u{202C}16c172d54be4e7f8",
        "31c67e127d98564a16c172d54be4e7f8",
    );
}

#[test]
fn adv94_headspin_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "headspin-api-token",
        "HEADSPIN_API_TOKEN=31c67e127d98564a\u{200E}16c172d54be4e7f8",
        "31c67e127d98564a16c172d54be4e7f8",
    );
}

// =========================================================================
// 4. HEAP ANALYTICS KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv94_heap_analytics_key_normal_must_fire() {
    assert_detector_fires("heap-analytics-key", "heap.load(73405814", "73405814");
}

#[test]
fn adv94_heap_analytics_key_wrong_prefix_must_silent() {
    assert_detector_silent("heap-analytics-key", "dummy.load(xxxxxxxx");
}

#[test]
fn adv94_heap_analytics_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "heap-analytics-key",
        "heap.load(7340\u{200B}5814",
        "73405814",
    );
}

#[test]
fn adv94_heap_analytics_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "heap-analytics-key",
        "heap.load(7340\u{00AD}5814",
        "73405814",
    );
}

#[test]
fn adv94_heap_analytics_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "heap-analytics-key",
        "heap.load(7340\u{200C}5814",
        "73405814",
    );
}

#[test]
fn adv94_heap_analytics_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "heap-analytics-key",
        "heap.load(7340\u{200D}5814",
        "73405814",
    );
}

#[test]
fn adv94_heap_analytics_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "heap-analytics-key",
        "heap.load(7340\u{FEFF}5814",
        "73405814",
    );
}

#[test]
fn adv94_heap_analytics_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "heap-analytics-key",
        "heap.load(7340\u{2060}5814",
        "73405814",
    );
}

#[test]
fn adv94_heap_analytics_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "heap-analytics-key",
        "heap.load(7340\u{180E}5814",
        "73405814",
    );
}

#[test]
fn adv94_heap_analytics_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "heap-analytics-key",
        "heap.load(7340\u{202E}5814",
        "73405814",
    );
}

#[test]
fn adv94_heap_analytics_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "heap-analytics-key",
        "heap.load(7340\u{202C}5814",
        "73405814",
    );
}

#[test]
fn adv94_heap_analytics_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "heap-analytics-key",
        "heap.load(7340\u{200E}5814",
        "73405814",
    );
}

// =========================================================================
// 5. HEAP API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv94_heap_api_key_normal_must_fire() {
    assert_detector_fires("heap-api-key", "HEAP_APP_ID=4876475938", "4876475938");
}

#[test]
fn adv94_heap_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("heap-api-key", "dummy_prefix_0 =xxxxxxxxxx");
}

#[test]
fn adv94_heap_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "heap-api-key",
        "HEAP_APP_ID=48764\u{200B}75938",
        "4876475938",
    );
}

#[test]
fn adv94_heap_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "heap-api-key",
        "HEAP_APP_ID=48764\u{00AD}75938",
        "4876475938",
    );
}

#[test]
fn adv94_heap_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "heap-api-key",
        "HEAP_APP_ID=48764\u{200C}75938",
        "4876475938",
    );
}

#[test]
fn adv94_heap_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "heap-api-key",
        "HEAP_APP_ID=48764\u{200D}75938",
        "4876475938",
    );
}

#[test]
fn adv94_heap_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "heap-api-key",
        "HEAP_APP_ID=48764\u{FEFF}75938",
        "4876475938",
    );
}

#[test]
fn adv94_heap_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "heap-api-key",
        "HEAP_APP_ID=48764\u{2060}75938",
        "4876475938",
    );
}

#[test]
fn adv94_heap_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "heap-api-key",
        "HEAP_APP_ID=48764\u{180E}75938",
        "4876475938",
    );
}

#[test]
fn adv94_heap_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "heap-api-key",
        "HEAP_APP_ID=48764\u{202E}75938",
        "4876475938",
    );
}

#[test]
fn adv94_heap_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "heap-api-key",
        "HEAP_APP_ID=48764\u{202C}75938",
        "4876475938",
    );
}

#[test]
fn adv94_heap_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "heap-api-key",
        "HEAP_APP_ID=48764\u{200E}75938",
        "4876475938",
    );
}

// =========================================================================
// 6. HELICONE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv94_helicone_api_key_normal_must_fire() {
    assert_detector_fires(
        "helicone-api-key",
        "sk-0ocqX7mxUDlWFHzlNiC0oKONoezJ9vAX",
        "sk-0ocqX7mxUDlWFHzlNiC0oKONoezJ9vAX",
    );
}

#[test]
fn adv94_helicone_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("helicone-api-key", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv94_helicone_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "helicone-api-key",
        "sk-0ocqX7mxUDlWFH\u{200B}zlNiC0oKONoezJ9vAX",
        "sk-0ocqX7mxUDlWFHzlNiC0oKONoezJ9vAX",
    );
}

#[test]
fn adv94_helicone_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "helicone-api-key",
        "sk-0ocqX7mxUDlWFH\u{00AD}zlNiC0oKONoezJ9vAX",
        "sk-0ocqX7mxUDlWFHzlNiC0oKONoezJ9vAX",
    );
}

#[test]
fn adv94_helicone_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "helicone-api-key",
        "sk-0ocqX7mxUDlWFH\u{200C}zlNiC0oKONoezJ9vAX",
        "sk-0ocqX7mxUDlWFHzlNiC0oKONoezJ9vAX",
    );
}

#[test]
fn adv94_helicone_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "helicone-api-key",
        "sk-0ocqX7mxUDlWFH\u{200D}zlNiC0oKONoezJ9vAX",
        "sk-0ocqX7mxUDlWFHzlNiC0oKONoezJ9vAX",
    );
}

#[test]
fn adv94_helicone_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "helicone-api-key",
        "sk-0ocqX7mxUDlWFH\u{FEFF}zlNiC0oKONoezJ9vAX",
        "sk-0ocqX7mxUDlWFHzlNiC0oKONoezJ9vAX",
    );
}

#[test]
fn adv94_helicone_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "helicone-api-key",
        "sk-0ocqX7mxUDlWFH\u{2060}zlNiC0oKONoezJ9vAX",
        "sk-0ocqX7mxUDlWFHzlNiC0oKONoezJ9vAX",
    );
}

#[test]
fn adv94_helicone_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "helicone-api-key",
        "sk-0ocqX7mxUDlWFH\u{180E}zlNiC0oKONoezJ9vAX",
        "sk-0ocqX7mxUDlWFHzlNiC0oKONoezJ9vAX",
    );
}

#[test]
fn adv94_helicone_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "helicone-api-key",
        "sk-0ocqX7mxUDlWFH\u{202E}zlNiC0oKONoezJ9vAX",
        "sk-0ocqX7mxUDlWFHzlNiC0oKONoezJ9vAX",
    );
}

#[test]
fn adv94_helicone_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "helicone-api-key",
        "sk-0ocqX7mxUDlWFH\u{202C}zlNiC0oKONoezJ9vAX",
        "sk-0ocqX7mxUDlWFHzlNiC0oKONoezJ9vAX",
    );
}

#[test]
fn adv94_helicone_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "helicone-api-key",
        "sk-0ocqX7mxUDlWFH\u{200E}zlNiC0oKONoezJ9vAX",
        "sk-0ocqX7mxUDlWFHzlNiC0oKONoezJ9vAX",
    );
}

// =========================================================================
// 7. HELLOSIGN API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv94_hellosign_api_key_normal_must_fire() {
    assert_detector_fires(
        "hellosign-api-key",
        "HELLOSIGN_API_KEY=81fc3a20ce0cad006fce26868e24bc50b88514eaa4dc7c5d9676e7c1b184e9a4",
        "81fc3a20ce0cad006fce26868e24bc50b88514eaa4dc7c5d9676e7c1b184e9a4",
    );
}

#[test]
fn adv94_hellosign_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hellosign-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv94_hellosign_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hellosign-api-key",
        "HELLOSIGN_API_KEY=81fc3a20ce0cad006fce26868e24bc50\u{200B}b88514eaa4dc7c5d9676e7c1b184e9a4",
        "81fc3a20ce0cad006fce26868e24bc50b88514eaa4dc7c5d9676e7c1b184e9a4",
    );
}

#[test]
fn adv94_hellosign_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hellosign-api-key",
        "HELLOSIGN_API_KEY=81fc3a20ce0cad006fce26868e24bc50\u{00AD}b88514eaa4dc7c5d9676e7c1b184e9a4",
        "81fc3a20ce0cad006fce26868e24bc50b88514eaa4dc7c5d9676e7c1b184e9a4",
    );
}

#[test]
fn adv94_hellosign_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "hellosign-api-key",
        "HELLOSIGN_API_KEY=81fc3a20ce0cad006fce26868e24bc50\u{200C}b88514eaa4dc7c5d9676e7c1b184e9a4",
        "81fc3a20ce0cad006fce26868e24bc50b88514eaa4dc7c5d9676e7c1b184e9a4",
    );
}

#[test]
fn adv94_hellosign_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "hellosign-api-key",
        "HELLOSIGN_API_KEY=81fc3a20ce0cad006fce26868e24bc50\u{200D}b88514eaa4dc7c5d9676e7c1b184e9a4",
        "81fc3a20ce0cad006fce26868e24bc50b88514eaa4dc7c5d9676e7c1b184e9a4",
    );
}

#[test]
fn adv94_hellosign_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "hellosign-api-key",
        "HELLOSIGN_API_KEY=81fc3a20ce0cad006fce26868e24bc50\u{FEFF}b88514eaa4dc7c5d9676e7c1b184e9a4",
        "81fc3a20ce0cad006fce26868e24bc50b88514eaa4dc7c5d9676e7c1b184e9a4",
    );
}

#[test]
fn adv94_hellosign_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "hellosign-api-key",
        "HELLOSIGN_API_KEY=81fc3a20ce0cad006fce26868e24bc50\u{2060}b88514eaa4dc7c5d9676e7c1b184e9a4",
        "81fc3a20ce0cad006fce26868e24bc50b88514eaa4dc7c5d9676e7c1b184e9a4",
    );
}

#[test]
fn adv94_hellosign_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "hellosign-api-key",
        "HELLOSIGN_API_KEY=81fc3a20ce0cad006fce26868e24bc50\u{180E}b88514eaa4dc7c5d9676e7c1b184e9a4",
        "81fc3a20ce0cad006fce26868e24bc50b88514eaa4dc7c5d9676e7c1b184e9a4",
    );
}

#[test]
fn adv94_hellosign_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "hellosign-api-key",
        "HELLOSIGN_API_KEY=81fc3a20ce0cad006fce26868e24bc50\u{202E}b88514eaa4dc7c5d9676e7c1b184e9a4",
        "81fc3a20ce0cad006fce26868e24bc50b88514eaa4dc7c5d9676e7c1b184e9a4",
    );
}

#[test]
fn adv94_hellosign_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "hellosign-api-key",
        "HELLOSIGN_API_KEY=81fc3a20ce0cad006fce26868e24bc50\u{202C}b88514eaa4dc7c5d9676e7c1b184e9a4",
        "81fc3a20ce0cad006fce26868e24bc50b88514eaa4dc7c5d9676e7c1b184e9a4",
    );
}

#[test]
fn adv94_hellosign_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "hellosign-api-key",
        "HELLOSIGN_API_KEY=81fc3a20ce0cad006fce26868e24bc50\u{200E}b88514eaa4dc7c5d9676e7c1b184e9a4",
        "81fc3a20ce0cad006fce26868e24bc50b88514eaa4dc7c5d9676e7c1b184e9a4",
    );
}

// =========================================================================
// 8. HELPSCOUT API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv94_helpscout_api_key_normal_must_fire() {
    assert_detector_fires(
        "helpscout-api-key",
        "HELPSCOUT_API_KEY=f5b0cdd4581ec28b6767",
        "f5b0cdd4581ec28b6767",
    );
}

#[test]
fn adv94_helpscout_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("helpscout-api-key", "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv94_helpscout_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "helpscout-api-key",
        "HELPSCOUT_API_KEY=f5b0cdd458\u{200B}1ec28b6767",
        "f5b0cdd4581ec28b6767",
    );
}

#[test]
fn adv94_helpscout_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "helpscout-api-key",
        "HELPSCOUT_API_KEY=f5b0cdd458\u{00AD}1ec28b6767",
        "f5b0cdd4581ec28b6767",
    );
}

#[test]
fn adv94_helpscout_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "helpscout-api-key",
        "HELPSCOUT_API_KEY=f5b0cdd458\u{200C}1ec28b6767",
        "f5b0cdd4581ec28b6767",
    );
}

#[test]
fn adv94_helpscout_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "helpscout-api-key",
        "HELPSCOUT_API_KEY=f5b0cdd458\u{200D}1ec28b6767",
        "f5b0cdd4581ec28b6767",
    );
}

#[test]
fn adv94_helpscout_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "helpscout-api-key",
        "HELPSCOUT_API_KEY=f5b0cdd458\u{FEFF}1ec28b6767",
        "f5b0cdd4581ec28b6767",
    );
}

#[test]
fn adv94_helpscout_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "helpscout-api-key",
        "HELPSCOUT_API_KEY=f5b0cdd458\u{2060}1ec28b6767",
        "f5b0cdd4581ec28b6767",
    );
}

#[test]
fn adv94_helpscout_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "helpscout-api-key",
        "HELPSCOUT_API_KEY=f5b0cdd458\u{180E}1ec28b6767",
        "f5b0cdd4581ec28b6767",
    );
}

#[test]
fn adv94_helpscout_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "helpscout-api-key",
        "HELPSCOUT_API_KEY=f5b0cdd458\u{202E}1ec28b6767",
        "f5b0cdd4581ec28b6767",
    );
}

#[test]
fn adv94_helpscout_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "helpscout-api-key",
        "HELPSCOUT_API_KEY=f5b0cdd458\u{202C}1ec28b6767",
        "f5b0cdd4581ec28b6767",
    );
}

#[test]
fn adv94_helpscout_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "helpscout-api-key",
        "HELPSCOUT_API_KEY=f5b0cdd458\u{200E}1ec28b6767",
        "f5b0cdd4581ec28b6767",
    );
}

// =========================================================================
// 9. HERE MAPS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv94_here_maps_api_key_normal_must_fire() {
    assert_detector_fires(
        "here-maps-api-key",
        "HERE_API_KEY=JwbAykwNNL4zIbfQOSw6FvkB5uYAFzOQidAQ9PTG",
        "JwbAykwNNL4zIbfQOSw6FvkB5uYAFzOQidAQ9PTG",
    );
}

#[test]
fn adv94_here_maps_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "here-maps-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv94_here_maps_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "here-maps-api-key",
        "HERE_API_KEY=JwbAykwNNL4zIbfQOSw6\u{200B}FvkB5uYAFzOQidAQ9PTG",
        "JwbAykwNNL4zIbfQOSw6FvkB5uYAFzOQidAQ9PTG",
    );
}

#[test]
fn adv94_here_maps_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "here-maps-api-key",
        "HERE_API_KEY=JwbAykwNNL4zIbfQOSw6\u{00AD}FvkB5uYAFzOQidAQ9PTG",
        "JwbAykwNNL4zIbfQOSw6FvkB5uYAFzOQidAQ9PTG",
    );
}

#[test]
fn adv94_here_maps_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "here-maps-api-key",
        "HERE_API_KEY=JwbAykwNNL4zIbfQOSw6\u{200C}FvkB5uYAFzOQidAQ9PTG",
        "JwbAykwNNL4zIbfQOSw6FvkB5uYAFzOQidAQ9PTG",
    );
}

#[test]
fn adv94_here_maps_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "here-maps-api-key",
        "HERE_API_KEY=JwbAykwNNL4zIbfQOSw6\u{200D}FvkB5uYAFzOQidAQ9PTG",
        "JwbAykwNNL4zIbfQOSw6FvkB5uYAFzOQidAQ9PTG",
    );
}

#[test]
fn adv94_here_maps_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "here-maps-api-key",
        "HERE_API_KEY=JwbAykwNNL4zIbfQOSw6\u{FEFF}FvkB5uYAFzOQidAQ9PTG",
        "JwbAykwNNL4zIbfQOSw6FvkB5uYAFzOQidAQ9PTG",
    );
}

#[test]
fn adv94_here_maps_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "here-maps-api-key",
        "HERE_API_KEY=JwbAykwNNL4zIbfQOSw6\u{2060}FvkB5uYAFzOQidAQ9PTG",
        "JwbAykwNNL4zIbfQOSw6FvkB5uYAFzOQidAQ9PTG",
    );
}

#[test]
fn adv94_here_maps_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "here-maps-api-key",
        "HERE_API_KEY=JwbAykwNNL4zIbfQOSw6\u{180E}FvkB5uYAFzOQidAQ9PTG",
        "JwbAykwNNL4zIbfQOSw6FvkB5uYAFzOQidAQ9PTG",
    );
}

#[test]
fn adv94_here_maps_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "here-maps-api-key",
        "HERE_API_KEY=JwbAykwNNL4zIbfQOSw6\u{202E}FvkB5uYAFzOQidAQ9PTG",
        "JwbAykwNNL4zIbfQOSw6FvkB5uYAFzOQidAQ9PTG",
    );
}

#[test]
fn adv94_here_maps_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "here-maps-api-key",
        "HERE_API_KEY=JwbAykwNNL4zIbfQOSw6\u{202C}FvkB5uYAFzOQidAQ9PTG",
        "JwbAykwNNL4zIbfQOSw6FvkB5uYAFzOQidAQ9PTG",
    );
}

#[test]
fn adv94_here_maps_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "here-maps-api-key",
        "HERE_API_KEY=JwbAykwNNL4zIbfQOSw6\u{200E}FvkB5uYAFzOQidAQ9PTG",
        "JwbAykwNNL4zIbfQOSw6FvkB5uYAFzOQidAQ9PTG",
    );
}

// =========================================================================
// 10. HEROKU API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv94_heroku_api_key_normal_must_fire() {
    assert_detector_fires(
        "heroku-api-key",
        "HEROKU_API_KEY=9a3b7c2e-4d1f-6a8b-0c5d-9e3f7a1b4c2d",
        "9a3b7c2e-4d1f-6a8b-0c5d-9e3f7a1b4c2d",
    );
}

#[test]
fn adv94_heroku_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "heroku-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv94_heroku_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "heroku-api-key",
        "HEROKU_API_KEY=9a3b7c2e-4d1f-6a8b\u{200B}-0c5d-9e3f7a1b4c2d",
        "9a3b7c2e-4d1f-6a8b-0c5d-9e3f7a1b4c2d",
    );
}

#[test]
fn adv94_heroku_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "heroku-api-key",
        "HEROKU_API_KEY=9a3b7c2e-4d1f-6a8b\u{00AD}-0c5d-9e3f7a1b4c2d",
        "9a3b7c2e-4d1f-6a8b-0c5d-9e3f7a1b4c2d",
    );
}

#[test]
fn adv94_heroku_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "heroku-api-key",
        "HEROKU_API_KEY=9a3b7c2e-4d1f-6a8b\u{200C}-0c5d-9e3f7a1b4c2d",
        "9a3b7c2e-4d1f-6a8b-0c5d-9e3f7a1b4c2d",
    );
}

#[test]
fn adv94_heroku_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "heroku-api-key",
        "HEROKU_API_KEY=9a3b7c2e-4d1f-6a8b\u{200D}-0c5d-9e3f7a1b4c2d",
        "9a3b7c2e-4d1f-6a8b-0c5d-9e3f7a1b4c2d",
    );
}

#[test]
fn adv94_heroku_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "heroku-api-key",
        "HEROKU_API_KEY=9a3b7c2e-4d1f-6a8b\u{FEFF}-0c5d-9e3f7a1b4c2d",
        "9a3b7c2e-4d1f-6a8b-0c5d-9e3f7a1b4c2d",
    );
}

#[test]
fn adv94_heroku_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "heroku-api-key",
        "HEROKU_API_KEY=9a3b7c2e-4d1f-6a8b\u{2060}-0c5d-9e3f7a1b4c2d",
        "9a3b7c2e-4d1f-6a8b-0c5d-9e3f7a1b4c2d",
    );
}

#[test]
fn adv94_heroku_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "heroku-api-key",
        "HEROKU_API_KEY=9a3b7c2e-4d1f-6a8b\u{180E}-0c5d-9e3f7a1b4c2d",
        "9a3b7c2e-4d1f-6a8b-0c5d-9e3f7a1b4c2d",
    );
}

#[test]
fn adv94_heroku_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "heroku-api-key",
        "HEROKU_API_KEY=9a3b7c2e-4d1f-6a8b\u{202E}-0c5d-9e3f7a1b4c2d",
        "9a3b7c2e-4d1f-6a8b-0c5d-9e3f7a1b4c2d",
    );
}

#[test]
fn adv94_heroku_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "heroku-api-key",
        "HEROKU_API_KEY=9a3b7c2e-4d1f-6a8b\u{202C}-0c5d-9e3f7a1b4c2d",
        "9a3b7c2e-4d1f-6a8b-0c5d-9e3f7a1b4c2d",
    );
}

#[test]
fn adv94_heroku_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "heroku-api-key",
        "HEROKU_API_KEY=9a3b7c2e-4d1f-6a8b\u{200E}-0c5d-9e3f7a1b4c2d",
        "9a3b7c2e-4d1f-6a8b-0c5d-9e3f7a1b4c2d",
    );
}
