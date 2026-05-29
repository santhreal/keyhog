//! Part 131 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates stabilityai, stackblitz, starknet, statuscake, steam, storj, strapi, stripe, stripe, stytch detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. STABILITYAI API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv131_stabilityai_api_key_normal_must_fire() {
    assert_detector_fires(
        "stabilityai-api-key",
        "sk-OMnteYvYJjTJJnaDUVtiV1BAzmBQ2oOu18uWz8HSrx419wAP",
        "sk-OMnteYvYJjTJJnaDUVtiV1BAzmBQ2oOu18uWz8HSrx419wAP",
    );
}

#[test]
fn adv131_stabilityai_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "stabilityai-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv131_stabilityai_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "stabilityai-api-key",
        "sk-OMnteYvYJjTJJnaDUVtiV1\u{200B}BAzmBQ2oOu18uWz8HSrx419wAP",
        "sk-OMnteYvYJjTJJnaDUVtiV1BAzmBQ2oOu18uWz8HSrx419wAP",
    );
}

#[test]
fn adv131_stabilityai_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "stabilityai-api-key",
        "sk-OMnteYvYJjTJJnaDUVtiV1\u{00AD}BAzmBQ2oOu18uWz8HSrx419wAP",
        "sk-OMnteYvYJjTJJnaDUVtiV1BAzmBQ2oOu18uWz8HSrx419wAP",
    );
}

#[test]
fn adv131_stabilityai_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "stabilityai-api-key",
        "sk-OMnteYvYJjTJJnaDUVtiV1\u{200C}BAzmBQ2oOu18uWz8HSrx419wAP",
        "sk-OMnteYvYJjTJJnaDUVtiV1BAzmBQ2oOu18uWz8HSrx419wAP",
    );
}

#[test]
fn adv131_stabilityai_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "stabilityai-api-key",
        "sk-OMnteYvYJjTJJnaDUVtiV1\u{200D}BAzmBQ2oOu18uWz8HSrx419wAP",
        "sk-OMnteYvYJjTJJnaDUVtiV1BAzmBQ2oOu18uWz8HSrx419wAP",
    );
}

#[test]
fn adv131_stabilityai_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "stabilityai-api-key",
        "sk-OMnteYvYJjTJJnaDUVtiV1\u{FEFF}BAzmBQ2oOu18uWz8HSrx419wAP",
        "sk-OMnteYvYJjTJJnaDUVtiV1BAzmBQ2oOu18uWz8HSrx419wAP",
    );
}

#[test]
fn adv131_stabilityai_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "stabilityai-api-key",
        "sk-OMnteYvYJjTJJnaDUVtiV1\u{2060}BAzmBQ2oOu18uWz8HSrx419wAP",
        "sk-OMnteYvYJjTJJnaDUVtiV1BAzmBQ2oOu18uWz8HSrx419wAP",
    );
}

#[test]
fn adv131_stabilityai_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "stabilityai-api-key",
        "sk-OMnteYvYJjTJJnaDUVtiV1\u{180E}BAzmBQ2oOu18uWz8HSrx419wAP",
        "sk-OMnteYvYJjTJJnaDUVtiV1BAzmBQ2oOu18uWz8HSrx419wAP",
    );
}

#[test]
fn adv131_stabilityai_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "stabilityai-api-key",
        "sk-OMnteYvYJjTJJnaDUVtiV1\u{202E}BAzmBQ2oOu18uWz8HSrx419wAP",
        "sk-OMnteYvYJjTJJnaDUVtiV1BAzmBQ2oOu18uWz8HSrx419wAP",
    );
}

#[test]
fn adv131_stabilityai_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "stabilityai-api-key",
        "sk-OMnteYvYJjTJJnaDUVtiV1\u{202C}BAzmBQ2oOu18uWz8HSrx419wAP",
        "sk-OMnteYvYJjTJJnaDUVtiV1BAzmBQ2oOu18uWz8HSrx419wAP",
    );
}

#[test]
fn adv131_stabilityai_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "stabilityai-api-key",
        "sk-OMnteYvYJjTJJnaDUVtiV1\u{200E}BAzmBQ2oOu18uWz8HSrx419wAP",
        "sk-OMnteYvYJjTJJnaDUVtiV1BAzmBQ2oOu18uWz8HSrx419wAP",
    );
}

// =========================================================================
// 2. STACKBLITZ CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv131_stackblitz_credentials_normal_must_fire() {
    assert_detector_fires(
        "stackblitz-credentials",
        "sb_stTzGx1SNLO8c33WrRghshvrRC1NFXIu",
        "sb_stTzGx1SNLO8c33WrRghshvrRC1NFXIu",
    );
}

#[test]
fn adv131_stackblitz_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "stackblitz-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv131_stackblitz_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "stackblitz-credentials",
        "sb_stTzGx1SNLO8c3\u{200B}3WrRghshvrRC1NFXIu",
        "sb_stTzGx1SNLO8c33WrRghshvrRC1NFXIu",
    );
}

#[test]
fn adv131_stackblitz_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "stackblitz-credentials",
        "sb_stTzGx1SNLO8c3\u{00AD}3WrRghshvrRC1NFXIu",
        "sb_stTzGx1SNLO8c33WrRghshvrRC1NFXIu",
    );
}

#[test]
fn adv131_stackblitz_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "stackblitz-credentials",
        "sb_stTzGx1SNLO8c3\u{200C}3WrRghshvrRC1NFXIu",
        "sb_stTzGx1SNLO8c33WrRghshvrRC1NFXIu",
    );
}

#[test]
fn adv131_stackblitz_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "stackblitz-credentials",
        "sb_stTzGx1SNLO8c3\u{200D}3WrRghshvrRC1NFXIu",
        "sb_stTzGx1SNLO8c33WrRghshvrRC1NFXIu",
    );
}

#[test]
fn adv131_stackblitz_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "stackblitz-credentials",
        "sb_stTzGx1SNLO8c3\u{FEFF}3WrRghshvrRC1NFXIu",
        "sb_stTzGx1SNLO8c33WrRghshvrRC1NFXIu",
    );
}

#[test]
fn adv131_stackblitz_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "stackblitz-credentials",
        "sb_stTzGx1SNLO8c3\u{2060}3WrRghshvrRC1NFXIu",
        "sb_stTzGx1SNLO8c33WrRghshvrRC1NFXIu",
    );
}

#[test]
fn adv131_stackblitz_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "stackblitz-credentials",
        "sb_stTzGx1SNLO8c3\u{180E}3WrRghshvrRC1NFXIu",
        "sb_stTzGx1SNLO8c33WrRghshvrRC1NFXIu",
    );
}

#[test]
fn adv131_stackblitz_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "stackblitz-credentials",
        "sb_stTzGx1SNLO8c3\u{202E}3WrRghshvrRC1NFXIu",
        "sb_stTzGx1SNLO8c33WrRghshvrRC1NFXIu",
    );
}

#[test]
fn adv131_stackblitz_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "stackblitz-credentials",
        "sb_stTzGx1SNLO8c3\u{202C}3WrRghshvrRC1NFXIu",
        "sb_stTzGx1SNLO8c33WrRghshvrRC1NFXIu",
    );
}

#[test]
fn adv131_stackblitz_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "stackblitz-credentials",
        "sb_stTzGx1SNLO8c3\u{200E}3WrRghshvrRC1NFXIu",
        "sb_stTzGx1SNLO8c33WrRghshvrRC1NFXIu",
    );
}

// =========================================================================
// 3. STARKNET API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv131_starknet_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "starknet-api-credentials",
        "stark-netapikey=f1b06e41e13eac3f206b06fbd10cecb3",
        "f1b06e41e13eac3f206b06fbd10cecb3",
    );
}

#[test]
fn adv131_starknet_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "starknet-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv131_starknet_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "starknet-api-credentials",
        "stark-netapikey=f1b06e41e13eac3f\u{200B}206b06fbd10cecb3",
        "f1b06e41e13eac3f206b06fbd10cecb3",
    );
}

#[test]
fn adv131_starknet_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "starknet-api-credentials",
        "stark-netapikey=f1b06e41e13eac3f\u{00AD}206b06fbd10cecb3",
        "f1b06e41e13eac3f206b06fbd10cecb3",
    );
}

#[test]
fn adv131_starknet_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "starknet-api-credentials",
        "stark-netapikey=f1b06e41e13eac3f\u{200C}206b06fbd10cecb3",
        "f1b06e41e13eac3f206b06fbd10cecb3",
    );
}

#[test]
fn adv131_starknet_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "starknet-api-credentials",
        "stark-netapikey=f1b06e41e13eac3f\u{200D}206b06fbd10cecb3",
        "f1b06e41e13eac3f206b06fbd10cecb3",
    );
}

#[test]
fn adv131_starknet_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "starknet-api-credentials",
        "stark-netapikey=f1b06e41e13eac3f\u{FEFF}206b06fbd10cecb3",
        "f1b06e41e13eac3f206b06fbd10cecb3",
    );
}

#[test]
fn adv131_starknet_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "starknet-api-credentials",
        "stark-netapikey=f1b06e41e13eac3f\u{2060}206b06fbd10cecb3",
        "f1b06e41e13eac3f206b06fbd10cecb3",
    );
}

#[test]
fn adv131_starknet_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "starknet-api-credentials",
        "stark-netapikey=f1b06e41e13eac3f\u{180E}206b06fbd10cecb3",
        "f1b06e41e13eac3f206b06fbd10cecb3",
    );
}

#[test]
fn adv131_starknet_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "starknet-api-credentials",
        "stark-netapikey=f1b06e41e13eac3f\u{202E}206b06fbd10cecb3",
        "f1b06e41e13eac3f206b06fbd10cecb3",
    );
}

#[test]
fn adv131_starknet_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "starknet-api-credentials",
        "stark-netapikey=f1b06e41e13eac3f\u{202C}206b06fbd10cecb3",
        "f1b06e41e13eac3f206b06fbd10cecb3",
    );
}

#[test]
fn adv131_starknet_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "starknet-api-credentials",
        "stark-netapikey=f1b06e41e13eac3f\u{200E}206b06fbd10cecb3",
        "f1b06e41e13eac3f206b06fbd10cecb3",
    );
}

// =========================================================================
// 4. STATUSCAKE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv131_statuscake_api_key_normal_must_fire() {
    assert_detector_fires(
        "statuscake-api-key",
        "statuscake_api_key=qc8f2a91b7e4d6c3a5f0b8e2d7c4a9f1",
        "qc8f2a91b7e4d6c3a5f0b8e2d7c4a9f1",
    );
}

#[test]
fn adv131_statuscake_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "statuscake-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv131_statuscake_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "statuscake-api-key",
        "statuscake_api_key=qc8f2a91b7e4d6c3\u{200B}a5f0b8e2d7c4a9f1",
        "qc8f2a91b7e4d6c3a5f0b8e2d7c4a9f1",
    );
}

#[test]
fn adv131_statuscake_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "statuscake-api-key",
        "statuscake_api_key=qc8f2a91b7e4d6c3\u{00AD}a5f0b8e2d7c4a9f1",
        "qc8f2a91b7e4d6c3a5f0b8e2d7c4a9f1",
    );
}

#[test]
fn adv131_statuscake_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "statuscake-api-key",
        "statuscake_api_key=qc8f2a91b7e4d6c3\u{200C}a5f0b8e2d7c4a9f1",
        "qc8f2a91b7e4d6c3a5f0b8e2d7c4a9f1",
    );
}

#[test]
fn adv131_statuscake_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "statuscake-api-key",
        "statuscake_api_key=qc8f2a91b7e4d6c3\u{200D}a5f0b8e2d7c4a9f1",
        "qc8f2a91b7e4d6c3a5f0b8e2d7c4a9f1",
    );
}

#[test]
fn adv131_statuscake_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "statuscake-api-key",
        "statuscake_api_key=qc8f2a91b7e4d6c3\u{FEFF}a5f0b8e2d7c4a9f1",
        "qc8f2a91b7e4d6c3a5f0b8e2d7c4a9f1",
    );
}

#[test]
fn adv131_statuscake_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "statuscake-api-key",
        "statuscake_api_key=qc8f2a91b7e4d6c3\u{2060}a5f0b8e2d7c4a9f1",
        "qc8f2a91b7e4d6c3a5f0b8e2d7c4a9f1",
    );
}

#[test]
fn adv131_statuscake_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "statuscake-api-key",
        "statuscake_api_key=qc8f2a91b7e4d6c3\u{180E}a5f0b8e2d7c4a9f1",
        "qc8f2a91b7e4d6c3a5f0b8e2d7c4a9f1",
    );
}

#[test]
fn adv131_statuscake_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "statuscake-api-key",
        "statuscake_api_key=qc8f2a91b7e4d6c3\u{202E}a5f0b8e2d7c4a9f1",
        "qc8f2a91b7e4d6c3a5f0b8e2d7c4a9f1",
    );
}

#[test]
fn adv131_statuscake_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "statuscake-api-key",
        "statuscake_api_key=qc8f2a91b7e4d6c3\u{202C}a5f0b8e2d7c4a9f1",
        "qc8f2a91b7e4d6c3a5f0b8e2d7c4a9f1",
    );
}

#[test]
fn adv131_statuscake_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "statuscake-api-key",
        "statuscake_api_key=qc8f2a91b7e4d6c3\u{200E}a5f0b8e2d7c4a9f1",
        "qc8f2a91b7e4d6c3a5f0b8e2d7c4a9f1",
    );
}

// =========================================================================
// 5. STEAM API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv131_steam_api_key_normal_must_fire() {
    assert_detector_fires(
        "steam-api-key",
        "STEAM_API_KEY=15eb9b9185146a3ab266d4e7ba0c5aba",
        "15eb9b9185146a3ab266d4e7ba0c5aba",
    );
}

#[test]
fn adv131_steam_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "steam-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv131_steam_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "steam-api-key",
        "STEAM_API_KEY=15eb9b9185146a3a\u{200B}b266d4e7ba0c5aba",
        "15eb9b9185146a3ab266d4e7ba0c5aba",
    );
}

#[test]
fn adv131_steam_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "steam-api-key",
        "STEAM_API_KEY=15eb9b9185146a3a\u{00AD}b266d4e7ba0c5aba",
        "15eb9b9185146a3ab266d4e7ba0c5aba",
    );
}

#[test]
fn adv131_steam_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "steam-api-key",
        "STEAM_API_KEY=15eb9b9185146a3a\u{200C}b266d4e7ba0c5aba",
        "15eb9b9185146a3ab266d4e7ba0c5aba",
    );
}

#[test]
fn adv131_steam_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "steam-api-key",
        "STEAM_API_KEY=15eb9b9185146a3a\u{200D}b266d4e7ba0c5aba",
        "15eb9b9185146a3ab266d4e7ba0c5aba",
    );
}

#[test]
fn adv131_steam_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "steam-api-key",
        "STEAM_API_KEY=15eb9b9185146a3a\u{FEFF}b266d4e7ba0c5aba",
        "15eb9b9185146a3ab266d4e7ba0c5aba",
    );
}

#[test]
fn adv131_steam_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "steam-api-key",
        "STEAM_API_KEY=15eb9b9185146a3a\u{2060}b266d4e7ba0c5aba",
        "15eb9b9185146a3ab266d4e7ba0c5aba",
    );
}

#[test]
fn adv131_steam_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "steam-api-key",
        "STEAM_API_KEY=15eb9b9185146a3a\u{180E}b266d4e7ba0c5aba",
        "15eb9b9185146a3ab266d4e7ba0c5aba",
    );
}

#[test]
fn adv131_steam_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "steam-api-key",
        "STEAM_API_KEY=15eb9b9185146a3a\u{202E}b266d4e7ba0c5aba",
        "15eb9b9185146a3ab266d4e7ba0c5aba",
    );
}

#[test]
fn adv131_steam_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "steam-api-key",
        "STEAM_API_KEY=15eb9b9185146a3a\u{202C}b266d4e7ba0c5aba",
        "15eb9b9185146a3ab266d4e7ba0c5aba",
    );
}

#[test]
fn adv131_steam_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "steam-api-key",
        "STEAM_API_KEY=15eb9b9185146a3a\u{200E}b266d4e7ba0c5aba",
        "15eb9b9185146a3ab266d4e7ba0c5aba",
    );
}

// =========================================================================
// 6. STORJ API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv131_storj_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "storj-api-credentials",
        "STORJ_ACCESS_KEY=RNF1H3ZNBFECPXUNY5EF",
        "RNF1H3ZNBFECPXUNY5EF",
    );
}

#[test]
fn adv131_storj_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "storj-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv131_storj_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "storj-api-credentials",
        "STORJ_ACCESS_KEY=RNF1H3ZNBF\u{200B}ECPXUNY5EF",
        "RNF1H3ZNBFECPXUNY5EF",
    );
}

#[test]
fn adv131_storj_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "storj-api-credentials",
        "STORJ_ACCESS_KEY=RNF1H3ZNBF\u{00AD}ECPXUNY5EF",
        "RNF1H3ZNBFECPXUNY5EF",
    );
}

#[test]
fn adv131_storj_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "storj-api-credentials",
        "STORJ_ACCESS_KEY=RNF1H3ZNBF\u{200C}ECPXUNY5EF",
        "RNF1H3ZNBFECPXUNY5EF",
    );
}

#[test]
fn adv131_storj_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "storj-api-credentials",
        "STORJ_ACCESS_KEY=RNF1H3ZNBF\u{200D}ECPXUNY5EF",
        "RNF1H3ZNBFECPXUNY5EF",
    );
}

#[test]
fn adv131_storj_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "storj-api-credentials",
        "STORJ_ACCESS_KEY=RNF1H3ZNBF\u{FEFF}ECPXUNY5EF",
        "RNF1H3ZNBFECPXUNY5EF",
    );
}

#[test]
fn adv131_storj_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "storj-api-credentials",
        "STORJ_ACCESS_KEY=RNF1H3ZNBF\u{2060}ECPXUNY5EF",
        "RNF1H3ZNBFECPXUNY5EF",
    );
}

#[test]
fn adv131_storj_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "storj-api-credentials",
        "STORJ_ACCESS_KEY=RNF1H3ZNBF\u{180E}ECPXUNY5EF",
        "RNF1H3ZNBFECPXUNY5EF",
    );
}

#[test]
fn adv131_storj_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "storj-api-credentials",
        "STORJ_ACCESS_KEY=RNF1H3ZNBF\u{202E}ECPXUNY5EF",
        "RNF1H3ZNBFECPXUNY5EF",
    );
}

#[test]
fn adv131_storj_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "storj-api-credentials",
        "STORJ_ACCESS_KEY=RNF1H3ZNBF\u{202C}ECPXUNY5EF",
        "RNF1H3ZNBFECPXUNY5EF",
    );
}

#[test]
fn adv131_storj_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "storj-api-credentials",
        "STORJ_ACCESS_KEY=RNF1H3ZNBF\u{200E}ECPXUNY5EF",
        "RNF1H3ZNBFECPXUNY5EF",
    );
}

// =========================================================================
// 7. STRAPI API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv131_strapi_api_token_normal_must_fire() {
    assert_detector_fires(
        "strapi-api-token",
        "STRAPI_API_TOKEN=OrJrppxooyD3eXgeGAD6",
        "OrJrppxooyD3eXgeGAD6",
    );
}

#[test]
fn adv131_strapi_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "strapi-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv131_strapi_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "strapi-api-token",
        "STRAPI_API_TOKEN=OrJrppxooy\u{200B}D3eXgeGAD6",
        "OrJrppxooyD3eXgeGAD6",
    );
}

#[test]
fn adv131_strapi_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "strapi-api-token",
        "STRAPI_API_TOKEN=OrJrppxooy\u{00AD}D3eXgeGAD6",
        "OrJrppxooyD3eXgeGAD6",
    );
}

#[test]
fn adv131_strapi_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "strapi-api-token",
        "STRAPI_API_TOKEN=OrJrppxooy\u{200C}D3eXgeGAD6",
        "OrJrppxooyD3eXgeGAD6",
    );
}

#[test]
fn adv131_strapi_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "strapi-api-token",
        "STRAPI_API_TOKEN=OrJrppxooy\u{200D}D3eXgeGAD6",
        "OrJrppxooyD3eXgeGAD6",
    );
}

#[test]
fn adv131_strapi_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "strapi-api-token",
        "STRAPI_API_TOKEN=OrJrppxooy\u{FEFF}D3eXgeGAD6",
        "OrJrppxooyD3eXgeGAD6",
    );
}

#[test]
fn adv131_strapi_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "strapi-api-token",
        "STRAPI_API_TOKEN=OrJrppxooy\u{2060}D3eXgeGAD6",
        "OrJrppxooyD3eXgeGAD6",
    );
}

#[test]
fn adv131_strapi_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "strapi-api-token",
        "STRAPI_API_TOKEN=OrJrppxooy\u{180E}D3eXgeGAD6",
        "OrJrppxooyD3eXgeGAD6",
    );
}

#[test]
fn adv131_strapi_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "strapi-api-token",
        "STRAPI_API_TOKEN=OrJrppxooy\u{202E}D3eXgeGAD6",
        "OrJrppxooyD3eXgeGAD6",
    );
}

#[test]
fn adv131_strapi_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "strapi-api-token",
        "STRAPI_API_TOKEN=OrJrppxooy\u{202C}D3eXgeGAD6",
        "OrJrppxooyD3eXgeGAD6",
    );
}

#[test]
fn adv131_strapi_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "strapi-api-token",
        "STRAPI_API_TOKEN=OrJrppxooy\u{200E}D3eXgeGAD6",
        "OrJrppxooyD3eXgeGAD6",
    );
}

// =========================================================================
// 8. STRIPE SECRET KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv131_stripe_secret_key_normal_must_fire() {
    assert_detector_fires(
        "stripe-secret-key",
        "STRIPE_SECRET_KEY=sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD",
        "sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD",
    );
}

#[test]
fn adv131_stripe_secret_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "stripe-secret-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv131_stripe_secret_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "stripe-secret-key",
        "STRIPE_SECRET_KEY=sk_live_aBcDeFgHiJkLmNoP\u{200B}qRsTuVwXyZ0123456789aBcD",
        "sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD",
    );
}

#[test]
fn adv131_stripe_secret_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "stripe-secret-key",
        "STRIPE_SECRET_KEY=sk_live_aBcDeFgHiJkLmNoP\u{00AD}qRsTuVwXyZ0123456789aBcD",
        "sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD",
    );
}

#[test]
fn adv131_stripe_secret_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "stripe-secret-key",
        "STRIPE_SECRET_KEY=sk_live_aBcDeFgHiJkLmNoP\u{200C}qRsTuVwXyZ0123456789aBcD",
        "sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD",
    );
}

#[test]
fn adv131_stripe_secret_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "stripe-secret-key",
        "STRIPE_SECRET_KEY=sk_live_aBcDeFgHiJkLmNoP\u{200D}qRsTuVwXyZ0123456789aBcD",
        "sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD",
    );
}

#[test]
fn adv131_stripe_secret_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "stripe-secret-key",
        "STRIPE_SECRET_KEY=sk_live_aBcDeFgHiJkLmNoP\u{FEFF}qRsTuVwXyZ0123456789aBcD",
        "sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD",
    );
}

#[test]
fn adv131_stripe_secret_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "stripe-secret-key",
        "STRIPE_SECRET_KEY=sk_live_aBcDeFgHiJkLmNoP\u{2060}qRsTuVwXyZ0123456789aBcD",
        "sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD",
    );
}

#[test]
fn adv131_stripe_secret_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "stripe-secret-key",
        "STRIPE_SECRET_KEY=sk_live_aBcDeFgHiJkLmNoP\u{180E}qRsTuVwXyZ0123456789aBcD",
        "sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD",
    );
}

#[test]
fn adv131_stripe_secret_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "stripe-secret-key",
        "STRIPE_SECRET_KEY=sk_live_aBcDeFgHiJkLmNoP\u{202E}qRsTuVwXyZ0123456789aBcD",
        "sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD",
    );
}

#[test]
fn adv131_stripe_secret_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "stripe-secret-key",
        "STRIPE_SECRET_KEY=sk_live_aBcDeFgHiJkLmNoP\u{202C}qRsTuVwXyZ0123456789aBcD",
        "sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD",
    );
}

#[test]
fn adv131_stripe_secret_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "stripe-secret-key",
        "STRIPE_SECRET_KEY=sk_live_aBcDeFgHiJkLmNoP\u{200E}qRsTuVwXyZ0123456789aBcD",
        "sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD",
    );
}

// =========================================================================
// 9. STRIPE WEBHOOK SIGNING SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv131_stripe_webhook_signing_secret_normal_must_fire() {
    assert_detector_fires(
        "stripe-webhook-signing-secret",
        "whsec_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
        "whsec_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv131_stripe_webhook_signing_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "stripe-webhook-signing-secret",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv131_stripe_webhook_signing_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "stripe-webhook-signing-secret",
        "whsec_Kp4Qx7Rm2Sn5Tb\u{200B}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "whsec_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv131_stripe_webhook_signing_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "stripe-webhook-signing-secret",
        "whsec_Kp4Qx7Rm2Sn5Tb\u{00AD}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "whsec_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv131_stripe_webhook_signing_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "stripe-webhook-signing-secret",
        "whsec_Kp4Qx7Rm2Sn5Tb\u{200C}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "whsec_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv131_stripe_webhook_signing_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "stripe-webhook-signing-secret",
        "whsec_Kp4Qx7Rm2Sn5Tb\u{200D}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "whsec_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv131_stripe_webhook_signing_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "stripe-webhook-signing-secret",
        "whsec_Kp4Qx7Rm2Sn5Tb\u{FEFF}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "whsec_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv131_stripe_webhook_signing_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "stripe-webhook-signing-secret",
        "whsec_Kp4Qx7Rm2Sn5Tb\u{2060}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "whsec_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv131_stripe_webhook_signing_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "stripe-webhook-signing-secret",
        "whsec_Kp4Qx7Rm2Sn5Tb\u{180E}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "whsec_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv131_stripe_webhook_signing_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "stripe-webhook-signing-secret",
        "whsec_Kp4Qx7Rm2Sn5Tb\u{202E}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "whsec_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv131_stripe_webhook_signing_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "stripe-webhook-signing-secret",
        "whsec_Kp4Qx7Rm2Sn5Tb\u{202C}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "whsec_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

#[test]
fn adv131_stripe_webhook_signing_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "stripe-webhook-signing-secret",
        "whsec_Kp4Qx7Rm2Sn5Tb\u{200E}8Vw3YzKp4Qx7Rm2Sn5Tb",
        "whsec_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb",
    );
}

// =========================================================================
// 10. STYTCH MAGIC LINK CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv131_stytch_magic_link_credentials_normal_must_fire() {
    assert_detector_fires(
        "stytch-magic-link-credentials",
        "public-token-nn0jNL1VcvphMW3FPn9XgheHCSC4NgTYnDOA",
        "public-token-nn0jNL1VcvphMW3FPn9XgheHCSC4NgTYnDOA",
    );
}

#[test]
fn adv131_stytch_magic_link_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "stytch-magic-link-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv131_stytch_magic_link_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "stytch-magic-link-credentials",
        "public-token-nn0jNL1Vcvp\u{200B}hMW3FPn9XgheHCSC4NgTYnDOA",
        "public-token-nn0jNL1VcvphMW3FPn9XgheHCSC4NgTYnDOA",
    );
}

#[test]
fn adv131_stytch_magic_link_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "stytch-magic-link-credentials",
        "public-token-nn0jNL1Vcvp\u{00AD}hMW3FPn9XgheHCSC4NgTYnDOA",
        "public-token-nn0jNL1VcvphMW3FPn9XgheHCSC4NgTYnDOA",
    );
}

#[test]
fn adv131_stytch_magic_link_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "stytch-magic-link-credentials",
        "public-token-nn0jNL1Vcvp\u{200C}hMW3FPn9XgheHCSC4NgTYnDOA",
        "public-token-nn0jNL1VcvphMW3FPn9XgheHCSC4NgTYnDOA",
    );
}

#[test]
fn adv131_stytch_magic_link_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "stytch-magic-link-credentials",
        "public-token-nn0jNL1Vcvp\u{200D}hMW3FPn9XgheHCSC4NgTYnDOA",
        "public-token-nn0jNL1VcvphMW3FPn9XgheHCSC4NgTYnDOA",
    );
}

#[test]
fn adv131_stytch_magic_link_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "stytch-magic-link-credentials",
        "public-token-nn0jNL1Vcvp\u{FEFF}hMW3FPn9XgheHCSC4NgTYnDOA",
        "public-token-nn0jNL1VcvphMW3FPn9XgheHCSC4NgTYnDOA",
    );
}

#[test]
fn adv131_stytch_magic_link_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "stytch-magic-link-credentials",
        "public-token-nn0jNL1Vcvp\u{2060}hMW3FPn9XgheHCSC4NgTYnDOA",
        "public-token-nn0jNL1VcvphMW3FPn9XgheHCSC4NgTYnDOA",
    );
}

#[test]
fn adv131_stytch_magic_link_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "stytch-magic-link-credentials",
        "public-token-nn0jNL1Vcvp\u{180E}hMW3FPn9XgheHCSC4NgTYnDOA",
        "public-token-nn0jNL1VcvphMW3FPn9XgheHCSC4NgTYnDOA",
    );
}

#[test]
fn adv131_stytch_magic_link_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "stytch-magic-link-credentials",
        "public-token-nn0jNL1Vcvp\u{202E}hMW3FPn9XgheHCSC4NgTYnDOA",
        "public-token-nn0jNL1VcvphMW3FPn9XgheHCSC4NgTYnDOA",
    );
}

#[test]
fn adv131_stytch_magic_link_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "stytch-magic-link-credentials",
        "public-token-nn0jNL1Vcvp\u{202C}hMW3FPn9XgheHCSC4NgTYnDOA",
        "public-token-nn0jNL1VcvphMW3FPn9XgheHCSC4NgTYnDOA",
    );
}

#[test]
fn adv131_stytch_magic_link_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "stytch-magic-link-credentials",
        "public-token-nn0jNL1Vcvp\u{200E}hMW3FPn9XgheHCSC4NgTYnDOA",
        "public-token-nn0jNL1VcvphMW3FPn9XgheHCSC4NgTYnDOA",
    );
}


