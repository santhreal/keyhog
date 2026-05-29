//! Part 140 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates zenrows, zksync, zora, zscaler detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. ZENROWS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv140_zenrows_api_key_normal_must_fire() {
    assert_detector_fires(
        "zenrows-api-key",
        "zenrows=M4konqTT3I7XgZ2O6ii284W8pAcp4STn",
        "M4konqTT3I7XgZ2O6ii284W8pAcp4STn",
    );
}

#[test]
fn adv140_zenrows_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "zenrows-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv140_zenrows_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "zenrows-api-key",
        "zenrows=M4konqTT3I7XgZ2O\u{200B}6ii284W8pAcp4STn",
        "M4konqTT3I7XgZ2O6ii284W8pAcp4STn",
    );
}

#[test]
fn adv140_zenrows_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "zenrows-api-key",
        "zenrows=M4konqTT3I7XgZ2O\u{00AD}6ii284W8pAcp4STn",
        "M4konqTT3I7XgZ2O6ii284W8pAcp4STn",
    );
}

#[test]
fn adv140_zenrows_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "zenrows-api-key",
        "zenrows=M4konqTT3I7XgZ2O\u{200C}6ii284W8pAcp4STn",
        "M4konqTT3I7XgZ2O6ii284W8pAcp4STn",
    );
}

#[test]
fn adv140_zenrows_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "zenrows-api-key",
        "zenrows=M4konqTT3I7XgZ2O\u{200D}6ii284W8pAcp4STn",
        "M4konqTT3I7XgZ2O6ii284W8pAcp4STn",
    );
}

#[test]
fn adv140_zenrows_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "zenrows-api-key",
        "zenrows=M4konqTT3I7XgZ2O\u{FEFF}6ii284W8pAcp4STn",
        "M4konqTT3I7XgZ2O6ii284W8pAcp4STn",
    );
}

#[test]
fn adv140_zenrows_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "zenrows-api-key",
        "zenrows=M4konqTT3I7XgZ2O\u{2060}6ii284W8pAcp4STn",
        "M4konqTT3I7XgZ2O6ii284W8pAcp4STn",
    );
}

#[test]
fn adv140_zenrows_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "zenrows-api-key",
        "zenrows=M4konqTT3I7XgZ2O\u{180E}6ii284W8pAcp4STn",
        "M4konqTT3I7XgZ2O6ii284W8pAcp4STn",
    );
}

#[test]
fn adv140_zenrows_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "zenrows-api-key",
        "zenrows=M4konqTT3I7XgZ2O\u{202E}6ii284W8pAcp4STn",
        "M4konqTT3I7XgZ2O6ii284W8pAcp4STn",
    );
}

#[test]
fn adv140_zenrows_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "zenrows-api-key",
        "zenrows=M4konqTT3I7XgZ2O\u{202C}6ii284W8pAcp4STn",
        "M4konqTT3I7XgZ2O6ii284W8pAcp4STn",
    );
}

#[test]
fn adv140_zenrows_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "zenrows-api-key",
        "zenrows=M4konqTT3I7XgZ2O\u{200E}6ii284W8pAcp4STn",
        "M4konqTT3I7XgZ2O6ii284W8pAcp4STn",
    );
}

// =========================================================================
// 2. ZKSYNC API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv140_zksync_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "zksync-api-credentials",
        "zk-sync.rpcurl =  =    http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqwodugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
        "http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqwodugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
    );
}

#[test]
fn adv140_zksync_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "zksync-api-credentials",
        "dummy_prefix_0 =  =    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv140_zksync_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "zksync-api-credentials",
        "zk-sync.rpcurl =  =    http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqw\u{200B}odugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
        "http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqwodugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
    );
}

#[test]
fn adv140_zksync_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "zksync-api-credentials",
        "zk-sync.rpcurl =  =    http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqw\u{00AD}odugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
        "http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqwodugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
    );
}

#[test]
fn adv140_zksync_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "zksync-api-credentials",
        "zk-sync.rpcurl =  =    http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqw\u{200C}odugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
        "http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqwodugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
    );
}

#[test]
fn adv140_zksync_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "zksync-api-credentials",
        "zk-sync.rpcurl =  =    http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqw\u{200D}odugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
        "http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqwodugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
    );
}

#[test]
fn adv140_zksync_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "zksync-api-credentials",
        "zk-sync.rpcurl =  =    http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqw\u{FEFF}odugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
        "http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqwodugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
    );
}

#[test]
fn adv140_zksync_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "zksync-api-credentials",
        "zk-sync.rpcurl =  =    http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqw\u{2060}odugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
        "http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqwodugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
    );
}

#[test]
fn adv140_zksync_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "zksync-api-credentials",
        "zk-sync.rpcurl =  =    http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqw\u{180E}odugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
        "http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqwodugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
    );
}

#[test]
fn adv140_zksync_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "zksync-api-credentials",
        "zk-sync.rpcurl =  =    http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqw\u{202E}odugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
        "http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqwodugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
    );
}

#[test]
fn adv140_zksync_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "zksync-api-credentials",
        "zk-sync.rpcurl =  =    http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqw\u{202C}odugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
        "http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqwodugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
    );
}

#[test]
fn adv140_zksync_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "zksync-api-credentials",
        "zk-sync.rpcurl =  =    http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqw\u{200E}odugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
        "http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqwodugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ",
    );
}

// =========================================================================
// 3. ZORA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv140_zora_api_key_normal_must_fire() {
    assert_detector_fires(
        "zora-api-key",
        "ZORA API KEY = \"k7mNp2qRs4tUv8wXy1zA3bC5dEfGhIj",
        "k7mNp2qRs4tUv8wXy1zA3bC5dEfGhIj",
    );
}

#[test]
fn adv140_zora_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "zora-api-key",
        "dummy_prefix_0 = \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv140_zora_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "zora-api-key",
        "ZORA API KEY = \"k7mNp2qRs4tUv8w\u{200B}Xy1zA3bC5dEfGhIj",
        "k7mNp2qRs4tUv8wXy1zA3bC5dEfGhIj",
    );
}

#[test]
fn adv140_zora_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "zora-api-key",
        "ZORA API KEY = \"k7mNp2qRs4tUv8w\u{00AD}Xy1zA3bC5dEfGhIj",
        "k7mNp2qRs4tUv8wXy1zA3bC5dEfGhIj",
    );
}

#[test]
fn adv140_zora_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "zora-api-key",
        "ZORA API KEY = \"k7mNp2qRs4tUv8w\u{200C}Xy1zA3bC5dEfGhIj",
        "k7mNp2qRs4tUv8wXy1zA3bC5dEfGhIj",
    );
}

#[test]
fn adv140_zora_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "zora-api-key",
        "ZORA API KEY = \"k7mNp2qRs4tUv8w\u{200D}Xy1zA3bC5dEfGhIj",
        "k7mNp2qRs4tUv8wXy1zA3bC5dEfGhIj",
    );
}

#[test]
fn adv140_zora_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "zora-api-key",
        "ZORA API KEY = \"k7mNp2qRs4tUv8w\u{FEFF}Xy1zA3bC5dEfGhIj",
        "k7mNp2qRs4tUv8wXy1zA3bC5dEfGhIj",
    );
}

#[test]
fn adv140_zora_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "zora-api-key",
        "ZORA API KEY = \"k7mNp2qRs4tUv8w\u{2060}Xy1zA3bC5dEfGhIj",
        "k7mNp2qRs4tUv8wXy1zA3bC5dEfGhIj",
    );
}

#[test]
fn adv140_zora_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "zora-api-key",
        "ZORA API KEY = \"k7mNp2qRs4tUv8w\u{180E}Xy1zA3bC5dEfGhIj",
        "k7mNp2qRs4tUv8wXy1zA3bC5dEfGhIj",
    );
}

#[test]
fn adv140_zora_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "zora-api-key",
        "ZORA API KEY = \"k7mNp2qRs4tUv8w\u{202E}Xy1zA3bC5dEfGhIj",
        "k7mNp2qRs4tUv8wXy1zA3bC5dEfGhIj",
    );
}

#[test]
fn adv140_zora_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "zora-api-key",
        "ZORA API KEY = \"k7mNp2qRs4tUv8w\u{202C}Xy1zA3bC5dEfGhIj",
        "k7mNp2qRs4tUv8wXy1zA3bC5dEfGhIj",
    );
}

#[test]
fn adv140_zora_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "zora-api-key",
        "ZORA API KEY = \"k7mNp2qRs4tUv8w\u{200E}Xy1zA3bC5dEfGhIj",
        "k7mNp2qRs4tUv8wXy1zA3bC5dEfGhIj",
    );
}

// =========================================================================
// 4. ZSCALER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv140_zscaler_api_key_normal_must_fire() {
    assert_detector_fires(
        "zscaler-api-key",
        "ZSCALERID=tNQHjfW1z0NhsUM9rf5jQ2MF",
        "tNQHjfW1z0NhsUM9rf5jQ2MF",
    );
}

#[test]
fn adv140_zscaler_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "zscaler-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv140_zscaler_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "zscaler-api-key",
        "ZSCALERID=tNQHjfW1z0Nh\u{200B}sUM9rf5jQ2MF",
        "tNQHjfW1z0NhsUM9rf5jQ2MF",
    );
}

#[test]
fn adv140_zscaler_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "zscaler-api-key",
        "ZSCALERID=tNQHjfW1z0Nh\u{00AD}sUM9rf5jQ2MF",
        "tNQHjfW1z0NhsUM9rf5jQ2MF",
    );
}

#[test]
fn adv140_zscaler_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "zscaler-api-key",
        "ZSCALERID=tNQHjfW1z0Nh\u{200C}sUM9rf5jQ2MF",
        "tNQHjfW1z0NhsUM9rf5jQ2MF",
    );
}

#[test]
fn adv140_zscaler_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "zscaler-api-key",
        "ZSCALERID=tNQHjfW1z0Nh\u{200D}sUM9rf5jQ2MF",
        "tNQHjfW1z0NhsUM9rf5jQ2MF",
    );
}

#[test]
fn adv140_zscaler_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "zscaler-api-key",
        "ZSCALERID=tNQHjfW1z0Nh\u{FEFF}sUM9rf5jQ2MF",
        "tNQHjfW1z0NhsUM9rf5jQ2MF",
    );
}

#[test]
fn adv140_zscaler_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "zscaler-api-key",
        "ZSCALERID=tNQHjfW1z0Nh\u{2060}sUM9rf5jQ2MF",
        "tNQHjfW1z0NhsUM9rf5jQ2MF",
    );
}

#[test]
fn adv140_zscaler_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "zscaler-api-key",
        "ZSCALERID=tNQHjfW1z0Nh\u{180E}sUM9rf5jQ2MF",
        "tNQHjfW1z0NhsUM9rf5jQ2MF",
    );
}

#[test]
fn adv140_zscaler_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "zscaler-api-key",
        "ZSCALERID=tNQHjfW1z0Nh\u{202E}sUM9rf5jQ2MF",
        "tNQHjfW1z0NhsUM9rf5jQ2MF",
    );
}

#[test]
fn adv140_zscaler_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "zscaler-api-key",
        "ZSCALERID=tNQHjfW1z0Nh\u{202C}sUM9rf5jQ2MF",
        "tNQHjfW1z0NhsUM9rf5jQ2MF",
    );
}

#[test]
fn adv140_zscaler_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "zscaler-api-key",
        "ZSCALERID=tNQHjfW1z0Nh\u{200E}sUM9rf5jQ2MF",
        "tNQHjfW1z0NhsUM9rf5jQ2MF",
    );
}


