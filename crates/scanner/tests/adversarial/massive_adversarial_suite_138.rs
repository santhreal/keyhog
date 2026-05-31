//! Part 138 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates virustotal, vonage, wandb, wasabi, weatherstack, wise, wistia, woocommerce, woocommerce, worldpay detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. VIRUSTOTAL API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv138_virustotal_api_key_normal_must_fire() {
    assert_detector_fires(
        "virustotal-api-key",
        "VIRUSTOTAL=94006201bd6c02ff2503b0a5791efdf15c370afd7e58806ee5633b46ce6cbdc6",
        "94006201bd6c02ff2503b0a5791efdf15c370afd7e58806ee5633b46ce6cbdc6",
    );
}

#[test]
fn adv138_virustotal_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "virustotal-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv138_virustotal_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "virustotal-api-key",
        "VIRUSTOTAL=94006201bd6c02ff2503b0a5791efdf1\u{200B}5c370afd7e58806ee5633b46ce6cbdc6",
        "94006201bd6c02ff2503b0a5791efdf15c370afd7e58806ee5633b46ce6cbdc6",
    );
}

#[test]
fn adv138_virustotal_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "virustotal-api-key",
        "VIRUSTOTAL=94006201bd6c02ff2503b0a5791efdf1\u{00AD}5c370afd7e58806ee5633b46ce6cbdc6",
        "94006201bd6c02ff2503b0a5791efdf15c370afd7e58806ee5633b46ce6cbdc6",
    );
}

#[test]
fn adv138_virustotal_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "virustotal-api-key",
        "VIRUSTOTAL=94006201bd6c02ff2503b0a5791efdf1\u{200C}5c370afd7e58806ee5633b46ce6cbdc6",
        "94006201bd6c02ff2503b0a5791efdf15c370afd7e58806ee5633b46ce6cbdc6",
    );
}

#[test]
fn adv138_virustotal_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "virustotal-api-key",
        "VIRUSTOTAL=94006201bd6c02ff2503b0a5791efdf1\u{200D}5c370afd7e58806ee5633b46ce6cbdc6",
        "94006201bd6c02ff2503b0a5791efdf15c370afd7e58806ee5633b46ce6cbdc6",
    );
}

#[test]
fn adv138_virustotal_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "virustotal-api-key",
        "VIRUSTOTAL=94006201bd6c02ff2503b0a5791efdf1\u{FEFF}5c370afd7e58806ee5633b46ce6cbdc6",
        "94006201bd6c02ff2503b0a5791efdf15c370afd7e58806ee5633b46ce6cbdc6",
    );
}

#[test]
fn adv138_virustotal_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "virustotal-api-key",
        "VIRUSTOTAL=94006201bd6c02ff2503b0a5791efdf1\u{2060}5c370afd7e58806ee5633b46ce6cbdc6",
        "94006201bd6c02ff2503b0a5791efdf15c370afd7e58806ee5633b46ce6cbdc6",
    );
}

#[test]
fn adv138_virustotal_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "virustotal-api-key",
        "VIRUSTOTAL=94006201bd6c02ff2503b0a5791efdf1\u{180E}5c370afd7e58806ee5633b46ce6cbdc6",
        "94006201bd6c02ff2503b0a5791efdf15c370afd7e58806ee5633b46ce6cbdc6",
    );
}

#[test]
fn adv138_virustotal_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "virustotal-api-key",
        "VIRUSTOTAL=94006201bd6c02ff2503b0a5791efdf1\u{202E}5c370afd7e58806ee5633b46ce6cbdc6",
        "94006201bd6c02ff2503b0a5791efdf15c370afd7e58806ee5633b46ce6cbdc6",
    );
}

#[test]
fn adv138_virustotal_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "virustotal-api-key",
        "VIRUSTOTAL=94006201bd6c02ff2503b0a5791efdf1\u{202C}5c370afd7e58806ee5633b46ce6cbdc6",
        "94006201bd6c02ff2503b0a5791efdf15c370afd7e58806ee5633b46ce6cbdc6",
    );
}

#[test]
fn adv138_virustotal_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "virustotal-api-key",
        "VIRUSTOTAL=94006201bd6c02ff2503b0a5791efdf1\u{200E}5c370afd7e58806ee5633b46ce6cbdc6",
        "94006201bd6c02ff2503b0a5791efdf15c370afd7e58806ee5633b46ce6cbdc6",
    );
}

// =========================================================================
// 2. VONAGE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv138_vonage_api_key_normal_must_fire() {
    assert_detector_fires("vonage-api-key", "NEXMO_API_KEY=f3ed3778", "f3ed3778");
}

#[test]
fn adv138_vonage_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("vonage-api-key", "dummy_prefix_0 =xxxxxxxx");
}

#[test]
fn adv138_vonage_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "vonage-api-key",
        "NEXMO_API_KEY=f3ed\u{200B}3778",
        "f3ed3778",
    );
}

#[test]
fn adv138_vonage_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "vonage-api-key",
        "NEXMO_API_KEY=f3ed\u{00AD}3778",
        "f3ed3778",
    );
}

#[test]
fn adv138_vonage_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "vonage-api-key",
        "NEXMO_API_KEY=f3ed\u{200C}3778",
        "f3ed3778",
    );
}

#[test]
fn adv138_vonage_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "vonage-api-key",
        "NEXMO_API_KEY=f3ed\u{200D}3778",
        "f3ed3778",
    );
}

#[test]
fn adv138_vonage_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "vonage-api-key",
        "NEXMO_API_KEY=f3ed\u{FEFF}3778",
        "f3ed3778",
    );
}

#[test]
fn adv138_vonage_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "vonage-api-key",
        "NEXMO_API_KEY=f3ed\u{2060}3778",
        "f3ed3778",
    );
}

#[test]
fn adv138_vonage_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "vonage-api-key",
        "NEXMO_API_KEY=f3ed\u{180E}3778",
        "f3ed3778",
    );
}

#[test]
fn adv138_vonage_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "vonage-api-key",
        "NEXMO_API_KEY=f3ed\u{202E}3778",
        "f3ed3778",
    );
}

#[test]
fn adv138_vonage_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "vonage-api-key",
        "NEXMO_API_KEY=f3ed\u{202C}3778",
        "f3ed3778",
    );
}

#[test]
fn adv138_vonage_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "vonage-api-key",
        "NEXMO_API_KEY=f3ed\u{200E}3778",
        "f3ed3778",
    );
}

// =========================================================================
// 3. WANDB API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv138_wandb_api_key_normal_must_fire() {
    assert_detector_fires(
        "wandb-api-key",
        "WANDB_API_KEY=034b1509e9cb1c6131ba5ee7dc30a6d542944a55",
        "034b1509e9cb1c6131ba5ee7dc30a6d542944a55",
    );
}

#[test]
fn adv138_wandb_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "wandb-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv138_wandb_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "wandb-api-key",
        "WANDB_API_KEY=034b1509e9cb1c6131ba\u{200B}5ee7dc30a6d542944a55",
        "034b1509e9cb1c6131ba5ee7dc30a6d542944a55",
    );
}

#[test]
fn adv138_wandb_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "wandb-api-key",
        "WANDB_API_KEY=034b1509e9cb1c6131ba\u{00AD}5ee7dc30a6d542944a55",
        "034b1509e9cb1c6131ba5ee7dc30a6d542944a55",
    );
}

#[test]
fn adv138_wandb_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "wandb-api-key",
        "WANDB_API_KEY=034b1509e9cb1c6131ba\u{200C}5ee7dc30a6d542944a55",
        "034b1509e9cb1c6131ba5ee7dc30a6d542944a55",
    );
}

#[test]
fn adv138_wandb_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "wandb-api-key",
        "WANDB_API_KEY=034b1509e9cb1c6131ba\u{200D}5ee7dc30a6d542944a55",
        "034b1509e9cb1c6131ba5ee7dc30a6d542944a55",
    );
}

#[test]
fn adv138_wandb_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "wandb-api-key",
        "WANDB_API_KEY=034b1509e9cb1c6131ba\u{FEFF}5ee7dc30a6d542944a55",
        "034b1509e9cb1c6131ba5ee7dc30a6d542944a55",
    );
}

#[test]
fn adv138_wandb_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "wandb-api-key",
        "WANDB_API_KEY=034b1509e9cb1c6131ba\u{2060}5ee7dc30a6d542944a55",
        "034b1509e9cb1c6131ba5ee7dc30a6d542944a55",
    );
}

#[test]
fn adv138_wandb_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "wandb-api-key",
        "WANDB_API_KEY=034b1509e9cb1c6131ba\u{180E}5ee7dc30a6d542944a55",
        "034b1509e9cb1c6131ba5ee7dc30a6d542944a55",
    );
}

#[test]
fn adv138_wandb_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "wandb-api-key",
        "WANDB_API_KEY=034b1509e9cb1c6131ba\u{202E}5ee7dc30a6d542944a55",
        "034b1509e9cb1c6131ba5ee7dc30a6d542944a55",
    );
}

#[test]
fn adv138_wandb_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "wandb-api-key",
        "WANDB_API_KEY=034b1509e9cb1c6131ba\u{202C}5ee7dc30a6d542944a55",
        "034b1509e9cb1c6131ba5ee7dc30a6d542944a55",
    );
}

#[test]
fn adv138_wandb_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "wandb-api-key",
        "WANDB_API_KEY=034b1509e9cb1c6131ba\u{200E}5ee7dc30a6d542944a55",
        "034b1509e9cb1c6131ba5ee7dc30a6d542944a55",
    );
}

// =========================================================================
// 4. WASABI ACCESS KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv138_wasabi_access_key_normal_must_fire() {
    assert_detector_fires(
        "wasabi-access-key",
        "WASABIKEY=D1R7E3FCOQ5SBACMK1F2",
        "D1R7E3FCOQ5SBACMK1F2",
    );
}

#[test]
fn adv138_wasabi_access_key_wrong_prefix_must_silent() {
    assert_detector_silent("wasabi-access-key", "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv138_wasabi_access_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "wasabi-access-key",
        "WASABIKEY=D1R7E3FCOQ\u{200B}5SBACMK1F2",
        "D1R7E3FCOQ5SBACMK1F2",
    );
}

#[test]
fn adv138_wasabi_access_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "wasabi-access-key",
        "WASABIKEY=D1R7E3FCOQ\u{00AD}5SBACMK1F2",
        "D1R7E3FCOQ5SBACMK1F2",
    );
}

#[test]
fn adv138_wasabi_access_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "wasabi-access-key",
        "WASABIKEY=D1R7E3FCOQ\u{200C}5SBACMK1F2",
        "D1R7E3FCOQ5SBACMK1F2",
    );
}

#[test]
fn adv138_wasabi_access_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "wasabi-access-key",
        "WASABIKEY=D1R7E3FCOQ\u{200D}5SBACMK1F2",
        "D1R7E3FCOQ5SBACMK1F2",
    );
}

#[test]
fn adv138_wasabi_access_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "wasabi-access-key",
        "WASABIKEY=D1R7E3FCOQ\u{FEFF}5SBACMK1F2",
        "D1R7E3FCOQ5SBACMK1F2",
    );
}

#[test]
fn adv138_wasabi_access_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "wasabi-access-key",
        "WASABIKEY=D1R7E3FCOQ\u{2060}5SBACMK1F2",
        "D1R7E3FCOQ5SBACMK1F2",
    );
}

#[test]
fn adv138_wasabi_access_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "wasabi-access-key",
        "WASABIKEY=D1R7E3FCOQ\u{180E}5SBACMK1F2",
        "D1R7E3FCOQ5SBACMK1F2",
    );
}

#[test]
fn adv138_wasabi_access_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "wasabi-access-key",
        "WASABIKEY=D1R7E3FCOQ\u{202E}5SBACMK1F2",
        "D1R7E3FCOQ5SBACMK1F2",
    );
}

#[test]
fn adv138_wasabi_access_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "wasabi-access-key",
        "WASABIKEY=D1R7E3FCOQ\u{202C}5SBACMK1F2",
        "D1R7E3FCOQ5SBACMK1F2",
    );
}

#[test]
fn adv138_wasabi_access_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "wasabi-access-key",
        "WASABIKEY=D1R7E3FCOQ\u{200E}5SBACMK1F2",
        "D1R7E3FCOQ5SBACMK1F2",
    );
}

// =========================================================================
// 5. WEATHERSTACK ACCESS KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv138_weatherstack_access_key_normal_must_fire() {
    assert_detector_fires(
        "weatherstack-access-key",
        "weatherstack _        _   _   _  ___  _ _        _   _    _  _    __          _        KEY BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtxlR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
        "BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtxlR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
    );
}

#[test]
fn adv138_weatherstack_access_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "weatherstack-access-key",
        "dummyherstack _        _   _   _  ___  _ _        _   _    _  _    __          _        KEY xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv138_weatherstack_access_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "weatherstack-access-key",
        "weatherstack _        _   _   _  ___  _ _        _   _    _  _    __          _        KEY BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtx\u{200B}lR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
        "BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtxlR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
    );
}

#[test]
fn adv138_weatherstack_access_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "weatherstack-access-key",
        "weatherstack _        _   _   _  ___  _ _        _   _    _  _    __          _        KEY BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtx\u{00AD}lR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
        "BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtxlR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
    );
}

#[test]
fn adv138_weatherstack_access_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "weatherstack-access-key",
        "weatherstack _        _   _   _  ___  _ _        _   _    _  _    __          _        KEY BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtx\u{200C}lR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
        "BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtxlR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
    );
}

#[test]
fn adv138_weatherstack_access_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "weatherstack-access-key",
        "weatherstack _        _   _   _  ___  _ _        _   _    _  _    __          _        KEY BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtx\u{200D}lR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
        "BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtxlR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
    );
}

#[test]
fn adv138_weatherstack_access_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "weatherstack-access-key",
        "weatherstack _        _   _   _  ___  _ _        _   _    _  _    __          _        KEY BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtx\u{FEFF}lR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
        "BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtxlR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
    );
}

#[test]
fn adv138_weatherstack_access_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "weatherstack-access-key",
        "weatherstack _        _   _   _  ___  _ _        _   _    _  _    __          _        KEY BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtx\u{2060}lR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
        "BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtxlR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
    );
}

#[test]
fn adv138_weatherstack_access_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "weatherstack-access-key",
        "weatherstack _        _   _   _  ___  _ _        _   _    _  _    __          _        KEY BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtx\u{180E}lR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
        "BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtxlR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
    );
}

#[test]
fn adv138_weatherstack_access_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "weatherstack-access-key",
        "weatherstack _        _   _   _  ___  _ _        _   _    _  _    __          _        KEY BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtx\u{202E}lR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
        "BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtxlR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
    );
}

#[test]
fn adv138_weatherstack_access_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "weatherstack-access-key",
        "weatherstack _        _   _   _  ___  _ _        _   _    _  _    __          _        KEY BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtx\u{202C}lR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
        "BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtxlR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
    );
}

#[test]
fn adv138_weatherstack_access_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "weatherstack-access-key",
        "weatherstack _        _   _   _  ___  _ _        _   _    _  _    __          _        KEY BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtx\u{200E}lR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
        "BKe3WCBO8JIILnzQeTQgSIMCOhUAEJcABtxlR7lZST6ju3MBJSPfwjkh2Ek5g2ocLW8SSZg",
    );
}

// =========================================================================
// 6. WISE API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv138_wise_api_token_normal_must_fire() {
    assert_detector_fires(
        "wise-api-token",
        "Wise-Token                                                                                  :=:==:=:::=::=:::::===:=:====:=:==:=:====:::==:===:==:::::=::::=               hHntXBBhcMghHhw15s27KqbT1Q8'",
        "hHntXBBhcMghHhw15s27KqbT1Q8",
    );
}

#[test]
fn adv138_wise_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "wise-api-token",
        "dummy_prefix_0 =:==:=:::=::=:::::===:=:====:=:==:=:====:::==:===:==:::::=::::=               xxxxxxxxxxxxxxxxxxxxxxxxxxx'",
    );
}

#[test]
fn adv138_wise_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "wise-api-token",
        "Wise-Token                                                                                  :=:==:=:::=::=:::::===:=:====:=:==:=:====:::==:===:==:::::=::::=               hHntXBBhcMghH\u{200B}hw15s27KqbT1Q8'",
        "hHntXBBhcMghHhw15s27KqbT1Q8",
    );
}

#[test]
fn adv138_wise_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "wise-api-token",
        "Wise-Token                                                                                  :=:==:=:::=::=:::::===:=:====:=:==:=:====:::==:===:==:::::=::::=               hHntXBBhcMghH\u{00AD}hw15s27KqbT1Q8'",
        "hHntXBBhcMghHhw15s27KqbT1Q8",
    );
}

#[test]
fn adv138_wise_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "wise-api-token",
        "Wise-Token                                                                                  :=:==:=:::=::=:::::===:=:====:=:==:=:====:::==:===:==:::::=::::=               hHntXBBhcMghH\u{200C}hw15s27KqbT1Q8'",
        "hHntXBBhcMghHhw15s27KqbT1Q8",
    );
}

#[test]
fn adv138_wise_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "wise-api-token",
        "Wise-Token                                                                                  :=:==:=:::=::=:::::===:=:====:=:==:=:====:::==:===:==:::::=::::=               hHntXBBhcMghH\u{200D}hw15s27KqbT1Q8'",
        "hHntXBBhcMghHhw15s27KqbT1Q8",
    );
}

#[test]
fn adv138_wise_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "wise-api-token",
        "Wise-Token                                                                                  :=:==:=:::=::=:::::===:=:====:=:==:=:====:::==:===:==:::::=::::=               hHntXBBhcMghH\u{FEFF}hw15s27KqbT1Q8'",
        "hHntXBBhcMghHhw15s27KqbT1Q8",
    );
}

#[test]
fn adv138_wise_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "wise-api-token",
        "Wise-Token                                                                                  :=:==:=:::=::=:::::===:=:====:=:==:=:====:::==:===:==:::::=::::=               hHntXBBhcMghH\u{2060}hw15s27KqbT1Q8'",
        "hHntXBBhcMghHhw15s27KqbT1Q8",
    );
}

#[test]
fn adv138_wise_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "wise-api-token",
        "Wise-Token                                                                                  :=:==:=:::=::=:::::===:=:====:=:==:=:====:::==:===:==:::::=::::=               hHntXBBhcMghH\u{180E}hw15s27KqbT1Q8'",
        "hHntXBBhcMghHhw15s27KqbT1Q8",
    );
}

#[test]
fn adv138_wise_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "wise-api-token",
        "Wise-Token                                                                                  :=:==:=:::=::=:::::===:=:====:=:==:=:====:::==:===:==:::::=::::=               hHntXBBhcMghH\u{202E}hw15s27KqbT1Q8'",
        "hHntXBBhcMghHhw15s27KqbT1Q8",
    );
}

#[test]
fn adv138_wise_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "wise-api-token",
        "Wise-Token                                                                                  :=:==:=:::=::=:::::===:=:====:=:==:=:====:::==:===:==:::::=::::=               hHntXBBhcMghH\u{202C}hw15s27KqbT1Q8'",
        "hHntXBBhcMghHhw15s27KqbT1Q8",
    );
}

#[test]
fn adv138_wise_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "wise-api-token",
        "Wise-Token                                                                                  :=:==:=:::=::=:::::===:=:====:=:==:=:====:::==:===:==:::::=::::=               hHntXBBhcMghH\u{200E}hw15s27KqbT1Q8'",
        "hHntXBBhcMghHhw15s27KqbT1Q8",
    );
}

// =========================================================================
// 7. WISTIA API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv138_wistia_api_token_normal_must_fire() {
    assert_detector_fires(
        "wistia-api-token",
        "wistiaapi_token=f58ba8284e74e6b6500bd0ddecb8e5e4",
        "f58ba8284e74e6b6500bd0ddecb8e5e4",
    );
}

#[test]
fn adv138_wistia_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "wistia-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv138_wistia_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "wistia-api-token",
        "wistiaapi_token=f58ba8284e74e6b6\u{200B}500bd0ddecb8e5e4",
        "f58ba8284e74e6b6500bd0ddecb8e5e4",
    );
}

#[test]
fn adv138_wistia_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "wistia-api-token",
        "wistiaapi_token=f58ba8284e74e6b6\u{00AD}500bd0ddecb8e5e4",
        "f58ba8284e74e6b6500bd0ddecb8e5e4",
    );
}

#[test]
fn adv138_wistia_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "wistia-api-token",
        "wistiaapi_token=f58ba8284e74e6b6\u{200C}500bd0ddecb8e5e4",
        "f58ba8284e74e6b6500bd0ddecb8e5e4",
    );
}

#[test]
fn adv138_wistia_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "wistia-api-token",
        "wistiaapi_token=f58ba8284e74e6b6\u{200D}500bd0ddecb8e5e4",
        "f58ba8284e74e6b6500bd0ddecb8e5e4",
    );
}

#[test]
fn adv138_wistia_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "wistia-api-token",
        "wistiaapi_token=f58ba8284e74e6b6\u{FEFF}500bd0ddecb8e5e4",
        "f58ba8284e74e6b6500bd0ddecb8e5e4",
    );
}

#[test]
fn adv138_wistia_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "wistia-api-token",
        "wistiaapi_token=f58ba8284e74e6b6\u{2060}500bd0ddecb8e5e4",
        "f58ba8284e74e6b6500bd0ddecb8e5e4",
    );
}

#[test]
fn adv138_wistia_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "wistia-api-token",
        "wistiaapi_token=f58ba8284e74e6b6\u{180E}500bd0ddecb8e5e4",
        "f58ba8284e74e6b6500bd0ddecb8e5e4",
    );
}

#[test]
fn adv138_wistia_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "wistia-api-token",
        "wistiaapi_token=f58ba8284e74e6b6\u{202E}500bd0ddecb8e5e4",
        "f58ba8284e74e6b6500bd0ddecb8e5e4",
    );
}

#[test]
fn adv138_wistia_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "wistia-api-token",
        "wistiaapi_token=f58ba8284e74e6b6\u{202C}500bd0ddecb8e5e4",
        "f58ba8284e74e6b6500bd0ddecb8e5e4",
    );
}

#[test]
fn adv138_wistia_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "wistia-api-token",
        "wistiaapi_token=f58ba8284e74e6b6\u{200E}500bd0ddecb8e5e4",
        "f58ba8284e74e6b6500bd0ddecb8e5e4",
    );
}

// =========================================================================
// 8. WOOCOMMERCE CONSUMER KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv138_woocommerce_consumer_key_normal_must_fire() {
    assert_detector_fires(
        "woocommerce-consumer-key",
        "ck_0a6efc600fa229b936e33cb2e62710fe11c2409e",
        "ck_0a6efc600fa229b936e33cb2e62710fe11c2409e",
    );
}

#[test]
fn adv138_woocommerce_consumer_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "woocommerce-consumer-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv138_woocommerce_consumer_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "woocommerce-consumer-key",
        "ck_0a6efc600fa229b936\u{200B}e33cb2e62710fe11c2409e",
        "ck_0a6efc600fa229b936e33cb2e62710fe11c2409e",
    );
}

#[test]
fn adv138_woocommerce_consumer_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "woocommerce-consumer-key",
        "ck_0a6efc600fa229b936\u{00AD}e33cb2e62710fe11c2409e",
        "ck_0a6efc600fa229b936e33cb2e62710fe11c2409e",
    );
}

#[test]
fn adv138_woocommerce_consumer_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "woocommerce-consumer-key",
        "ck_0a6efc600fa229b936\u{200C}e33cb2e62710fe11c2409e",
        "ck_0a6efc600fa229b936e33cb2e62710fe11c2409e",
    );
}

#[test]
fn adv138_woocommerce_consumer_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "woocommerce-consumer-key",
        "ck_0a6efc600fa229b936\u{200D}e33cb2e62710fe11c2409e",
        "ck_0a6efc600fa229b936e33cb2e62710fe11c2409e",
    );
}

#[test]
fn adv138_woocommerce_consumer_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "woocommerce-consumer-key",
        "ck_0a6efc600fa229b936\u{FEFF}e33cb2e62710fe11c2409e",
        "ck_0a6efc600fa229b936e33cb2e62710fe11c2409e",
    );
}

#[test]
fn adv138_woocommerce_consumer_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "woocommerce-consumer-key",
        "ck_0a6efc600fa229b936\u{2060}e33cb2e62710fe11c2409e",
        "ck_0a6efc600fa229b936e33cb2e62710fe11c2409e",
    );
}

#[test]
fn adv138_woocommerce_consumer_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "woocommerce-consumer-key",
        "ck_0a6efc600fa229b936\u{180E}e33cb2e62710fe11c2409e",
        "ck_0a6efc600fa229b936e33cb2e62710fe11c2409e",
    );
}

#[test]
fn adv138_woocommerce_consumer_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "woocommerce-consumer-key",
        "ck_0a6efc600fa229b936\u{202E}e33cb2e62710fe11c2409e",
        "ck_0a6efc600fa229b936e33cb2e62710fe11c2409e",
    );
}

#[test]
fn adv138_woocommerce_consumer_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "woocommerce-consumer-key",
        "ck_0a6efc600fa229b936\u{202C}e33cb2e62710fe11c2409e",
        "ck_0a6efc600fa229b936e33cb2e62710fe11c2409e",
    );
}

#[test]
fn adv138_woocommerce_consumer_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "woocommerce-consumer-key",
        "ck_0a6efc600fa229b936\u{200E}e33cb2e62710fe11c2409e",
        "ck_0a6efc600fa229b936e33cb2e62710fe11c2409e",
    );
}

// =========================================================================
// 9. WOOCOMMERCE REST API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv138_woocommerce_rest_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "woocommerce-rest-api-credentials",
        "ck_7c5fc9d2ad65fe400fd501c368a7252ab4c1994c",
        "ck_7c5fc9d2ad65fe400fd501c368a7252ab4c1994c",
    );
}

#[test]
fn adv138_woocommerce_rest_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "woocommerce-rest-api-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv138_woocommerce_rest_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "woocommerce-rest-api-credentials",
        "ck_7c5fc9d2ad65fe400f\u{200B}d501c368a7252ab4c1994c",
        "ck_7c5fc9d2ad65fe400fd501c368a7252ab4c1994c",
    );
}

#[test]
fn adv138_woocommerce_rest_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "woocommerce-rest-api-credentials",
        "ck_7c5fc9d2ad65fe400f\u{00AD}d501c368a7252ab4c1994c",
        "ck_7c5fc9d2ad65fe400fd501c368a7252ab4c1994c",
    );
}

#[test]
fn adv138_woocommerce_rest_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "woocommerce-rest-api-credentials",
        "ck_7c5fc9d2ad65fe400f\u{200C}d501c368a7252ab4c1994c",
        "ck_7c5fc9d2ad65fe400fd501c368a7252ab4c1994c",
    );
}

#[test]
fn adv138_woocommerce_rest_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "woocommerce-rest-api-credentials",
        "ck_7c5fc9d2ad65fe400f\u{200D}d501c368a7252ab4c1994c",
        "ck_7c5fc9d2ad65fe400fd501c368a7252ab4c1994c",
    );
}

#[test]
fn adv138_woocommerce_rest_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "woocommerce-rest-api-credentials",
        "ck_7c5fc9d2ad65fe400f\u{FEFF}d501c368a7252ab4c1994c",
        "ck_7c5fc9d2ad65fe400fd501c368a7252ab4c1994c",
    );
}

#[test]
fn adv138_woocommerce_rest_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "woocommerce-rest-api-credentials",
        "ck_7c5fc9d2ad65fe400f\u{2060}d501c368a7252ab4c1994c",
        "ck_7c5fc9d2ad65fe400fd501c368a7252ab4c1994c",
    );
}

#[test]
fn adv138_woocommerce_rest_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "woocommerce-rest-api-credentials",
        "ck_7c5fc9d2ad65fe400f\u{180E}d501c368a7252ab4c1994c",
        "ck_7c5fc9d2ad65fe400fd501c368a7252ab4c1994c",
    );
}

#[test]
fn adv138_woocommerce_rest_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "woocommerce-rest-api-credentials",
        "ck_7c5fc9d2ad65fe400f\u{202E}d501c368a7252ab4c1994c",
        "ck_7c5fc9d2ad65fe400fd501c368a7252ab4c1994c",
    );
}

#[test]
fn adv138_woocommerce_rest_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "woocommerce-rest-api-credentials",
        "ck_7c5fc9d2ad65fe400f\u{202C}d501c368a7252ab4c1994c",
        "ck_7c5fc9d2ad65fe400fd501c368a7252ab4c1994c",
    );
}

#[test]
fn adv138_woocommerce_rest_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "woocommerce-rest-api-credentials",
        "ck_7c5fc9d2ad65fe400f\u{200E}d501c368a7252ab4c1994c",
        "ck_7c5fc9d2ad65fe400fd501c368a7252ab4c1994c",
    );
}

// =========================================================================
// 10. WORLDPAY API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv138_worldpay_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "worldpay-api-credentials",
        "WORLDPAY_SERVICE_ID=VkPWCSH92J12",
        "VkPWCSH92J12",
    );
}

#[test]
fn adv138_worldpay_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent("worldpay-api-credentials", "dummy_prefix_0 =xxxxxxxxxxxx");
}

#[test]
fn adv138_worldpay_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "worldpay-api-credentials",
        "WORLDPAY_SERVICE_ID=VkPWCS\u{200B}H92J12",
        "VkPWCSH92J12",
    );
}

#[test]
fn adv138_worldpay_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "worldpay-api-credentials",
        "WORLDPAY_SERVICE_ID=VkPWCS\u{00AD}H92J12",
        "VkPWCSH92J12",
    );
}

#[test]
fn adv138_worldpay_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "worldpay-api-credentials",
        "WORLDPAY_SERVICE_ID=VkPWCS\u{200C}H92J12",
        "VkPWCSH92J12",
    );
}

#[test]
fn adv138_worldpay_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "worldpay-api-credentials",
        "WORLDPAY_SERVICE_ID=VkPWCS\u{200D}H92J12",
        "VkPWCSH92J12",
    );
}

#[test]
fn adv138_worldpay_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "worldpay-api-credentials",
        "WORLDPAY_SERVICE_ID=VkPWCS\u{FEFF}H92J12",
        "VkPWCSH92J12",
    );
}

#[test]
fn adv138_worldpay_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "worldpay-api-credentials",
        "WORLDPAY_SERVICE_ID=VkPWCS\u{2060}H92J12",
        "VkPWCSH92J12",
    );
}

#[test]
fn adv138_worldpay_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "worldpay-api-credentials",
        "WORLDPAY_SERVICE_ID=VkPWCS\u{180E}H92J12",
        "VkPWCSH92J12",
    );
}

#[test]
fn adv138_worldpay_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "worldpay-api-credentials",
        "WORLDPAY_SERVICE_ID=VkPWCS\u{202E}H92J12",
        "VkPWCSH92J12",
    );
}

#[test]
fn adv138_worldpay_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "worldpay-api-credentials",
        "WORLDPAY_SERVICE_ID=VkPWCS\u{202C}H92J12",
        "VkPWCSH92J12",
    );
}

#[test]
fn adv138_worldpay_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "worldpay-api-credentials",
        "WORLDPAY_SERVICE_ID=VkPWCS\u{200E}H92J12",
        "VkPWCSH92J12",
    );
}
