//! Part 103 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates loggly, logrocket, logz, logz, lokalise, looker, looksrare, loom, lorawan, losant detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. LOGGLY CUSTOMER TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv103_loggly_customer_token_normal_must_fire() {
    assert_detector_fires(
        "loggly-customer-token",
        "loggly=c2dc9879-849a-2cf5-83e5-1ad58caad492",
        "c2dc9879-849a-2cf5-83e5-1ad58caad492",
    );
}

#[test]
fn adv103_loggly_customer_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "loggly-customer-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv103_loggly_customer_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "loggly-customer-token",
        "loggly=c2dc9879-849a-2cf5\u{200B}-83e5-1ad58caad492",
        "c2dc9879-849a-2cf5-83e5-1ad58caad492",
    );
}

#[test]
fn adv103_loggly_customer_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "loggly-customer-token",
        "loggly=c2dc9879-849a-2cf5\u{00AD}-83e5-1ad58caad492",
        "c2dc9879-849a-2cf5-83e5-1ad58caad492",
    );
}

#[test]
fn adv103_loggly_customer_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "loggly-customer-token",
        "loggly=c2dc9879-849a-2cf5\u{200C}-83e5-1ad58caad492",
        "c2dc9879-849a-2cf5-83e5-1ad58caad492",
    );
}

#[test]
fn adv103_loggly_customer_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "loggly-customer-token",
        "loggly=c2dc9879-849a-2cf5\u{200D}-83e5-1ad58caad492",
        "c2dc9879-849a-2cf5-83e5-1ad58caad492",
    );
}

#[test]
fn adv103_loggly_customer_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "loggly-customer-token",
        "loggly=c2dc9879-849a-2cf5\u{FEFF}-83e5-1ad58caad492",
        "c2dc9879-849a-2cf5-83e5-1ad58caad492",
    );
}

#[test]
fn adv103_loggly_customer_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "loggly-customer-token",
        "loggly=c2dc9879-849a-2cf5\u{2060}-83e5-1ad58caad492",
        "c2dc9879-849a-2cf5-83e5-1ad58caad492",
    );
}

#[test]
fn adv103_loggly_customer_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "loggly-customer-token",
        "loggly=c2dc9879-849a-2cf5\u{180E}-83e5-1ad58caad492",
        "c2dc9879-849a-2cf5-83e5-1ad58caad492",
    );
}

#[test]
fn adv103_loggly_customer_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "loggly-customer-token",
        "loggly=c2dc9879-849a-2cf5\u{202E}-83e5-1ad58caad492",
        "c2dc9879-849a-2cf5-83e5-1ad58caad492",
    );
}

#[test]
fn adv103_loggly_customer_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "loggly-customer-token",
        "loggly=c2dc9879-849a-2cf5\u{202C}-83e5-1ad58caad492",
        "c2dc9879-849a-2cf5-83e5-1ad58caad492",
    );
}

#[test]
fn adv103_loggly_customer_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "loggly-customer-token",
        "loggly=c2dc9879-849a-2cf5\u{200E}-83e5-1ad58caad492",
        "c2dc9879-849a-2cf5-83e5-1ad58caad492",
    );
}

// =========================================================================
// 2. LOGROCKET API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv103_logrocket_api_key_normal_must_fire() {
    assert_detector_fires(
        "logrocket-api-key",
        "LOGROCKET_API_KEY=XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
        "XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
    );
}

#[test]
fn adv103_logrocket_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "logrocket-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv103_logrocket_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "logrocket-api-key",
        "LOGROCKET_API_KEY=XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_\u{200B}:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
        "XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
    );
}

#[test]
fn adv103_logrocket_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "logrocket-api-key",
        "LOGROCKET_API_KEY=XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_\u{00AD}:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
        "XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
    );
}

#[test]
fn adv103_logrocket_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "logrocket-api-key",
        "LOGROCKET_API_KEY=XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_\u{200C}:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
        "XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
    );
}

#[test]
fn adv103_logrocket_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "logrocket-api-key",
        "LOGROCKET_API_KEY=XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_\u{200D}:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
        "XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
    );
}

#[test]
fn adv103_logrocket_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "logrocket-api-key",
        "LOGROCKET_API_KEY=XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_\u{FEFF}:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
        "XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
    );
}

#[test]
fn adv103_logrocket_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "logrocket-api-key",
        "LOGROCKET_API_KEY=XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_\u{2060}:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
        "XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
    );
}

#[test]
fn adv103_logrocket_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "logrocket-api-key",
        "LOGROCKET_API_KEY=XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_\u{180E}:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
        "XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
    );
}

#[test]
fn adv103_logrocket_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "logrocket-api-key",
        "LOGROCKET_API_KEY=XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_\u{202E}:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
        "XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
    );
}

#[test]
fn adv103_logrocket_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "logrocket-api-key",
        "LOGROCKET_API_KEY=XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_\u{202C}:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
        "XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
    );
}

#[test]
fn adv103_logrocket_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "logrocket-api-key",
        "LOGROCKET_API_KEY=XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_\u{200E}:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
        "XTgWG3ko9u_47Xtuf6XF4bdjMdsEGaG3bqFIpzl0kYmlBk-s5-Jhtml7WjUqI4C_av3g7x8-CM7gXgALSqNPXe06VT_:wQSo-54VIvNBiRC3vqN3AY3EJbZ9LD0odjTcHgQ5134_v3Kza6g4xs6nTS9hsLzL_aAnQ58ISu71FaiIZ:tQW7kunT",
    );
}

// =========================================================================
// 3. LOGZ IO API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv103_logz_io_api_token_normal_must_fire() {
    assert_detector_fires(
        "logz-io-api-token",
        "LOGZIO_API_TOKEN=ea3a3ee0cee5c612686ea0c6af0baffc",
        "ea3a3ee0cee5c612686ea0c6af0baffc",
    );
}

#[test]
fn adv103_logz_io_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "logz-io-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv103_logz_io_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "logz-io-api-token",
        "LOGZIO_API_TOKEN=ea3a3ee0cee5c612\u{200B}686ea0c6af0baffc",
        "ea3a3ee0cee5c612686ea0c6af0baffc",
    );
}

#[test]
fn adv103_logz_io_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "logz-io-api-token",
        "LOGZIO_API_TOKEN=ea3a3ee0cee5c612\u{00AD}686ea0c6af0baffc",
        "ea3a3ee0cee5c612686ea0c6af0baffc",
    );
}

#[test]
fn adv103_logz_io_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "logz-io-api-token",
        "LOGZIO_API_TOKEN=ea3a3ee0cee5c612\u{200C}686ea0c6af0baffc",
        "ea3a3ee0cee5c612686ea0c6af0baffc",
    );
}

#[test]
fn adv103_logz_io_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "logz-io-api-token",
        "LOGZIO_API_TOKEN=ea3a3ee0cee5c612\u{200D}686ea0c6af0baffc",
        "ea3a3ee0cee5c612686ea0c6af0baffc",
    );
}

#[test]
fn adv103_logz_io_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "logz-io-api-token",
        "LOGZIO_API_TOKEN=ea3a3ee0cee5c612\u{FEFF}686ea0c6af0baffc",
        "ea3a3ee0cee5c612686ea0c6af0baffc",
    );
}

#[test]
fn adv103_logz_io_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "logz-io-api-token",
        "LOGZIO_API_TOKEN=ea3a3ee0cee5c612\u{2060}686ea0c6af0baffc",
        "ea3a3ee0cee5c612686ea0c6af0baffc",
    );
}

#[test]
fn adv103_logz_io_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "logz-io-api-token",
        "LOGZIO_API_TOKEN=ea3a3ee0cee5c612\u{180E}686ea0c6af0baffc",
        "ea3a3ee0cee5c612686ea0c6af0baffc",
    );
}

#[test]
fn adv103_logz_io_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "logz-io-api-token",
        "LOGZIO_API_TOKEN=ea3a3ee0cee5c612\u{202E}686ea0c6af0baffc",
        "ea3a3ee0cee5c612686ea0c6af0baffc",
    );
}

#[test]
fn adv103_logz_io_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "logz-io-api-token",
        "LOGZIO_API_TOKEN=ea3a3ee0cee5c612\u{202C}686ea0c6af0baffc",
        "ea3a3ee0cee5c612686ea0c6af0baffc",
    );
}

#[test]
fn adv103_logz_io_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "logz-io-api-token",
        "LOGZIO_API_TOKEN=ea3a3ee0cee5c612\u{200E}686ea0c6af0baffc",
        "ea3a3ee0cee5c612686ea0c6af0baffc",
    );
}

// =========================================================================
// 4. LOGZ IO SHIPPING TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv103_logz_io_shipping_token_normal_must_fire() {
    assert_detector_fires(
        "logz-io-shipping-token",
        "LOGZIO_TOKEN=f2fa077663b2c802ba773043ea4c1058",
        "f2fa077663b2c802ba773043ea4c1058",
    );
}

#[test]
fn adv103_logz_io_shipping_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "logz-io-shipping-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv103_logz_io_shipping_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "logz-io-shipping-token",
        "LOGZIO_TOKEN=f2fa077663b2c802\u{200B}ba773043ea4c1058",
        "f2fa077663b2c802ba773043ea4c1058",
    );
}

#[test]
fn adv103_logz_io_shipping_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "logz-io-shipping-token",
        "LOGZIO_TOKEN=f2fa077663b2c802\u{00AD}ba773043ea4c1058",
        "f2fa077663b2c802ba773043ea4c1058",
    );
}

#[test]
fn adv103_logz_io_shipping_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "logz-io-shipping-token",
        "LOGZIO_TOKEN=f2fa077663b2c802\u{200C}ba773043ea4c1058",
        "f2fa077663b2c802ba773043ea4c1058",
    );
}

#[test]
fn adv103_logz_io_shipping_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "logz-io-shipping-token",
        "LOGZIO_TOKEN=f2fa077663b2c802\u{200D}ba773043ea4c1058",
        "f2fa077663b2c802ba773043ea4c1058",
    );
}

#[test]
fn adv103_logz_io_shipping_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "logz-io-shipping-token",
        "LOGZIO_TOKEN=f2fa077663b2c802\u{FEFF}ba773043ea4c1058",
        "f2fa077663b2c802ba773043ea4c1058",
    );
}

#[test]
fn adv103_logz_io_shipping_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "logz-io-shipping-token",
        "LOGZIO_TOKEN=f2fa077663b2c802\u{2060}ba773043ea4c1058",
        "f2fa077663b2c802ba773043ea4c1058",
    );
}

#[test]
fn adv103_logz_io_shipping_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "logz-io-shipping-token",
        "LOGZIO_TOKEN=f2fa077663b2c802\u{180E}ba773043ea4c1058",
        "f2fa077663b2c802ba773043ea4c1058",
    );
}

#[test]
fn adv103_logz_io_shipping_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "logz-io-shipping-token",
        "LOGZIO_TOKEN=f2fa077663b2c802\u{202E}ba773043ea4c1058",
        "f2fa077663b2c802ba773043ea4c1058",
    );
}

#[test]
fn adv103_logz_io_shipping_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "logz-io-shipping-token",
        "LOGZIO_TOKEN=f2fa077663b2c802\u{202C}ba773043ea4c1058",
        "f2fa077663b2c802ba773043ea4c1058",
    );
}

#[test]
fn adv103_logz_io_shipping_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "logz-io-shipping-token",
        "LOGZIO_TOKEN=f2fa077663b2c802\u{200E}ba773043ea4c1058",
        "f2fa077663b2c802ba773043ea4c1058",
    );
}

// =========================================================================
// 5. LOKALISE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv103_lokalise_api_key_normal_must_fire() {
    assert_detector_fires(
        "lokalise-api-key",
        "lol7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
        "lol7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

#[test]
fn adv103_lokalise_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "lokalise-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv103_lokalise_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "lokalise-api-key",
        "lol7b3e5d8c1a9f4e2b6c\u{200B}8d3a5e9f1b7c4d7b3ea9e2",
        "lol7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

#[test]
fn adv103_lokalise_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "lokalise-api-key",
        "lol7b3e5d8c1a9f4e2b6c\u{00AD}8d3a5e9f1b7c4d7b3ea9e2",
        "lol7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

#[test]
fn adv103_lokalise_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "lokalise-api-key",
        "lol7b3e5d8c1a9f4e2b6c\u{200C}8d3a5e9f1b7c4d7b3ea9e2",
        "lol7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

#[test]
fn adv103_lokalise_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "lokalise-api-key",
        "lol7b3e5d8c1a9f4e2b6c\u{200D}8d3a5e9f1b7c4d7b3ea9e2",
        "lol7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

#[test]
fn adv103_lokalise_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "lokalise-api-key",
        "lol7b3e5d8c1a9f4e2b6c\u{FEFF}8d3a5e9f1b7c4d7b3ea9e2",
        "lol7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

#[test]
fn adv103_lokalise_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "lokalise-api-key",
        "lol7b3e5d8c1a9f4e2b6c\u{2060}8d3a5e9f1b7c4d7b3ea9e2",
        "lol7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

#[test]
fn adv103_lokalise_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "lokalise-api-key",
        "lol7b3e5d8c1a9f4e2b6c\u{180E}8d3a5e9f1b7c4d7b3ea9e2",
        "lol7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

#[test]
fn adv103_lokalise_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "lokalise-api-key",
        "lol7b3e5d8c1a9f4e2b6c\u{202E}8d3a5e9f1b7c4d7b3ea9e2",
        "lol7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

#[test]
fn adv103_lokalise_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "lokalise-api-key",
        "lol7b3e5d8c1a9f4e2b6c\u{202C}8d3a5e9f1b7c4d7b3ea9e2",
        "lol7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

#[test]
fn adv103_lokalise_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "lokalise-api-key",
        "lol7b3e5d8c1a9f4e2b6c\u{200E}8d3a5e9f1b7c4d7b3ea9e2",
        "lol7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2",
    );
}

// =========================================================================
// 6. LOOKER API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv103_looker_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "looker-api-credentials",
        "LOOKERSDK_base_url=https://demo.cloud.looker.com:19999",
        "https://demo.cloud.looker.com:19999",
    );
}

#[test]
fn adv103_looker_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "looker-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv103_looker_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "looker-api-credentials",
        "LOOKERSDK_base_url=https://demo.clou\u{200B}d.looker.com:19999",
        "https://demo.cloud.looker.com:19999",
    );
}

#[test]
fn adv103_looker_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "looker-api-credentials",
        "LOOKERSDK_base_url=https://demo.clou\u{00AD}d.looker.com:19999",
        "https://demo.cloud.looker.com:19999",
    );
}

#[test]
fn adv103_looker_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "looker-api-credentials",
        "LOOKERSDK_base_url=https://demo.clou\u{200C}d.looker.com:19999",
        "https://demo.cloud.looker.com:19999",
    );
}

#[test]
fn adv103_looker_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "looker-api-credentials",
        "LOOKERSDK_base_url=https://demo.clou\u{200D}d.looker.com:19999",
        "https://demo.cloud.looker.com:19999",
    );
}

#[test]
fn adv103_looker_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "looker-api-credentials",
        "LOOKERSDK_base_url=https://demo.clou\u{FEFF}d.looker.com:19999",
        "https://demo.cloud.looker.com:19999",
    );
}

#[test]
fn adv103_looker_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "looker-api-credentials",
        "LOOKERSDK_base_url=https://demo.clou\u{2060}d.looker.com:19999",
        "https://demo.cloud.looker.com:19999",
    );
}

#[test]
fn adv103_looker_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "looker-api-credentials",
        "LOOKERSDK_base_url=https://demo.clou\u{180E}d.looker.com:19999",
        "https://demo.cloud.looker.com:19999",
    );
}

#[test]
fn adv103_looker_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "looker-api-credentials",
        "LOOKERSDK_base_url=https://demo.clou\u{202E}d.looker.com:19999",
        "https://demo.cloud.looker.com:19999",
    );
}

#[test]
fn adv103_looker_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "looker-api-credentials",
        "LOOKERSDK_base_url=https://demo.clou\u{202C}d.looker.com:19999",
        "https://demo.cloud.looker.com:19999",
    );
}

#[test]
fn adv103_looker_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "looker-api-credentials",
        "LOOKERSDK_base_url=https://demo.clou\u{200E}d.looker.com:19999",
        "https://demo.cloud.looker.com:19999",
    );
}

// =========================================================================
// 7. LOOKSRARE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv103_looksrare_api_key_normal_must_fire() {
    assert_detector_fires(
        "looksrare-api-key",
        "X-Looks-Api-Key: fedcba9876543210fedcba9876543210abcd",
        "fedcba9876543210fedcba9876543210abcd",
    );
}

#[test]
fn adv103_looksrare_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "looksrare-api-key",
        "dummy_prefix_0: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv103_looksrare_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "looksrare-api-key",
        "X-Looks-Api-Key: fedcba9876543210fe\u{200B}dcba9876543210abcd",
        "fedcba9876543210fedcba9876543210abcd",
    );
}

#[test]
fn adv103_looksrare_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "looksrare-api-key",
        "X-Looks-Api-Key: fedcba9876543210fe\u{00AD}dcba9876543210abcd",
        "fedcba9876543210fedcba9876543210abcd",
    );
}

#[test]
fn adv103_looksrare_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "looksrare-api-key",
        "X-Looks-Api-Key: fedcba9876543210fe\u{200C}dcba9876543210abcd",
        "fedcba9876543210fedcba9876543210abcd",
    );
}

#[test]
fn adv103_looksrare_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "looksrare-api-key",
        "X-Looks-Api-Key: fedcba9876543210fe\u{200D}dcba9876543210abcd",
        "fedcba9876543210fedcba9876543210abcd",
    );
}

#[test]
fn adv103_looksrare_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "looksrare-api-key",
        "X-Looks-Api-Key: fedcba9876543210fe\u{FEFF}dcba9876543210abcd",
        "fedcba9876543210fedcba9876543210abcd",
    );
}

#[test]
fn adv103_looksrare_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "looksrare-api-key",
        "X-Looks-Api-Key: fedcba9876543210fe\u{2060}dcba9876543210abcd",
        "fedcba9876543210fedcba9876543210abcd",
    );
}

#[test]
fn adv103_looksrare_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "looksrare-api-key",
        "X-Looks-Api-Key: fedcba9876543210fe\u{180E}dcba9876543210abcd",
        "fedcba9876543210fedcba9876543210abcd",
    );
}

#[test]
fn adv103_looksrare_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "looksrare-api-key",
        "X-Looks-Api-Key: fedcba9876543210fe\u{202E}dcba9876543210abcd",
        "fedcba9876543210fedcba9876543210abcd",
    );
}

#[test]
fn adv103_looksrare_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "looksrare-api-key",
        "X-Looks-Api-Key: fedcba9876543210fe\u{202C}dcba9876543210abcd",
        "fedcba9876543210fedcba9876543210abcd",
    );
}

#[test]
fn adv103_looksrare_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "looksrare-api-key",
        "X-Looks-Api-Key: fedcba9876543210fe\u{200E}dcba9876543210abcd",
        "fedcba9876543210fedcba9876543210abcd",
    );
}

// =========================================================================
// 8. LOOM API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv103_loom_api_token_normal_must_fire() {
    assert_detector_fires(
        "loom-api-token",
        "LOOM_API_TOKEN=abgfAPVXbb5fupwJ2p-m_0cpaYef-z",
        "abgfAPVXbb5fupwJ2p-m_0cpaYef-z",
    );
}

#[test]
fn adv103_loom_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "loom-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv103_loom_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "loom-api-token",
        "LOOM_API_TOKEN=abgfAPVXbb5fupw\u{200B}J2p-m_0cpaYef-z",
        "abgfAPVXbb5fupwJ2p-m_0cpaYef-z",
    );
}

#[test]
fn adv103_loom_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "loom-api-token",
        "LOOM_API_TOKEN=abgfAPVXbb5fupw\u{00AD}J2p-m_0cpaYef-z",
        "abgfAPVXbb5fupwJ2p-m_0cpaYef-z",
    );
}

#[test]
fn adv103_loom_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "loom-api-token",
        "LOOM_API_TOKEN=abgfAPVXbb5fupw\u{200C}J2p-m_0cpaYef-z",
        "abgfAPVXbb5fupwJ2p-m_0cpaYef-z",
    );
}

#[test]
fn adv103_loom_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "loom-api-token",
        "LOOM_API_TOKEN=abgfAPVXbb5fupw\u{200D}J2p-m_0cpaYef-z",
        "abgfAPVXbb5fupwJ2p-m_0cpaYef-z",
    );
}

#[test]
fn adv103_loom_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "loom-api-token",
        "LOOM_API_TOKEN=abgfAPVXbb5fupw\u{FEFF}J2p-m_0cpaYef-z",
        "abgfAPVXbb5fupwJ2p-m_0cpaYef-z",
    );
}

#[test]
fn adv103_loom_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "loom-api-token",
        "LOOM_API_TOKEN=abgfAPVXbb5fupw\u{2060}J2p-m_0cpaYef-z",
        "abgfAPVXbb5fupwJ2p-m_0cpaYef-z",
    );
}

#[test]
fn adv103_loom_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "loom-api-token",
        "LOOM_API_TOKEN=abgfAPVXbb5fupw\u{180E}J2p-m_0cpaYef-z",
        "abgfAPVXbb5fupwJ2p-m_0cpaYef-z",
    );
}

#[test]
fn adv103_loom_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "loom-api-token",
        "LOOM_API_TOKEN=abgfAPVXbb5fupw\u{202E}J2p-m_0cpaYef-z",
        "abgfAPVXbb5fupwJ2p-m_0cpaYef-z",
    );
}

#[test]
fn adv103_loom_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "loom-api-token",
        "LOOM_API_TOKEN=abgfAPVXbb5fupw\u{202C}J2p-m_0cpaYef-z",
        "abgfAPVXbb5fupwJ2p-m_0cpaYef-z",
    );
}

#[test]
fn adv103_loom_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "loom-api-token",
        "LOOM_API_TOKEN=abgfAPVXbb5fupw\u{200E}J2p-m_0cpaYef-z",
        "abgfAPVXbb5fupwJ2p-m_0cpaYef-z",
    );
}

// =========================================================================
// 9. LORAWAN CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv103_lorawan_credentials_normal_must_fire() {
    assert_detector_fires(
        "lorawan-credentials",
        "LORAWANDEVEUI=65FC2B90Bd21cD54",
        "65FC2B90Bd21cD54",
    );
}

#[test]
fn adv103_lorawan_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "lorawan-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv103_lorawan_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "lorawan-credentials",
        "LORAWANDEVEUI=65FC2B90\u{200B}Bd21cD54",
        "65FC2B90Bd21cD54",
    );
}

#[test]
fn adv103_lorawan_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "lorawan-credentials",
        "LORAWANDEVEUI=65FC2B90\u{00AD}Bd21cD54",
        "65FC2B90Bd21cD54",
    );
}

#[test]
fn adv103_lorawan_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "lorawan-credentials",
        "LORAWANDEVEUI=65FC2B90\u{200C}Bd21cD54",
        "65FC2B90Bd21cD54",
    );
}

#[test]
fn adv103_lorawan_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "lorawan-credentials",
        "LORAWANDEVEUI=65FC2B90\u{200D}Bd21cD54",
        "65FC2B90Bd21cD54",
    );
}

#[test]
fn adv103_lorawan_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "lorawan-credentials",
        "LORAWANDEVEUI=65FC2B90\u{FEFF}Bd21cD54",
        "65FC2B90Bd21cD54",
    );
}

#[test]
fn adv103_lorawan_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "lorawan-credentials",
        "LORAWANDEVEUI=65FC2B90\u{2060}Bd21cD54",
        "65FC2B90Bd21cD54",
    );
}

#[test]
fn adv103_lorawan_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "lorawan-credentials",
        "LORAWANDEVEUI=65FC2B90\u{180E}Bd21cD54",
        "65FC2B90Bd21cD54",
    );
}

#[test]
fn adv103_lorawan_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "lorawan-credentials",
        "LORAWANDEVEUI=65FC2B90\u{202E}Bd21cD54",
        "65FC2B90Bd21cD54",
    );
}

#[test]
fn adv103_lorawan_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "lorawan-credentials",
        "LORAWANDEVEUI=65FC2B90\u{202C}Bd21cD54",
        "65FC2B90Bd21cD54",
    );
}

#[test]
fn adv103_lorawan_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "lorawan-credentials",
        "LORAWANDEVEUI=65FC2B90\u{200E}Bd21cD54",
        "65FC2B90Bd21cD54",
    );
}

// =========================================================================
// 10. LOSANT API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv103_losant_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "losant-api-credentials",
        "LOSANT_ACCESS_KEY=FJkepLYelHEQDonIVhEJ",
        "FJkepLYelHEQDonIVhEJ",
    );
}

#[test]
fn adv103_losant_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "losant-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv103_losant_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "losant-api-credentials",
        "LOSANT_ACCESS_KEY=FJkepLYelH\u{200B}EQDonIVhEJ",
        "FJkepLYelHEQDonIVhEJ",
    );
}

#[test]
fn adv103_losant_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "losant-api-credentials",
        "LOSANT_ACCESS_KEY=FJkepLYelH\u{00AD}EQDonIVhEJ",
        "FJkepLYelHEQDonIVhEJ",
    );
}

#[test]
fn adv103_losant_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "losant-api-credentials",
        "LOSANT_ACCESS_KEY=FJkepLYelH\u{200C}EQDonIVhEJ",
        "FJkepLYelHEQDonIVhEJ",
    );
}

#[test]
fn adv103_losant_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "losant-api-credentials",
        "LOSANT_ACCESS_KEY=FJkepLYelH\u{200D}EQDonIVhEJ",
        "FJkepLYelHEQDonIVhEJ",
    );
}

#[test]
fn adv103_losant_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "losant-api-credentials",
        "LOSANT_ACCESS_KEY=FJkepLYelH\u{FEFF}EQDonIVhEJ",
        "FJkepLYelHEQDonIVhEJ",
    );
}

#[test]
fn adv103_losant_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "losant-api-credentials",
        "LOSANT_ACCESS_KEY=FJkepLYelH\u{2060}EQDonIVhEJ",
        "FJkepLYelHEQDonIVhEJ",
    );
}

#[test]
fn adv103_losant_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "losant-api-credentials",
        "LOSANT_ACCESS_KEY=FJkepLYelH\u{180E}EQDonIVhEJ",
        "FJkepLYelHEQDonIVhEJ",
    );
}

#[test]
fn adv103_losant_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "losant-api-credentials",
        "LOSANT_ACCESS_KEY=FJkepLYelH\u{202E}EQDonIVhEJ",
        "FJkepLYelHEQDonIVhEJ",
    );
}

#[test]
fn adv103_losant_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "losant-api-credentials",
        "LOSANT_ACCESS_KEY=FJkepLYelH\u{202C}EQDonIVhEJ",
        "FJkepLYelHEQDonIVhEJ",
    );
}

#[test]
fn adv103_losant_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "losant-api-credentials",
        "LOSANT_ACCESS_KEY=FJkepLYelH\u{200E}EQDonIVhEJ",
        "FJkepLYelHEQDonIVhEJ",
    );
}


