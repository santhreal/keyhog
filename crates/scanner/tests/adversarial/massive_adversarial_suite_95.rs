//! Part 95 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates hetzner, hevo, hexpm, hibp, hightouch, hologram, home, homebrew, honeybadger, honeycomb detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. HETZNER API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv95_hetzner_api_token_normal_must_fire() {
    assert_detector_fires(
        "hetzner-api-token",
        "HCLOUD_TOKEN=c5fd1aee81e06b2f61bfe276214ca7aa8f6051ea71dcaa2e40187610db9d78db",
        "c5fd1aee81e06b2f61bfe276214ca7aa8f6051ea71dcaa2e40187610db9d78db",
    );
}

#[test]
fn adv95_hetzner_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hetzner-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv95_hetzner_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hetzner-api-token",
        "HCLOUD_TOKEN=c5fd1aee81e06b2f61bfe276214ca7aa\u{200B}8f6051ea71dcaa2e40187610db9d78db",
        "c5fd1aee81e06b2f61bfe276214ca7aa8f6051ea71dcaa2e40187610db9d78db",
    );
}

#[test]
fn adv95_hetzner_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hetzner-api-token",
        "HCLOUD_TOKEN=c5fd1aee81e06b2f61bfe276214ca7aa\u{00AD}8f6051ea71dcaa2e40187610db9d78db",
        "c5fd1aee81e06b2f61bfe276214ca7aa8f6051ea71dcaa2e40187610db9d78db",
    );
}

#[test]
fn adv95_hetzner_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "hetzner-api-token",
        "HCLOUD_TOKEN=c5fd1aee81e06b2f61bfe276214ca7aa\u{200C}8f6051ea71dcaa2e40187610db9d78db",
        "c5fd1aee81e06b2f61bfe276214ca7aa8f6051ea71dcaa2e40187610db9d78db",
    );
}

#[test]
fn adv95_hetzner_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "hetzner-api-token",
        "HCLOUD_TOKEN=c5fd1aee81e06b2f61bfe276214ca7aa\u{200D}8f6051ea71dcaa2e40187610db9d78db",
        "c5fd1aee81e06b2f61bfe276214ca7aa8f6051ea71dcaa2e40187610db9d78db",
    );
}

#[test]
fn adv95_hetzner_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "hetzner-api-token",
        "HCLOUD_TOKEN=c5fd1aee81e06b2f61bfe276214ca7aa\u{FEFF}8f6051ea71dcaa2e40187610db9d78db",
        "c5fd1aee81e06b2f61bfe276214ca7aa8f6051ea71dcaa2e40187610db9d78db",
    );
}

#[test]
fn adv95_hetzner_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "hetzner-api-token",
        "HCLOUD_TOKEN=c5fd1aee81e06b2f61bfe276214ca7aa\u{2060}8f6051ea71dcaa2e40187610db9d78db",
        "c5fd1aee81e06b2f61bfe276214ca7aa8f6051ea71dcaa2e40187610db9d78db",
    );
}

#[test]
fn adv95_hetzner_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "hetzner-api-token",
        "HCLOUD_TOKEN=c5fd1aee81e06b2f61bfe276214ca7aa\u{180E}8f6051ea71dcaa2e40187610db9d78db",
        "c5fd1aee81e06b2f61bfe276214ca7aa8f6051ea71dcaa2e40187610db9d78db",
    );
}

#[test]
fn adv95_hetzner_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "hetzner-api-token",
        "HCLOUD_TOKEN=c5fd1aee81e06b2f61bfe276214ca7aa\u{202E}8f6051ea71dcaa2e40187610db9d78db",
        "c5fd1aee81e06b2f61bfe276214ca7aa8f6051ea71dcaa2e40187610db9d78db",
    );
}

#[test]
fn adv95_hetzner_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "hetzner-api-token",
        "HCLOUD_TOKEN=c5fd1aee81e06b2f61bfe276214ca7aa\u{202C}8f6051ea71dcaa2e40187610db9d78db",
        "c5fd1aee81e06b2f61bfe276214ca7aa8f6051ea71dcaa2e40187610db9d78db",
    );
}

#[test]
fn adv95_hetzner_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "hetzner-api-token",
        "HCLOUD_TOKEN=c5fd1aee81e06b2f61bfe276214ca7aa\u{200E}8f6051ea71dcaa2e40187610db9d78db",
        "c5fd1aee81e06b2f61bfe276214ca7aa8f6051ea71dcaa2e40187610db9d78db",
    );
}

// =========================================================================
// 2. HEVO DATA CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv95_hevo_data_credentials_normal_must_fire() {
    assert_detector_fires(
        "hevo-data-credentials",
        "HEVO_API_KEY=j1DB8mMR4XfVmrn3VAXW",
        "j1DB8mMR4XfVmrn3VAXW",
    );
}

#[test]
fn adv95_hevo_data_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hevo-data-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv95_hevo_data_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hevo-data-credentials",
        "HEVO_API_KEY=j1DB8mMR4X\u{200B}fVmrn3VAXW",
        "j1DB8mMR4XfVmrn3VAXW",
    );
}

#[test]
fn adv95_hevo_data_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hevo-data-credentials",
        "HEVO_API_KEY=j1DB8mMR4X\u{00AD}fVmrn3VAXW",
        "j1DB8mMR4XfVmrn3VAXW",
    );
}

#[test]
fn adv95_hevo_data_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "hevo-data-credentials",
        "HEVO_API_KEY=j1DB8mMR4X\u{200C}fVmrn3VAXW",
        "j1DB8mMR4XfVmrn3VAXW",
    );
}

#[test]
fn adv95_hevo_data_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "hevo-data-credentials",
        "HEVO_API_KEY=j1DB8mMR4X\u{200D}fVmrn3VAXW",
        "j1DB8mMR4XfVmrn3VAXW",
    );
}

#[test]
fn adv95_hevo_data_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "hevo-data-credentials",
        "HEVO_API_KEY=j1DB8mMR4X\u{FEFF}fVmrn3VAXW",
        "j1DB8mMR4XfVmrn3VAXW",
    );
}

#[test]
fn adv95_hevo_data_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "hevo-data-credentials",
        "HEVO_API_KEY=j1DB8mMR4X\u{2060}fVmrn3VAXW",
        "j1DB8mMR4XfVmrn3VAXW",
    );
}

#[test]
fn adv95_hevo_data_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "hevo-data-credentials",
        "HEVO_API_KEY=j1DB8mMR4X\u{180E}fVmrn3VAXW",
        "j1DB8mMR4XfVmrn3VAXW",
    );
}

#[test]
fn adv95_hevo_data_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "hevo-data-credentials",
        "HEVO_API_KEY=j1DB8mMR4X\u{202E}fVmrn3VAXW",
        "j1DB8mMR4XfVmrn3VAXW",
    );
}

#[test]
fn adv95_hevo_data_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "hevo-data-credentials",
        "HEVO_API_KEY=j1DB8mMR4X\u{202C}fVmrn3VAXW",
        "j1DB8mMR4XfVmrn3VAXW",
    );
}

#[test]
fn adv95_hevo_data_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "hevo-data-credentials",
        "HEVO_API_KEY=j1DB8mMR4X\u{200E}fVmrn3VAXW",
        "j1DB8mMR4XfVmrn3VAXW",
    );
}

// =========================================================================
// 3. HEXPM API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv95_hexpm_api_key_normal_must_fire() {
    assert_detector_fires(
        "hexpm-api-key",
        "hexpm_QzweGR+iCsrFqlpYB40b/3ctNZZ9kdTqkx2OJ0nFLx=",
        "hexpm_QzweGR+iCsrFqlpYB40b/3ctNZZ9kdTqkx2OJ0nFLx=",
    );
}

#[test]
fn adv95_hexpm_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hexpm-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv95_hexpm_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hexpm-api-key",
        "hexpm_QzweGR+iCsrFqlpYB4\u{200B}0b/3ctNZZ9kdTqkx2OJ0nFLx=",
        "hexpm_QzweGR+iCsrFqlpYB40b/3ctNZZ9kdTqkx2OJ0nFLx=",
    );
}

#[test]
fn adv95_hexpm_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hexpm-api-key",
        "hexpm_QzweGR+iCsrFqlpYB4\u{00AD}0b/3ctNZZ9kdTqkx2OJ0nFLx=",
        "hexpm_QzweGR+iCsrFqlpYB40b/3ctNZZ9kdTqkx2OJ0nFLx=",
    );
}

#[test]
fn adv95_hexpm_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "hexpm-api-key",
        "hexpm_QzweGR+iCsrFqlpYB4\u{200C}0b/3ctNZZ9kdTqkx2OJ0nFLx=",
        "hexpm_QzweGR+iCsrFqlpYB40b/3ctNZZ9kdTqkx2OJ0nFLx=",
    );
}

#[test]
fn adv95_hexpm_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "hexpm-api-key",
        "hexpm_QzweGR+iCsrFqlpYB4\u{200D}0b/3ctNZZ9kdTqkx2OJ0nFLx=",
        "hexpm_QzweGR+iCsrFqlpYB40b/3ctNZZ9kdTqkx2OJ0nFLx=",
    );
}

#[test]
fn adv95_hexpm_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "hexpm-api-key",
        "hexpm_QzweGR+iCsrFqlpYB4\u{FEFF}0b/3ctNZZ9kdTqkx2OJ0nFLx=",
        "hexpm_QzweGR+iCsrFqlpYB40b/3ctNZZ9kdTqkx2OJ0nFLx=",
    );
}

#[test]
fn adv95_hexpm_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "hexpm-api-key",
        "hexpm_QzweGR+iCsrFqlpYB4\u{2060}0b/3ctNZZ9kdTqkx2OJ0nFLx=",
        "hexpm_QzweGR+iCsrFqlpYB40b/3ctNZZ9kdTqkx2OJ0nFLx=",
    );
}

#[test]
fn adv95_hexpm_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "hexpm-api-key",
        "hexpm_QzweGR+iCsrFqlpYB4\u{180E}0b/3ctNZZ9kdTqkx2OJ0nFLx=",
        "hexpm_QzweGR+iCsrFqlpYB40b/3ctNZZ9kdTqkx2OJ0nFLx=",
    );
}

#[test]
fn adv95_hexpm_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "hexpm-api-key",
        "hexpm_QzweGR+iCsrFqlpYB4\u{202E}0b/3ctNZZ9kdTqkx2OJ0nFLx=",
        "hexpm_QzweGR+iCsrFqlpYB40b/3ctNZZ9kdTqkx2OJ0nFLx=",
    );
}

#[test]
fn adv95_hexpm_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "hexpm-api-key",
        "hexpm_QzweGR+iCsrFqlpYB4\u{202C}0b/3ctNZZ9kdTqkx2OJ0nFLx=",
        "hexpm_QzweGR+iCsrFqlpYB40b/3ctNZZ9kdTqkx2OJ0nFLx=",
    );
}

#[test]
fn adv95_hexpm_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "hexpm-api-key",
        "hexpm_QzweGR+iCsrFqlpYB4\u{200E}0b/3ctNZZ9kdTqkx2OJ0nFLx=",
        "hexpm_QzweGR+iCsrFqlpYB40b/3ctNZZ9kdTqkx2OJ0nFLx=",
    );
}

// =========================================================================
// 4. HIBP API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv95_hibp_api_key_normal_must_fire() {
    assert_detector_fires(
        "hibp-api-key",
        "hibp-api-key=1d8744f744361c8c3e27549b337d5863",
        "1d8744f744361c8c3e27549b337d5863",
    );
}

#[test]
fn adv95_hibp_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hibp-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv95_hibp_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hibp-api-key",
        "hibp-api-key=1d8744f744361c8c\u{200B}3e27549b337d5863",
        "1d8744f744361c8c3e27549b337d5863",
    );
}

#[test]
fn adv95_hibp_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hibp-api-key",
        "hibp-api-key=1d8744f744361c8c\u{00AD}3e27549b337d5863",
        "1d8744f744361c8c3e27549b337d5863",
    );
}

#[test]
fn adv95_hibp_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "hibp-api-key",
        "hibp-api-key=1d8744f744361c8c\u{200C}3e27549b337d5863",
        "1d8744f744361c8c3e27549b337d5863",
    );
}

#[test]
fn adv95_hibp_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "hibp-api-key",
        "hibp-api-key=1d8744f744361c8c\u{200D}3e27549b337d5863",
        "1d8744f744361c8c3e27549b337d5863",
    );
}

#[test]
fn adv95_hibp_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "hibp-api-key",
        "hibp-api-key=1d8744f744361c8c\u{FEFF}3e27549b337d5863",
        "1d8744f744361c8c3e27549b337d5863",
    );
}

#[test]
fn adv95_hibp_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "hibp-api-key",
        "hibp-api-key=1d8744f744361c8c\u{2060}3e27549b337d5863",
        "1d8744f744361c8c3e27549b337d5863",
    );
}

#[test]
fn adv95_hibp_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "hibp-api-key",
        "hibp-api-key=1d8744f744361c8c\u{180E}3e27549b337d5863",
        "1d8744f744361c8c3e27549b337d5863",
    );
}

#[test]
fn adv95_hibp_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "hibp-api-key",
        "hibp-api-key=1d8744f744361c8c\u{202E}3e27549b337d5863",
        "1d8744f744361c8c3e27549b337d5863",
    );
}

#[test]
fn adv95_hibp_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "hibp-api-key",
        "hibp-api-key=1d8744f744361c8c\u{202C}3e27549b337d5863",
        "1d8744f744361c8c3e27549b337d5863",
    );
}

#[test]
fn adv95_hibp_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "hibp-api-key",
        "hibp-api-key=1d8744f744361c8c\u{200E}3e27549b337d5863",
        "1d8744f744361c8c3e27549b337d5863",
    );
}

// =========================================================================
// 5. HIGHTOUCH API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv95_hightouch_api_key_normal_must_fire() {
    assert_detector_fires(
        "hightouch-api-key",
        "HIGHTOUCH_API_KEY=yTHF1Ffp67TZgGw8EbdenjdcxEvbgeiS",
        "yTHF1Ffp67TZgGw8EbdenjdcxEvbgeiS",
    );
}

#[test]
fn adv95_hightouch_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hightouch-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv95_hightouch_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hightouch-api-key",
        "HIGHTOUCH_API_KEY=yTHF1Ffp67TZgGw8\u{200B}EbdenjdcxEvbgeiS",
        "yTHF1Ffp67TZgGw8EbdenjdcxEvbgeiS",
    );
}

#[test]
fn adv95_hightouch_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hightouch-api-key",
        "HIGHTOUCH_API_KEY=yTHF1Ffp67TZgGw8\u{00AD}EbdenjdcxEvbgeiS",
        "yTHF1Ffp67TZgGw8EbdenjdcxEvbgeiS",
    );
}

#[test]
fn adv95_hightouch_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "hightouch-api-key",
        "HIGHTOUCH_API_KEY=yTHF1Ffp67TZgGw8\u{200C}EbdenjdcxEvbgeiS",
        "yTHF1Ffp67TZgGw8EbdenjdcxEvbgeiS",
    );
}

#[test]
fn adv95_hightouch_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "hightouch-api-key",
        "HIGHTOUCH_API_KEY=yTHF1Ffp67TZgGw8\u{200D}EbdenjdcxEvbgeiS",
        "yTHF1Ffp67TZgGw8EbdenjdcxEvbgeiS",
    );
}

#[test]
fn adv95_hightouch_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "hightouch-api-key",
        "HIGHTOUCH_API_KEY=yTHF1Ffp67TZgGw8\u{FEFF}EbdenjdcxEvbgeiS",
        "yTHF1Ffp67TZgGw8EbdenjdcxEvbgeiS",
    );
}

#[test]
fn adv95_hightouch_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "hightouch-api-key",
        "HIGHTOUCH_API_KEY=yTHF1Ffp67TZgGw8\u{2060}EbdenjdcxEvbgeiS",
        "yTHF1Ffp67TZgGw8EbdenjdcxEvbgeiS",
    );
}

#[test]
fn adv95_hightouch_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "hightouch-api-key",
        "HIGHTOUCH_API_KEY=yTHF1Ffp67TZgGw8\u{180E}EbdenjdcxEvbgeiS",
        "yTHF1Ffp67TZgGw8EbdenjdcxEvbgeiS",
    );
}

#[test]
fn adv95_hightouch_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "hightouch-api-key",
        "HIGHTOUCH_API_KEY=yTHF1Ffp67TZgGw8\u{202E}EbdenjdcxEvbgeiS",
        "yTHF1Ffp67TZgGw8EbdenjdcxEvbgeiS",
    );
}

#[test]
fn adv95_hightouch_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "hightouch-api-key",
        "HIGHTOUCH_API_KEY=yTHF1Ffp67TZgGw8\u{202C}EbdenjdcxEvbgeiS",
        "yTHF1Ffp67TZgGw8EbdenjdcxEvbgeiS",
    );
}

#[test]
fn adv95_hightouch_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "hightouch-api-key",
        "HIGHTOUCH_API_KEY=yTHF1Ffp67TZgGw8\u{200E}EbdenjdcxEvbgeiS",
        "yTHF1Ffp67TZgGw8EbdenjdcxEvbgeiS",
    );
}

// =========================================================================
// 6. HOLOGRAM API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv95_hologram_api_key_normal_must_fire() {
    assert_detector_fires(
        "hologram-api-key",
        "HOLOGRAM_API_KEY=0hJbPI18aekE205Bq4osIbrsNwBPn5EaLtbbmfpG",
        "0hJbPI18aekE205Bq4osIbrsNwBPn5EaLtbbmfpG",
    );
}

#[test]
fn adv95_hologram_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "hologram-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv95_hologram_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "hologram-api-key",
        "HOLOGRAM_API_KEY=0hJbPI18aekE205Bq4os\u{200B}IbrsNwBPn5EaLtbbmfpG",
        "0hJbPI18aekE205Bq4osIbrsNwBPn5EaLtbbmfpG",
    );
}

#[test]
fn adv95_hologram_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "hologram-api-key",
        "HOLOGRAM_API_KEY=0hJbPI18aekE205Bq4os\u{00AD}IbrsNwBPn5EaLtbbmfpG",
        "0hJbPI18aekE205Bq4osIbrsNwBPn5EaLtbbmfpG",
    );
}

#[test]
fn adv95_hologram_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "hologram-api-key",
        "HOLOGRAM_API_KEY=0hJbPI18aekE205Bq4os\u{200C}IbrsNwBPn5EaLtbbmfpG",
        "0hJbPI18aekE205Bq4osIbrsNwBPn5EaLtbbmfpG",
    );
}

#[test]
fn adv95_hologram_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "hologram-api-key",
        "HOLOGRAM_API_KEY=0hJbPI18aekE205Bq4os\u{200D}IbrsNwBPn5EaLtbbmfpG",
        "0hJbPI18aekE205Bq4osIbrsNwBPn5EaLtbbmfpG",
    );
}

#[test]
fn adv95_hologram_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "hologram-api-key",
        "HOLOGRAM_API_KEY=0hJbPI18aekE205Bq4os\u{FEFF}IbrsNwBPn5EaLtbbmfpG",
        "0hJbPI18aekE205Bq4osIbrsNwBPn5EaLtbbmfpG",
    );
}

#[test]
fn adv95_hologram_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "hologram-api-key",
        "HOLOGRAM_API_KEY=0hJbPI18aekE205Bq4os\u{2060}IbrsNwBPn5EaLtbbmfpG",
        "0hJbPI18aekE205Bq4osIbrsNwBPn5EaLtbbmfpG",
    );
}

#[test]
fn adv95_hologram_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "hologram-api-key",
        "HOLOGRAM_API_KEY=0hJbPI18aekE205Bq4os\u{180E}IbrsNwBPn5EaLtbbmfpG",
        "0hJbPI18aekE205Bq4osIbrsNwBPn5EaLtbbmfpG",
    );
}

#[test]
fn adv95_hologram_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "hologram-api-key",
        "HOLOGRAM_API_KEY=0hJbPI18aekE205Bq4os\u{202E}IbrsNwBPn5EaLtbbmfpG",
        "0hJbPI18aekE205Bq4osIbrsNwBPn5EaLtbbmfpG",
    );
}

#[test]
fn adv95_hologram_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "hologram-api-key",
        "HOLOGRAM_API_KEY=0hJbPI18aekE205Bq4os\u{202C}IbrsNwBPn5EaLtbbmfpG",
        "0hJbPI18aekE205Bq4osIbrsNwBPn5EaLtbbmfpG",
    );
}

#[test]
fn adv95_hologram_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "hologram-api-key",
        "HOLOGRAM_API_KEY=0hJbPI18aekE205Bq4os\u{200E}IbrsNwBPn5EaLtbbmfpG",
        "0hJbPI18aekE205Bq4osIbrsNwBPn5EaLtbbmfpG",
    );
}

// =========================================================================
// 7. HOME ASSISTANT API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv95_home_assistant_api_token_normal_must_fire() {
    assert_detector_fires(
        "home-assistant-api-token",
        "HOME_ASSISTANT_API_TOKEN=TZZU1V1fRiBnY5xwsDZXovveco9_68C1kCDSkKv4",
        "TZZU1V1fRiBnY5xwsDZXovveco9_68C1kCDSkKv4",
    );
}

#[test]
fn adv95_home_assistant_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "home-assistant-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv95_home_assistant_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "home-assistant-api-token",
        "HOME_ASSISTANT_API_TOKEN=TZZU1V1fRiBnY5xwsDZX\u{200B}ovveco9_68C1kCDSkKv4",
        "TZZU1V1fRiBnY5xwsDZXovveco9_68C1kCDSkKv4",
    );
}

#[test]
fn adv95_home_assistant_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "home-assistant-api-token",
        "HOME_ASSISTANT_API_TOKEN=TZZU1V1fRiBnY5xwsDZX\u{00AD}ovveco9_68C1kCDSkKv4",
        "TZZU1V1fRiBnY5xwsDZXovveco9_68C1kCDSkKv4",
    );
}

#[test]
fn adv95_home_assistant_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "home-assistant-api-token",
        "HOME_ASSISTANT_API_TOKEN=TZZU1V1fRiBnY5xwsDZX\u{200C}ovveco9_68C1kCDSkKv4",
        "TZZU1V1fRiBnY5xwsDZXovveco9_68C1kCDSkKv4",
    );
}

#[test]
fn adv95_home_assistant_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "home-assistant-api-token",
        "HOME_ASSISTANT_API_TOKEN=TZZU1V1fRiBnY5xwsDZX\u{200D}ovveco9_68C1kCDSkKv4",
        "TZZU1V1fRiBnY5xwsDZXovveco9_68C1kCDSkKv4",
    );
}

#[test]
fn adv95_home_assistant_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "home-assistant-api-token",
        "HOME_ASSISTANT_API_TOKEN=TZZU1V1fRiBnY5xwsDZX\u{FEFF}ovveco9_68C1kCDSkKv4",
        "TZZU1V1fRiBnY5xwsDZXovveco9_68C1kCDSkKv4",
    );
}

#[test]
fn adv95_home_assistant_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "home-assistant-api-token",
        "HOME_ASSISTANT_API_TOKEN=TZZU1V1fRiBnY5xwsDZX\u{2060}ovveco9_68C1kCDSkKv4",
        "TZZU1V1fRiBnY5xwsDZXovveco9_68C1kCDSkKv4",
    );
}

#[test]
fn adv95_home_assistant_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "home-assistant-api-token",
        "HOME_ASSISTANT_API_TOKEN=TZZU1V1fRiBnY5xwsDZX\u{180E}ovveco9_68C1kCDSkKv4",
        "TZZU1V1fRiBnY5xwsDZXovveco9_68C1kCDSkKv4",
    );
}

#[test]
fn adv95_home_assistant_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "home-assistant-api-token",
        "HOME_ASSISTANT_API_TOKEN=TZZU1V1fRiBnY5xwsDZX\u{202E}ovveco9_68C1kCDSkKv4",
        "TZZU1V1fRiBnY5xwsDZXovveco9_68C1kCDSkKv4",
    );
}

#[test]
fn adv95_home_assistant_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "home-assistant-api-token",
        "HOME_ASSISTANT_API_TOKEN=TZZU1V1fRiBnY5xwsDZX\u{202C}ovveco9_68C1kCDSkKv4",
        "TZZU1V1fRiBnY5xwsDZXovveco9_68C1kCDSkKv4",
    );
}

#[test]
fn adv95_home_assistant_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "home-assistant-api-token",
        "HOME_ASSISTANT_API_TOKEN=TZZU1V1fRiBnY5xwsDZX\u{200E}ovveco9_68C1kCDSkKv4",
        "TZZU1V1fRiBnY5xwsDZXovveco9_68C1kCDSkKv4",
    );
}

// =========================================================================
// 8. HOMEBREW API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv95_homebrew_api_token_normal_must_fire() {
    assert_detector_fires(
        "homebrew-api-token",
        "HOMEBREW_GITHUB_API_TOKEN=ghp_P5lsGh3LzOTnVByk1zm6620MPFvKcQNclaif",
        "ghp_P5lsGh3LzOTnVByk1zm6620MPFvKcQNclaif",
    );
}

#[test]
fn adv95_homebrew_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "homebrew-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv95_homebrew_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "homebrew-api-token",
        "HOMEBREW_GITHUB_API_TOKEN=ghp_P5lsGh3LzOTnVByk\u{200B}1zm6620MPFvKcQNclaif",
        "ghp_P5lsGh3LzOTnVByk1zm6620MPFvKcQNclaif",
    );
}

#[test]
fn adv95_homebrew_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "homebrew-api-token",
        "HOMEBREW_GITHUB_API_TOKEN=ghp_P5lsGh3LzOTnVByk\u{00AD}1zm6620MPFvKcQNclaif",
        "ghp_P5lsGh3LzOTnVByk1zm6620MPFvKcQNclaif",
    );
}

#[test]
fn adv95_homebrew_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "homebrew-api-token",
        "HOMEBREW_GITHUB_API_TOKEN=ghp_P5lsGh3LzOTnVByk\u{200C}1zm6620MPFvKcQNclaif",
        "ghp_P5lsGh3LzOTnVByk1zm6620MPFvKcQNclaif",
    );
}

#[test]
fn adv95_homebrew_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "homebrew-api-token",
        "HOMEBREW_GITHUB_API_TOKEN=ghp_P5lsGh3LzOTnVByk\u{200D}1zm6620MPFvKcQNclaif",
        "ghp_P5lsGh3LzOTnVByk1zm6620MPFvKcQNclaif",
    );
}

#[test]
fn adv95_homebrew_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "homebrew-api-token",
        "HOMEBREW_GITHUB_API_TOKEN=ghp_P5lsGh3LzOTnVByk\u{FEFF}1zm6620MPFvKcQNclaif",
        "ghp_P5lsGh3LzOTnVByk1zm6620MPFvKcQNclaif",
    );
}

#[test]
fn adv95_homebrew_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "homebrew-api-token",
        "HOMEBREW_GITHUB_API_TOKEN=ghp_P5lsGh3LzOTnVByk\u{2060}1zm6620MPFvKcQNclaif",
        "ghp_P5lsGh3LzOTnVByk1zm6620MPFvKcQNclaif",
    );
}

#[test]
fn adv95_homebrew_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "homebrew-api-token",
        "HOMEBREW_GITHUB_API_TOKEN=ghp_P5lsGh3LzOTnVByk\u{180E}1zm6620MPFvKcQNclaif",
        "ghp_P5lsGh3LzOTnVByk1zm6620MPFvKcQNclaif",
    );
}

#[test]
fn adv95_homebrew_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "homebrew-api-token",
        "HOMEBREW_GITHUB_API_TOKEN=ghp_P5lsGh3LzOTnVByk\u{202E}1zm6620MPFvKcQNclaif",
        "ghp_P5lsGh3LzOTnVByk1zm6620MPFvKcQNclaif",
    );
}

#[test]
fn adv95_homebrew_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "homebrew-api-token",
        "HOMEBREW_GITHUB_API_TOKEN=ghp_P5lsGh3LzOTnVByk\u{202C}1zm6620MPFvKcQNclaif",
        "ghp_P5lsGh3LzOTnVByk1zm6620MPFvKcQNclaif",
    );
}

#[test]
fn adv95_homebrew_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "homebrew-api-token",
        "HOMEBREW_GITHUB_API_TOKEN=ghp_P5lsGh3LzOTnVByk\u{200E}1zm6620MPFvKcQNclaif",
        "ghp_P5lsGh3LzOTnVByk1zm6620MPFvKcQNclaif",
    );
}

// =========================================================================
// 9. HONEYBADGER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv95_honeybadger_api_key_normal_must_fire() {
    assert_detector_fires(
        "honeybadger-api-key",
        "api_key=eb9bba259a9ddafe89e911d116ebdf68",
        "eb9bba259a9ddafe89e911d116ebdf68",
    );
}

#[test]
fn adv95_honeybadger_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "honeybadger-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv95_honeybadger_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "honeybadger-api-key",
        "api_key=eb9bba259a9ddafe\u{200B}89e911d116ebdf68",
        "eb9bba259a9ddafe89e911d116ebdf68",
    );
}

#[test]
fn adv95_honeybadger_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "honeybadger-api-key",
        "api_key=eb9bba259a9ddafe\u{00AD}89e911d116ebdf68",
        "eb9bba259a9ddafe89e911d116ebdf68",
    );
}

#[test]
fn adv95_honeybadger_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "honeybadger-api-key",
        "api_key=eb9bba259a9ddafe\u{200C}89e911d116ebdf68",
        "eb9bba259a9ddafe89e911d116ebdf68",
    );
}

#[test]
fn adv95_honeybadger_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "honeybadger-api-key",
        "api_key=eb9bba259a9ddafe\u{200D}89e911d116ebdf68",
        "eb9bba259a9ddafe89e911d116ebdf68",
    );
}

#[test]
fn adv95_honeybadger_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "honeybadger-api-key",
        "api_key=eb9bba259a9ddafe\u{FEFF}89e911d116ebdf68",
        "eb9bba259a9ddafe89e911d116ebdf68",
    );
}

#[test]
fn adv95_honeybadger_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "honeybadger-api-key",
        "api_key=eb9bba259a9ddafe\u{2060}89e911d116ebdf68",
        "eb9bba259a9ddafe89e911d116ebdf68",
    );
}

#[test]
fn adv95_honeybadger_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "honeybadger-api-key",
        "api_key=eb9bba259a9ddafe\u{180E}89e911d116ebdf68",
        "eb9bba259a9ddafe89e911d116ebdf68",
    );
}

#[test]
fn adv95_honeybadger_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "honeybadger-api-key",
        "api_key=eb9bba259a9ddafe\u{202E}89e911d116ebdf68",
        "eb9bba259a9ddafe89e911d116ebdf68",
    );
}

#[test]
fn adv95_honeybadger_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "honeybadger-api-key",
        "api_key=eb9bba259a9ddafe\u{202C}89e911d116ebdf68",
        "eb9bba259a9ddafe89e911d116ebdf68",
    );
}

#[test]
fn adv95_honeybadger_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "honeybadger-api-key",
        "api_key=eb9bba259a9ddafe\u{200E}89e911d116ebdf68",
        "eb9bba259a9ddafe89e911d116ebdf68",
    );
}

// =========================================================================
// 10. HONEYCOMB API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv95_honeycomb_api_key_normal_must_fire() {
    assert_detector_fires(
        "honeycomb-api-key",
        "hcai_AbCdEfGhIjKlMnOpQrStUv",
        "hcai_AbCdEfGhIjKlMnOpQrStUv",
    );
}

#[test]
fn adv95_honeycomb_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "honeycomb-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv95_honeycomb_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "honeycomb-api-key",
        "hcai_AbCdEfGh\u{200B}IjKlMnOpQrStUv",
        "hcai_AbCdEfGhIjKlMnOpQrStUv",
    );
}

#[test]
fn adv95_honeycomb_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "honeycomb-api-key",
        "hcai_AbCdEfGh\u{00AD}IjKlMnOpQrStUv",
        "hcai_AbCdEfGhIjKlMnOpQrStUv",
    );
}

#[test]
fn adv95_honeycomb_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "honeycomb-api-key",
        "hcai_AbCdEfGh\u{200C}IjKlMnOpQrStUv",
        "hcai_AbCdEfGhIjKlMnOpQrStUv",
    );
}

#[test]
fn adv95_honeycomb_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "honeycomb-api-key",
        "hcai_AbCdEfGh\u{200D}IjKlMnOpQrStUv",
        "hcai_AbCdEfGhIjKlMnOpQrStUv",
    );
}

#[test]
fn adv95_honeycomb_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "honeycomb-api-key",
        "hcai_AbCdEfGh\u{FEFF}IjKlMnOpQrStUv",
        "hcai_AbCdEfGhIjKlMnOpQrStUv",
    );
}

#[test]
fn adv95_honeycomb_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "honeycomb-api-key",
        "hcai_AbCdEfGh\u{2060}IjKlMnOpQrStUv",
        "hcai_AbCdEfGhIjKlMnOpQrStUv",
    );
}

#[test]
fn adv95_honeycomb_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "honeycomb-api-key",
        "hcai_AbCdEfGh\u{180E}IjKlMnOpQrStUv",
        "hcai_AbCdEfGhIjKlMnOpQrStUv",
    );
}

#[test]
fn adv95_honeycomb_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "honeycomb-api-key",
        "hcai_AbCdEfGh\u{202E}IjKlMnOpQrStUv",
        "hcai_AbCdEfGhIjKlMnOpQrStUv",
    );
}

#[test]
fn adv95_honeycomb_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "honeycomb-api-key",
        "hcai_AbCdEfGh\u{202C}IjKlMnOpQrStUv",
        "hcai_AbCdEfGhIjKlMnOpQrStUv",
    );
}

#[test]
fn adv95_honeycomb_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "honeycomb-api-key",
        "hcai_AbCdEfGh\u{200E}IjKlMnOpQrStUv",
        "hcai_AbCdEfGhIjKlMnOpQrStUv",
    );
}


