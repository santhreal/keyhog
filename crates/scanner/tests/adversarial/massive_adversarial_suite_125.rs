//! Part 125 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates scylladb, seaweedfs, sec, securitytrails, segment, segment, sendgrid, sendgrid, sentinelone, sentry detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. SCYLLADB CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv125_scylladb_credentials_normal_must_fire() {
    assert_detector_fires(
        "scylladb-credentials",
        "SCYLLA_TOKEN=NUuWFGMt567ege1hrYjO",
        "NUuWFGMt567ege1hrYjO",
    );
}

#[test]
fn adv125_scylladb_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "scylladb-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv125_scylladb_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "scylladb-credentials",
        "SCYLLA_TOKEN=NUuWFGMt56\u{200B}7ege1hrYjO",
        "NUuWFGMt567ege1hrYjO",
    );
}

#[test]
fn adv125_scylladb_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "scylladb-credentials",
        "SCYLLA_TOKEN=NUuWFGMt56\u{00AD}7ege1hrYjO",
        "NUuWFGMt567ege1hrYjO",
    );
}

#[test]
fn adv125_scylladb_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "scylladb-credentials",
        "SCYLLA_TOKEN=NUuWFGMt56\u{200C}7ege1hrYjO",
        "NUuWFGMt567ege1hrYjO",
    );
}

#[test]
fn adv125_scylladb_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "scylladb-credentials",
        "SCYLLA_TOKEN=NUuWFGMt56\u{200D}7ege1hrYjO",
        "NUuWFGMt567ege1hrYjO",
    );
}

#[test]
fn adv125_scylladb_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "scylladb-credentials",
        "SCYLLA_TOKEN=NUuWFGMt56\u{FEFF}7ege1hrYjO",
        "NUuWFGMt567ege1hrYjO",
    );
}

#[test]
fn adv125_scylladb_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "scylladb-credentials",
        "SCYLLA_TOKEN=NUuWFGMt56\u{2060}7ege1hrYjO",
        "NUuWFGMt567ege1hrYjO",
    );
}

#[test]
fn adv125_scylladb_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "scylladb-credentials",
        "SCYLLA_TOKEN=NUuWFGMt56\u{180E}7ege1hrYjO",
        "NUuWFGMt567ege1hrYjO",
    );
}

#[test]
fn adv125_scylladb_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "scylladb-credentials",
        "SCYLLA_TOKEN=NUuWFGMt56\u{202E}7ege1hrYjO",
        "NUuWFGMt567ege1hrYjO",
    );
}

#[test]
fn adv125_scylladb_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "scylladb-credentials",
        "SCYLLA_TOKEN=NUuWFGMt56\u{202C}7ege1hrYjO",
        "NUuWFGMt567ege1hrYjO",
    );
}

#[test]
fn adv125_scylladb_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "scylladb-credentials",
        "SCYLLA_TOKEN=NUuWFGMt56\u{200E}7ege1hrYjO",
        "NUuWFGMt567ege1hrYjO",
    );
}

// =========================================================================
// 2. SEAWEEDFS CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv125_seaweedfs_credentials_normal_must_fire() {
    assert_detector_fires(
        "seaweedfs-credentials",
        "SEAWEEDFS_ACCESS_KEY=p0TfUwn47PaB2",
        "p0TfUwn47PaB2",
    );
}

#[test]
fn adv125_seaweedfs_credentials_wrong_prefix_must_silent() {
    assert_detector_silent("seaweedfs-credentials", "dummy_prefix_0 =xxxxxxxxxxxxx");
}

#[test]
fn adv125_seaweedfs_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "seaweedfs-credentials",
        "SEAWEEDFS_ACCESS_KEY=p0TfUw\u{200B}n47PaB2",
        "p0TfUwn47PaB2",
    );
}

#[test]
fn adv125_seaweedfs_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "seaweedfs-credentials",
        "SEAWEEDFS_ACCESS_KEY=p0TfUw\u{00AD}n47PaB2",
        "p0TfUwn47PaB2",
    );
}

#[test]
fn adv125_seaweedfs_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "seaweedfs-credentials",
        "SEAWEEDFS_ACCESS_KEY=p0TfUw\u{200C}n47PaB2",
        "p0TfUwn47PaB2",
    );
}

#[test]
fn adv125_seaweedfs_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "seaweedfs-credentials",
        "SEAWEEDFS_ACCESS_KEY=p0TfUw\u{200D}n47PaB2",
        "p0TfUwn47PaB2",
    );
}

#[test]
fn adv125_seaweedfs_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "seaweedfs-credentials",
        "SEAWEEDFS_ACCESS_KEY=p0TfUw\u{FEFF}n47PaB2",
        "p0TfUwn47PaB2",
    );
}

#[test]
fn adv125_seaweedfs_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "seaweedfs-credentials",
        "SEAWEEDFS_ACCESS_KEY=p0TfUw\u{2060}n47PaB2",
        "p0TfUwn47PaB2",
    );
}

#[test]
fn adv125_seaweedfs_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "seaweedfs-credentials",
        "SEAWEEDFS_ACCESS_KEY=p0TfUw\u{180E}n47PaB2",
        "p0TfUwn47PaB2",
    );
}

#[test]
fn adv125_seaweedfs_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "seaweedfs-credentials",
        "SEAWEEDFS_ACCESS_KEY=p0TfUw\u{202E}n47PaB2",
        "p0TfUwn47PaB2",
    );
}

#[test]
fn adv125_seaweedfs_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "seaweedfs-credentials",
        "SEAWEEDFS_ACCESS_KEY=p0TfUw\u{202C}n47PaB2",
        "p0TfUwn47PaB2",
    );
}

#[test]
fn adv125_seaweedfs_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "seaweedfs-credentials",
        "SEAWEEDFS_ACCESS_KEY=p0TfUw\u{200E}n47PaB2",
        "p0TfUwn47PaB2",
    );
}

// =========================================================================
// 3. SEC EDGAR API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv125_sec_edgar_api_token_normal_must_fire() {
    assert_detector_fires(
        "sec-edgar-api-token",
        "EDGAR_API vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGahzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
        "vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGahzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
    );
}

#[test]
fn adv125_sec_edgar_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "sec-edgar-api-token",
        "dummyR_API xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv125_sec_edgar_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sec-edgar-api-token",
        "EDGAR_API vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGa\u{200B}hzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
        "vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGahzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
    );
}

#[test]
fn adv125_sec_edgar_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sec-edgar-api-token",
        "EDGAR_API vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGa\u{00AD}hzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
        "vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGahzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
    );
}

#[test]
fn adv125_sec_edgar_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "sec-edgar-api-token",
        "EDGAR_API vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGa\u{200C}hzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
        "vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGahzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
    );
}

#[test]
fn adv125_sec_edgar_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "sec-edgar-api-token",
        "EDGAR_API vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGa\u{200D}hzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
        "vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGahzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
    );
}

#[test]
fn adv125_sec_edgar_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "sec-edgar-api-token",
        "EDGAR_API vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGa\u{FEFF}hzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
        "vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGahzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
    );
}

#[test]
fn adv125_sec_edgar_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "sec-edgar-api-token",
        "EDGAR_API vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGa\u{2060}hzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
        "vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGahzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
    );
}

#[test]
fn adv125_sec_edgar_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "sec-edgar-api-token",
        "EDGAR_API vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGa\u{180E}hzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
        "vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGahzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
    );
}

#[test]
fn adv125_sec_edgar_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "sec-edgar-api-token",
        "EDGAR_API vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGa\u{202E}hzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
        "vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGahzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
    );
}

#[test]
fn adv125_sec_edgar_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "sec-edgar-api-token",
        "EDGAR_API vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGa\u{202C}hzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
        "vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGahzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
    );
}

#[test]
fn adv125_sec_edgar_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "sec-edgar-api-token",
        "EDGAR_API vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGa\u{200E}hzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
        "vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGahzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
    );
}

// =========================================================================
// 4. SECURITYTRAILS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv125_securitytrails_api_key_normal_must_fire() {
    assert_detector_fires(
        "securitytrails-api-key",
        "SECURITYTRAILS=89KxsottTaOI1AwvEP1nwB-xlX1oBgDN",
        "89KxsottTaOI1AwvEP1nwB-xlX1oBgDN",
    );
}

#[test]
fn adv125_securitytrails_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "securitytrails-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv125_securitytrails_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "securitytrails-api-key",
        "SECURITYTRAILS=89KxsottTaOI1Awv\u{200B}EP1nwB-xlX1oBgDN",
        "89KxsottTaOI1AwvEP1nwB-xlX1oBgDN",
    );
}

#[test]
fn adv125_securitytrails_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "securitytrails-api-key",
        "SECURITYTRAILS=89KxsottTaOI1Awv\u{00AD}EP1nwB-xlX1oBgDN",
        "89KxsottTaOI1AwvEP1nwB-xlX1oBgDN",
    );
}

#[test]
fn adv125_securitytrails_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "securitytrails-api-key",
        "SECURITYTRAILS=89KxsottTaOI1Awv\u{200C}EP1nwB-xlX1oBgDN",
        "89KxsottTaOI1AwvEP1nwB-xlX1oBgDN",
    );
}

#[test]
fn adv125_securitytrails_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "securitytrails-api-key",
        "SECURITYTRAILS=89KxsottTaOI1Awv\u{200D}EP1nwB-xlX1oBgDN",
        "89KxsottTaOI1AwvEP1nwB-xlX1oBgDN",
    );
}

#[test]
fn adv125_securitytrails_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "securitytrails-api-key",
        "SECURITYTRAILS=89KxsottTaOI1Awv\u{FEFF}EP1nwB-xlX1oBgDN",
        "89KxsottTaOI1AwvEP1nwB-xlX1oBgDN",
    );
}

#[test]
fn adv125_securitytrails_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "securitytrails-api-key",
        "SECURITYTRAILS=89KxsottTaOI1Awv\u{2060}EP1nwB-xlX1oBgDN",
        "89KxsottTaOI1AwvEP1nwB-xlX1oBgDN",
    );
}

#[test]
fn adv125_securitytrails_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "securitytrails-api-key",
        "SECURITYTRAILS=89KxsottTaOI1Awv\u{180E}EP1nwB-xlX1oBgDN",
        "89KxsottTaOI1AwvEP1nwB-xlX1oBgDN",
    );
}

#[test]
fn adv125_securitytrails_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "securitytrails-api-key",
        "SECURITYTRAILS=89KxsottTaOI1Awv\u{202E}EP1nwB-xlX1oBgDN",
        "89KxsottTaOI1AwvEP1nwB-xlX1oBgDN",
    );
}

#[test]
fn adv125_securitytrails_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "securitytrails-api-key",
        "SECURITYTRAILS=89KxsottTaOI1Awv\u{202C}EP1nwB-xlX1oBgDN",
        "89KxsottTaOI1AwvEP1nwB-xlX1oBgDN",
    );
}

#[test]
fn adv125_securitytrails_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "securitytrails-api-key",
        "SECURITYTRAILS=89KxsottTaOI1Awv\u{200E}EP1nwB-xlX1oBgDN",
        "89KxsottTaOI1AwvEP1nwB-xlX1oBgDN",
    );
}

// =========================================================================
// 5. SEGMENT SOURCES API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv125_segment_sources_api_token_normal_must_fire() {
    assert_detector_fires(
        "segment-sources-api-token",
        "SEGMENT_API_TOKEN=72qoIjIstcOUXiPOw9CuHNOHFEZLODhcJhlrNhR4Ff6d",
        "72qoIjIstcOUXiPOw9CuHNOHFEZLODhcJhlrNhR4Ff6d",
    );
}

#[test]
fn adv125_segment_sources_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "segment-sources-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv125_segment_sources_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "segment-sources-api-token",
        "SEGMENT_API_TOKEN=72qoIjIstcOUXiPOw9CuHN\u{200B}OHFEZLODhcJhlrNhR4Ff6d",
        "72qoIjIstcOUXiPOw9CuHNOHFEZLODhcJhlrNhR4Ff6d",
    );
}

#[test]
fn adv125_segment_sources_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "segment-sources-api-token",
        "SEGMENT_API_TOKEN=72qoIjIstcOUXiPOw9CuHN\u{00AD}OHFEZLODhcJhlrNhR4Ff6d",
        "72qoIjIstcOUXiPOw9CuHNOHFEZLODhcJhlrNhR4Ff6d",
    );
}

#[test]
fn adv125_segment_sources_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "segment-sources-api-token",
        "SEGMENT_API_TOKEN=72qoIjIstcOUXiPOw9CuHN\u{200C}OHFEZLODhcJhlrNhR4Ff6d",
        "72qoIjIstcOUXiPOw9CuHNOHFEZLODhcJhlrNhR4Ff6d",
    );
}

#[test]
fn adv125_segment_sources_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "segment-sources-api-token",
        "SEGMENT_API_TOKEN=72qoIjIstcOUXiPOw9CuHN\u{200D}OHFEZLODhcJhlrNhR4Ff6d",
        "72qoIjIstcOUXiPOw9CuHNOHFEZLODhcJhlrNhR4Ff6d",
    );
}

#[test]
fn adv125_segment_sources_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "segment-sources-api-token",
        "SEGMENT_API_TOKEN=72qoIjIstcOUXiPOw9CuHN\u{FEFF}OHFEZLODhcJhlrNhR4Ff6d",
        "72qoIjIstcOUXiPOw9CuHNOHFEZLODhcJhlrNhR4Ff6d",
    );
}

#[test]
fn adv125_segment_sources_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "segment-sources-api-token",
        "SEGMENT_API_TOKEN=72qoIjIstcOUXiPOw9CuHN\u{2060}OHFEZLODhcJhlrNhR4Ff6d",
        "72qoIjIstcOUXiPOw9CuHNOHFEZLODhcJhlrNhR4Ff6d",
    );
}

#[test]
fn adv125_segment_sources_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "segment-sources-api-token",
        "SEGMENT_API_TOKEN=72qoIjIstcOUXiPOw9CuHN\u{180E}OHFEZLODhcJhlrNhR4Ff6d",
        "72qoIjIstcOUXiPOw9CuHNOHFEZLODhcJhlrNhR4Ff6d",
    );
}

#[test]
fn adv125_segment_sources_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "segment-sources-api-token",
        "SEGMENT_API_TOKEN=72qoIjIstcOUXiPOw9CuHN\u{202E}OHFEZLODhcJhlrNhR4Ff6d",
        "72qoIjIstcOUXiPOw9CuHNOHFEZLODhcJhlrNhR4Ff6d",
    );
}

#[test]
fn adv125_segment_sources_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "segment-sources-api-token",
        "SEGMENT_API_TOKEN=72qoIjIstcOUXiPOw9CuHN\u{202C}OHFEZLODhcJhlrNhR4Ff6d",
        "72qoIjIstcOUXiPOw9CuHNOHFEZLODhcJhlrNhR4Ff6d",
    );
}

#[test]
fn adv125_segment_sources_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "segment-sources-api-token",
        "SEGMENT_API_TOKEN=72qoIjIstcOUXiPOw9CuHN\u{200E}OHFEZLODhcJhlrNhR4Ff6d",
        "72qoIjIstcOUXiPOw9CuHNOHFEZLODhcJhlrNhR4Ff6d",
    );
}

// =========================================================================
// 6. SEGMENT WRITE KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv125_segment_write_key_normal_must_fire() {
    assert_detector_fires(
        "segment-write-key",
        "segment_write_key=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
    );
}

#[test]
fn adv125_segment_write_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "segment-write-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv125_segment_write_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "segment-write-key",
        "segment_write_key=YWJjZGVmZ2hpamtsbW5vcH\u{200B}Fyc3R1dnd4eXoxMjM0NTY=",
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
    );
}

#[test]
fn adv125_segment_write_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "segment-write-key",
        "segment_write_key=YWJjZGVmZ2hpamtsbW5vcH\u{00AD}Fyc3R1dnd4eXoxMjM0NTY=",
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
    );
}

#[test]
fn adv125_segment_write_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "segment-write-key",
        "segment_write_key=YWJjZGVmZ2hpamtsbW5vcH\u{200C}Fyc3R1dnd4eXoxMjM0NTY=",
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
    );
}

#[test]
fn adv125_segment_write_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "segment-write-key",
        "segment_write_key=YWJjZGVmZ2hpamtsbW5vcH\u{200D}Fyc3R1dnd4eXoxMjM0NTY=",
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
    );
}

#[test]
fn adv125_segment_write_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "segment-write-key",
        "segment_write_key=YWJjZGVmZ2hpamtsbW5vcH\u{FEFF}Fyc3R1dnd4eXoxMjM0NTY=",
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
    );
}

#[test]
fn adv125_segment_write_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "segment-write-key",
        "segment_write_key=YWJjZGVmZ2hpamtsbW5vcH\u{2060}Fyc3R1dnd4eXoxMjM0NTY=",
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
    );
}

#[test]
fn adv125_segment_write_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "segment-write-key",
        "segment_write_key=YWJjZGVmZ2hpamtsbW5vcH\u{180E}Fyc3R1dnd4eXoxMjM0NTY=",
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
    );
}

#[test]
fn adv125_segment_write_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "segment-write-key",
        "segment_write_key=YWJjZGVmZ2hpamtsbW5vcH\u{202E}Fyc3R1dnd4eXoxMjM0NTY=",
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
    );
}

#[test]
fn adv125_segment_write_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "segment-write-key",
        "segment_write_key=YWJjZGVmZ2hpamtsbW5vcH\u{202C}Fyc3R1dnd4eXoxMjM0NTY=",
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
    );
}

#[test]
fn adv125_segment_write_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "segment-write-key",
        "segment_write_key=YWJjZGVmZ2hpamtsbW5vcH\u{200E}Fyc3R1dnd4eXoxMjM0NTY=",
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
    );
}

// =========================================================================
// 7. SENDGRID API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv125_sendgrid_api_key_normal_must_fire() {
    assert_detector_fires(
        "sendgrid-api-key",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
    );
}

#[test]
fn adv125_sendgrid_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "sendgrid-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv125_sendgrid_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sendgrid-api-key",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHa\u{200B}IoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
    );
}

#[test]
fn adv125_sendgrid_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sendgrid-api-key",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHa\u{00AD}IoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
    );
}

#[test]
fn adv125_sendgrid_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "sendgrid-api-key",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHa\u{200C}IoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
    );
}

#[test]
fn adv125_sendgrid_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "sendgrid-api-key",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHa\u{200D}IoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
    );
}

#[test]
fn adv125_sendgrid_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "sendgrid-api-key",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHa\u{FEFF}IoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
    );
}

#[test]
fn adv125_sendgrid_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "sendgrid-api-key",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHa\u{2060}IoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
    );
}

#[test]
fn adv125_sendgrid_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "sendgrid-api-key",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHa\u{180E}IoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
    );
}

#[test]
fn adv125_sendgrid_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "sendgrid-api-key",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHa\u{202E}IoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
    );
}

#[test]
fn adv125_sendgrid_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "sendgrid-api-key",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHa\u{202C}IoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
    );
}

#[test]
fn adv125_sendgrid_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "sendgrid-api-key",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHa\u{200E}IoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
        "SG.9X3kQp7VbT2hYRzNcMfWj4.DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeF",
    );
}

// =========================================================================
// 8. SENDGRID WEBHOOK SIGNING SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv125_sendgrid_webhook_signing_secret_normal_must_fire() {
    assert_detector_fires(
        "sendgrid-webhook-signing-secret",
        "SENDGRIDWEBHOOKSIGNING=fcbd4f520552bce529c480d614790d74",
        "fcbd4f520552bce529c480d614790d74",
    );
}

#[test]
fn adv125_sendgrid_webhook_signing_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "sendgrid-webhook-signing-secret",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv125_sendgrid_webhook_signing_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sendgrid-webhook-signing-secret",
        "SENDGRIDWEBHOOKSIGNING=fcbd4f520552bce5\u{200B}29c480d614790d74",
        "fcbd4f520552bce529c480d614790d74",
    );
}

#[test]
fn adv125_sendgrid_webhook_signing_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sendgrid-webhook-signing-secret",
        "SENDGRIDWEBHOOKSIGNING=fcbd4f520552bce5\u{00AD}29c480d614790d74",
        "fcbd4f520552bce529c480d614790d74",
    );
}

#[test]
fn adv125_sendgrid_webhook_signing_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "sendgrid-webhook-signing-secret",
        "SENDGRIDWEBHOOKSIGNING=fcbd4f520552bce5\u{200C}29c480d614790d74",
        "fcbd4f520552bce529c480d614790d74",
    );
}

#[test]
fn adv125_sendgrid_webhook_signing_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "sendgrid-webhook-signing-secret",
        "SENDGRIDWEBHOOKSIGNING=fcbd4f520552bce5\u{200D}29c480d614790d74",
        "fcbd4f520552bce529c480d614790d74",
    );
}

#[test]
fn adv125_sendgrid_webhook_signing_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "sendgrid-webhook-signing-secret",
        "SENDGRIDWEBHOOKSIGNING=fcbd4f520552bce5\u{FEFF}29c480d614790d74",
        "fcbd4f520552bce529c480d614790d74",
    );
}

#[test]
fn adv125_sendgrid_webhook_signing_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "sendgrid-webhook-signing-secret",
        "SENDGRIDWEBHOOKSIGNING=fcbd4f520552bce5\u{2060}29c480d614790d74",
        "fcbd4f520552bce529c480d614790d74",
    );
}

#[test]
fn adv125_sendgrid_webhook_signing_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "sendgrid-webhook-signing-secret",
        "SENDGRIDWEBHOOKSIGNING=fcbd4f520552bce5\u{180E}29c480d614790d74",
        "fcbd4f520552bce529c480d614790d74",
    );
}

#[test]
fn adv125_sendgrid_webhook_signing_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "sendgrid-webhook-signing-secret",
        "SENDGRIDWEBHOOKSIGNING=fcbd4f520552bce5\u{202E}29c480d614790d74",
        "fcbd4f520552bce529c480d614790d74",
    );
}

#[test]
fn adv125_sendgrid_webhook_signing_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "sendgrid-webhook-signing-secret",
        "SENDGRIDWEBHOOKSIGNING=fcbd4f520552bce5\u{202C}29c480d614790d74",
        "fcbd4f520552bce529c480d614790d74",
    );
}

#[test]
fn adv125_sendgrid_webhook_signing_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "sendgrid-webhook-signing-secret",
        "SENDGRIDWEBHOOKSIGNING=fcbd4f520552bce5\u{200E}29c480d614790d74",
        "fcbd4f520552bce529c480d614790d74",
    );
}

// =========================================================================
// 9. SENTINELONE API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv125_sentinelone_api_token_normal_must_fire() {
    assert_detector_fires(
        "sentinelone-api-token",
        "SENTINELONE_API_TOKEN=VTLKc1UW3ORMthMR2228PzVvccx9vfRITHRsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
        "VTLKc1UW3ORMthMR2228PzVvccx9vfRITHRsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
    );
}

#[test]
fn adv125_sentinelone_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "sentinelone-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv125_sentinelone_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sentinelone-api-token",
        "SENTINELONE_API_TOKEN=VTLKc1UW3ORMthMR2228PzVvccx9vfRITH\u{200B}RsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
        "VTLKc1UW3ORMthMR2228PzVvccx9vfRITHRsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
    );
}

#[test]
fn adv125_sentinelone_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sentinelone-api-token",
        "SENTINELONE_API_TOKEN=VTLKc1UW3ORMthMR2228PzVvccx9vfRITH\u{00AD}RsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
        "VTLKc1UW3ORMthMR2228PzVvccx9vfRITHRsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
    );
}

#[test]
fn adv125_sentinelone_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "sentinelone-api-token",
        "SENTINELONE_API_TOKEN=VTLKc1UW3ORMthMR2228PzVvccx9vfRITH\u{200C}RsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
        "VTLKc1UW3ORMthMR2228PzVvccx9vfRITHRsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
    );
}

#[test]
fn adv125_sentinelone_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "sentinelone-api-token",
        "SENTINELONE_API_TOKEN=VTLKc1UW3ORMthMR2228PzVvccx9vfRITH\u{200D}RsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
        "VTLKc1UW3ORMthMR2228PzVvccx9vfRITHRsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
    );
}

#[test]
fn adv125_sentinelone_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "sentinelone-api-token",
        "SENTINELONE_API_TOKEN=VTLKc1UW3ORMthMR2228PzVvccx9vfRITH\u{FEFF}RsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
        "VTLKc1UW3ORMthMR2228PzVvccx9vfRITHRsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
    );
}

#[test]
fn adv125_sentinelone_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "sentinelone-api-token",
        "SENTINELONE_API_TOKEN=VTLKc1UW3ORMthMR2228PzVvccx9vfRITH\u{2060}RsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
        "VTLKc1UW3ORMthMR2228PzVvccx9vfRITHRsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
    );
}

#[test]
fn adv125_sentinelone_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "sentinelone-api-token",
        "SENTINELONE_API_TOKEN=VTLKc1UW3ORMthMR2228PzVvccx9vfRITH\u{180E}RsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
        "VTLKc1UW3ORMthMR2228PzVvccx9vfRITHRsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
    );
}

#[test]
fn adv125_sentinelone_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "sentinelone-api-token",
        "SENTINELONE_API_TOKEN=VTLKc1UW3ORMthMR2228PzVvccx9vfRITH\u{202E}RsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
        "VTLKc1UW3ORMthMR2228PzVvccx9vfRITHRsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
    );
}

#[test]
fn adv125_sentinelone_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "sentinelone-api-token",
        "SENTINELONE_API_TOKEN=VTLKc1UW3ORMthMR2228PzVvccx9vfRITH\u{202C}RsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
        "VTLKc1UW3ORMthMR2228PzVvccx9vfRITHRsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
    );
}

#[test]
fn adv125_sentinelone_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "sentinelone-api-token",
        "SENTINELONE_API_TOKEN=VTLKc1UW3ORMthMR2228PzVvccx9vfRITH\u{200E}RsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
        "VTLKc1UW3ORMthMR2228PzVvccx9vfRITHRsJ7kuH_XizcBV9Cd4tf-PTl-yPLEYJc-a",
    );
}

// =========================================================================
// 10. SENTRY API KEY LEGACY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv125_sentry_api_key_legacy_normal_must_fire() {
    assert_detector_fires(
        "sentry-api-key-legacy",
        "SENTRY_API_KEY=26551c665f4a3f14f1162c872eddb8bc",
        "26551c665f4a3f14f1162c872eddb8bc",
    );
}

#[test]
fn adv125_sentry_api_key_legacy_wrong_prefix_must_silent() {
    assert_detector_silent(
        "sentry-api-key-legacy",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv125_sentry_api_key_legacy_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sentry-api-key-legacy",
        "SENTRY_API_KEY=26551c665f4a3f14\u{200B}f1162c872eddb8bc",
        "26551c665f4a3f14f1162c872eddb8bc",
    );
}

#[test]
fn adv125_sentry_api_key_legacy_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sentry-api-key-legacy",
        "SENTRY_API_KEY=26551c665f4a3f14\u{00AD}f1162c872eddb8bc",
        "26551c665f4a3f14f1162c872eddb8bc",
    );
}

#[test]
fn adv125_sentry_api_key_legacy_evade_zwnj_must_fire() {
    assert_detector_fires(
        "sentry-api-key-legacy",
        "SENTRY_API_KEY=26551c665f4a3f14\u{200C}f1162c872eddb8bc",
        "26551c665f4a3f14f1162c872eddb8bc",
    );
}

#[test]
fn adv125_sentry_api_key_legacy_evade_zwj_must_fire() {
    assert_detector_fires(
        "sentry-api-key-legacy",
        "SENTRY_API_KEY=26551c665f4a3f14\u{200D}f1162c872eddb8bc",
        "26551c665f4a3f14f1162c872eddb8bc",
    );
}

#[test]
fn adv125_sentry_api_key_legacy_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "sentry-api-key-legacy",
        "SENTRY_API_KEY=26551c665f4a3f14\u{FEFF}f1162c872eddb8bc",
        "26551c665f4a3f14f1162c872eddb8bc",
    );
}

#[test]
fn adv125_sentry_api_key_legacy_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "sentry-api-key-legacy",
        "SENTRY_API_KEY=26551c665f4a3f14\u{2060}f1162c872eddb8bc",
        "26551c665f4a3f14f1162c872eddb8bc",
    );
}

#[test]
fn adv125_sentry_api_key_legacy_evade_mongolian_must_fire() {
    assert_detector_fires(
        "sentry-api-key-legacy",
        "SENTRY_API_KEY=26551c665f4a3f14\u{180E}f1162c872eddb8bc",
        "26551c665f4a3f14f1162c872eddb8bc",
    );
}

#[test]
fn adv125_sentry_api_key_legacy_evade_rtl_must_fire() {
    assert_detector_fires(
        "sentry-api-key-legacy",
        "SENTRY_API_KEY=26551c665f4a3f14\u{202E}f1162c872eddb8bc",
        "26551c665f4a3f14f1162c872eddb8bc",
    );
}

#[test]
fn adv125_sentry_api_key_legacy_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "sentry-api-key-legacy",
        "SENTRY_API_KEY=26551c665f4a3f14\u{202C}f1162c872eddb8bc",
        "26551c665f4a3f14f1162c872eddb8bc",
    );
}

#[test]
fn adv125_sentry_api_key_legacy_evade_lrm_must_fire() {
    assert_detector_fires(
        "sentry-api-key-legacy",
        "SENTRY_API_KEY=26551c665f4a3f14\u{200E}f1162c872eddb8bc",
        "26551c665f4a3f14f1162c872eddb8bc",
    );
}
