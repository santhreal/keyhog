//! Part 61 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates scrapeops, scraperapi, scrapingbee, scylladb, seaweedfs, sec, securitytrails, segment, segment, sendgrid detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. SCRAPEOPS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv61_scrapeops_api_key_normal_must_fire() {
    assert_detector_fires(
        "scrapeops-api-key",
        "scrapeops=42lzch6Jg83lGwx5zyvvoA4A5ClC9pjf",
        "42lzch6Jg83lGwx5zyvvoA4A5ClC9pjf",
    );
}

#[test]
fn adv61_scrapeops_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "scrapeops-api-key",
        "dummy_prefix_0 =xxxzch6Jg83lGwx5zyvvoA4A5ClC9pjf",
    );
}

#[test]
fn adv61_scrapeops_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "scrapeops-api-key",
        "scrapeops=42lzch6Jg83lGwx5\u{200B}zyvvoA4A5ClC9pjf",
        "42lzch6Jg83lGwx5zyvvoA4A5ClC9pjf",
    );
}

#[test]
fn adv61_scrapeops_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "scrapeops-api-key",
        "scrapeops=42lzch6Jg83lGwx5\u{00AD}zyvvoA4A5ClC9pjf",
        "42lzch6Jg83lGwx5zyvvoA4A5ClC9pjf",
    );
}

// =========================================================================
// 2. SCRAPERAPI KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv61_scraperapi_key_normal_must_fire() {
    assert_detector_fires(
        "scraperapi-key",
        "scraperapi=izPAS25CHzk8Sz3oh4TMdXOqCCQnaX8d",
        "izPAS25CHzk8Sz3oh4TMdXOqCCQnaX8d",
    );
}

#[test]
fn adv61_scraperapi_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "scraperapi-key",
        "dummy_prefix_0 =xxxAS25CHzk8Sz3oh4TMdXOqCCQnaX8d",
    );
}

#[test]
fn adv61_scraperapi_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "scraperapi-key",
        "scraperapi=izPAS25CHzk8Sz3o\u{200B}h4TMdXOqCCQnaX8d",
        "izPAS25CHzk8Sz3oh4TMdXOqCCQnaX8d",
    );
}

#[test]
fn adv61_scraperapi_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "scraperapi-key",
        "scraperapi=izPAS25CHzk8Sz3o\u{00AD}h4TMdXOqCCQnaX8d",
        "izPAS25CHzk8Sz3oh4TMdXOqCCQnaX8d",
    );
}

// =========================================================================
// 3. SCRAPINGBEE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv61_scrapingbee_api_key_normal_must_fire() {
    assert_detector_fires(
        "scrapingbee-api-key",
        "scrapingbee=cnSctbWZ2NV8jmNLV0upUAtUAAP2aK3l",
        "cnSctbWZ2NV8jmNLV0upUAtUAAP2aK3l",
    );
}

#[test]
fn adv61_scrapingbee_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "scrapingbee-api-key",
        "dummy_prefix_0 =xxxctbWZ2NV8jmNLV0upUAtUAAP2aK3l",
    );
}

#[test]
fn adv61_scrapingbee_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "scrapingbee-api-key",
        "scrapingbee=cnSctbWZ2NV8jmNL\u{200B}V0upUAtUAAP2aK3l",
        "cnSctbWZ2NV8jmNLV0upUAtUAAP2aK3l",
    );
}

#[test]
fn adv61_scrapingbee_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "scrapingbee-api-key",
        "scrapingbee=cnSctbWZ2NV8jmNL\u{00AD}V0upUAtUAAP2aK3l",
        "cnSctbWZ2NV8jmNLV0upUAtUAAP2aK3l",
    );
}

// =========================================================================
// 4. SCYLLADB CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv61_scylladb_credentials_normal_must_fire() {
    assert_detector_fires(
        "scylladb-credentials",
        "SCYLLA_TOKEN=NUuWFGMt567ege1hrYjO",
        "NUuWFGMt567ege1hrYjO",
    );
}

#[test]
fn adv61_scylladb_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "scylladb-credentials",
        "dummy_prefix_0 =xxxWFGMt567ege1hrYjO",
    );
}

#[test]
fn adv61_scylladb_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "scylladb-credentials",
        "SCYLLA_TOKEN=NUuWFGMt56\u{200B}7ege1hrYjO",
        "NUuWFGMt567ege1hrYjO",
    );
}

#[test]
fn adv61_scylladb_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "scylladb-credentials",
        "SCYLLA_TOKEN=NUuWFGMt56\u{00AD}7ege1hrYjO",
        "NUuWFGMt567ege1hrYjO",
    );
}

// =========================================================================
// 5. SEAWEEDFS CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv61_seaweedfs_credentials_normal_must_fire() {
    assert_detector_fires(
        "seaweedfs-credentials",
        "SEAWEEDFS_ACCESS_KEY=p0TfUwn47PaB2",
        "p0TfUwn47PaB2",
    );
}

#[test]
fn adv61_seaweedfs_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "seaweedfs-credentials",
        "dummy_prefix_0 =xxxfUwn47PaB2",
    );
}

#[test]
fn adv61_seaweedfs_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "seaweedfs-credentials",
        "SEAWEEDFS_ACCESS_KEY=p0TfUw\u{200B}n47PaB2",
        "p0TfUwn47PaB2",
    );
}

#[test]
fn adv61_seaweedfs_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "seaweedfs-credentials",
        "SEAWEEDFS_ACCESS_KEY=p0TfUw\u{00AD}n47PaB2",
        "p0TfUwn47PaB2",
    );
}

// =========================================================================
// 6. SEC EDGAR API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv61_sec_edgar_api_token_normal_must_fire() {
    assert_detector_fires(
        "sec-edgar-api-token",
        "EDGAR_API vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGahzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
        "vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGahzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
    );
}

#[test]
fn adv61_sec_edgar_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "sec-edgar-api-token",
        "dummyR_API xxxmNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGahzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
    );
}

#[test]
fn adv61_sec_edgar_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sec-edgar-api-token",
        "EDGAR_API vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGa\u{200B}hzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
        "vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGahzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
    );
}

#[test]
fn adv61_sec_edgar_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sec-edgar-api-token",
        "EDGAR_API vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGa\u{00AD}hzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
        "vNymNhkRusErbZf8JQ7LhW-77W4yTk1CM2D9LyQG1r-IPu71kc2PGahzHZ_LFgQfK2Rv5ewycQQmqKv3Ox9059uiKFJ17k.BYKt9YjY09.Cj",
    );
}

// =========================================================================
// 7. SECURITYTRAILS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv61_securitytrails_api_key_normal_must_fire() {
    assert_detector_fires(
        "securitytrails-api-key",
        "SECURITYTRAILS=89KxsottTaOI1AwvEP1nwB-xlX1oBgDN",
        "89KxsottTaOI1AwvEP1nwB-xlX1oBgDN",
    );
}

#[test]
fn adv61_securitytrails_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "securitytrails-api-key",
        "dummy_prefix_0 =xxxxsottTaOI1AwvEP1nwB-xlX1oBgDN",
    );
}

#[test]
fn adv61_securitytrails_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "securitytrails-api-key",
        "SECURITYTRAILS=89KxsottTaOI1Awv\u{200B}EP1nwB-xlX1oBgDN",
        "89KxsottTaOI1AwvEP1nwB-xlX1oBgDN",
    );
}

#[test]
fn adv61_securitytrails_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "securitytrails-api-key",
        "SECURITYTRAILS=89KxsottTaOI1Awv\u{00AD}EP1nwB-xlX1oBgDN",
        "89KxsottTaOI1AwvEP1nwB-xlX1oBgDN",
    );
}

// =========================================================================
// 8. SEGMENT SOURCES API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv61_segment_sources_api_token_normal_must_fire() {
    assert_detector_fires(
        "segment-sources-api-token",
        "SEGMENT_API_TOKEN=72qoIjIstcOUXiPOw9CuHNOHFEZLODhcJhlrNhR4Ff6d",
        "72qoIjIstcOUXiPOw9CuHNOHFEZLODhcJhlrNhR4Ff6d",
    );
}

#[test]
fn adv61_segment_sources_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "segment-sources-api-token",
        "dummy_prefix_0 =xxxoIjIstcOUXiPOw9CuHNOHFEZLODhcJhlrNhR4Ff6d",
    );
}

#[test]
fn adv61_segment_sources_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "segment-sources-api-token",
        "SEGMENT_API_TOKEN=72qoIjIstcOUXiPOw9CuHN\u{200B}OHFEZLODhcJhlrNhR4Ff6d",
        "72qoIjIstcOUXiPOw9CuHNOHFEZLODhcJhlrNhR4Ff6d",
    );
}

#[test]
fn adv61_segment_sources_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "segment-sources-api-token",
        "SEGMENT_API_TOKEN=72qoIjIstcOUXiPOw9CuHN\u{00AD}OHFEZLODhcJhlrNhR4Ff6d",
        "72qoIjIstcOUXiPOw9CuHNOHFEZLODhcJhlrNhR4Ff6d",
    );
}

// =========================================================================
// 9. SEGMENT WRITE KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv61_segment_write_key_normal_must_fire() {
    assert_detector_fires(
        "segment-write-key",
        "segment_write_key=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
    );
}

#[test]
fn adv61_segment_write_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "segment-write-key",
        "dummy_prefix_0 =xxxjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
    );
}

#[test]
fn adv61_segment_write_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "segment-write-key",
        "segment_write_key=YWJjZGVmZ2hpamtsbW5vcH\u{200B}Fyc3R1dnd4eXoxMjM0NTY=",
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
    );
}

#[test]
fn adv61_segment_write_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "segment-write-key",
        "segment_write_key=YWJjZGVmZ2hpamtsbW5vcH\u{00AD}Fyc3R1dnd4eXoxMjM0NTY=",
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
    );
}

// =========================================================================
// 10. SENDGRID WEBHOOK SIGNING SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv61_sendgrid_webhook_signing_secret_normal_must_fire() {
    assert_detector_fires(
        "sendgrid-webhook-signing-secret",
        "SENDGRIDWEBHOOKSIGNING=fcbd4f520552bce529c480d614790d74",
        "fcbd4f520552bce529c480d614790d74",
    );
}

#[test]
fn adv61_sendgrid_webhook_signing_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "sendgrid-webhook-signing-secret",
        "dummy_prefix_0 =xxxd4f520552bce529c480d614790d74",
    );
}

#[test]
fn adv61_sendgrid_webhook_signing_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sendgrid-webhook-signing-secret",
        "SENDGRIDWEBHOOKSIGNING=fcbd4f520552bce5\u{200B}29c480d614790d74",
        "fcbd4f520552bce529c480d614790d74",
    );
}

#[test]
fn adv61_sendgrid_webhook_signing_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sendgrid-webhook-signing-secret",
        "SENDGRIDWEBHOOKSIGNING=fcbd4f520552bce5\u{00AD}29c480d614790d74",
        "fcbd4f520552bce529c480d614790d74",
    );
}


