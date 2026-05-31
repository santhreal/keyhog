//! Part 97 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates ifttt, incident, india, infinite, influxdb, infobip, infura, instabug, integromat, intelowl detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. IFTTT SERVICE KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv97_ifttt_service_key_normal_must_fire() {
    assert_detector_fires(
        "ifttt-service-key",
        "IFTTT=BKrT2666jEnUtrVPk0CJeL",
        "BKrT2666jEnUtrVPk0CJeL",
    );
}

#[test]
fn adv97_ifttt_service_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ifttt-service-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv97_ifttt_service_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ifttt-service-key",
        "IFTTT=BKrT2666jEn\u{200B}UtrVPk0CJeL",
        "BKrT2666jEnUtrVPk0CJeL",
    );
}

#[test]
fn adv97_ifttt_service_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ifttt-service-key",
        "IFTTT=BKrT2666jEn\u{00AD}UtrVPk0CJeL",
        "BKrT2666jEnUtrVPk0CJeL",
    );
}

#[test]
fn adv97_ifttt_service_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "ifttt-service-key",
        "IFTTT=BKrT2666jEn\u{200C}UtrVPk0CJeL",
        "BKrT2666jEnUtrVPk0CJeL",
    );
}

#[test]
fn adv97_ifttt_service_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "ifttt-service-key",
        "IFTTT=BKrT2666jEn\u{200D}UtrVPk0CJeL",
        "BKrT2666jEnUtrVPk0CJeL",
    );
}

#[test]
fn adv97_ifttt_service_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "ifttt-service-key",
        "IFTTT=BKrT2666jEn\u{FEFF}UtrVPk0CJeL",
        "BKrT2666jEnUtrVPk0CJeL",
    );
}

#[test]
fn adv97_ifttt_service_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "ifttt-service-key",
        "IFTTT=BKrT2666jEn\u{2060}UtrVPk0CJeL",
        "BKrT2666jEnUtrVPk0CJeL",
    );
}

#[test]
fn adv97_ifttt_service_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "ifttt-service-key",
        "IFTTT=BKrT2666jEn\u{180E}UtrVPk0CJeL",
        "BKrT2666jEnUtrVPk0CJeL",
    );
}

#[test]
fn adv97_ifttt_service_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "ifttt-service-key",
        "IFTTT=BKrT2666jEn\u{202E}UtrVPk0CJeL",
        "BKrT2666jEnUtrVPk0CJeL",
    );
}

#[test]
fn adv97_ifttt_service_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "ifttt-service-key",
        "IFTTT=BKrT2666jEn\u{202C}UtrVPk0CJeL",
        "BKrT2666jEnUtrVPk0CJeL",
    );
}

#[test]
fn adv97_ifttt_service_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "ifttt-service-key",
        "IFTTT=BKrT2666jEn\u{200E}UtrVPk0CJeL",
        "BKrT2666jEnUtrVPk0CJeL",
    );
}

// =========================================================================
// 2. INCIDENT IO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv97_incident_io_api_key_normal_must_fire() {
    assert_detector_fires(
        "incident-io-api-key",
        "INCIDENT_IO_API_KEY=IrON1dLQ2vmde7SqtJhGTXdxVeT9UbiuUXv9yO5a",
        "IrON1dLQ2vmde7SqtJhGTXdxVeT9UbiuUXv9yO5a",
    );
}

#[test]
fn adv97_incident_io_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "incident-io-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv97_incident_io_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "incident-io-api-key",
        "INCIDENT_IO_API_KEY=IrON1dLQ2vmde7SqtJhG\u{200B}TXdxVeT9UbiuUXv9yO5a",
        "IrON1dLQ2vmde7SqtJhGTXdxVeT9UbiuUXv9yO5a",
    );
}

#[test]
fn adv97_incident_io_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "incident-io-api-key",
        "INCIDENT_IO_API_KEY=IrON1dLQ2vmde7SqtJhG\u{00AD}TXdxVeT9UbiuUXv9yO5a",
        "IrON1dLQ2vmde7SqtJhGTXdxVeT9UbiuUXv9yO5a",
    );
}

#[test]
fn adv97_incident_io_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "incident-io-api-key",
        "INCIDENT_IO_API_KEY=IrON1dLQ2vmde7SqtJhG\u{200C}TXdxVeT9UbiuUXv9yO5a",
        "IrON1dLQ2vmde7SqtJhGTXdxVeT9UbiuUXv9yO5a",
    );
}

#[test]
fn adv97_incident_io_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "incident-io-api-key",
        "INCIDENT_IO_API_KEY=IrON1dLQ2vmde7SqtJhG\u{200D}TXdxVeT9UbiuUXv9yO5a",
        "IrON1dLQ2vmde7SqtJhGTXdxVeT9UbiuUXv9yO5a",
    );
}

#[test]
fn adv97_incident_io_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "incident-io-api-key",
        "INCIDENT_IO_API_KEY=IrON1dLQ2vmde7SqtJhG\u{FEFF}TXdxVeT9UbiuUXv9yO5a",
        "IrON1dLQ2vmde7SqtJhGTXdxVeT9UbiuUXv9yO5a",
    );
}

#[test]
fn adv97_incident_io_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "incident-io-api-key",
        "INCIDENT_IO_API_KEY=IrON1dLQ2vmde7SqtJhG\u{2060}TXdxVeT9UbiuUXv9yO5a",
        "IrON1dLQ2vmde7SqtJhGTXdxVeT9UbiuUXv9yO5a",
    );
}

#[test]
fn adv97_incident_io_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "incident-io-api-key",
        "INCIDENT_IO_API_KEY=IrON1dLQ2vmde7SqtJhG\u{180E}TXdxVeT9UbiuUXv9yO5a",
        "IrON1dLQ2vmde7SqtJhGTXdxVeT9UbiuUXv9yO5a",
    );
}

#[test]
fn adv97_incident_io_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "incident-io-api-key",
        "INCIDENT_IO_API_KEY=IrON1dLQ2vmde7SqtJhG\u{202E}TXdxVeT9UbiuUXv9yO5a",
        "IrON1dLQ2vmde7SqtJhGTXdxVeT9UbiuUXv9yO5a",
    );
}

#[test]
fn adv97_incident_io_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "incident-io-api-key",
        "INCIDENT_IO_API_KEY=IrON1dLQ2vmde7SqtJhG\u{202C}TXdxVeT9UbiuUXv9yO5a",
        "IrON1dLQ2vmde7SqtJhGTXdxVeT9UbiuUXv9yO5a",
    );
}

#[test]
fn adv97_incident_io_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "incident-io-api-key",
        "INCIDENT_IO_API_KEY=IrON1dLQ2vmde7SqtJhG\u{200E}TXdxVeT9UbiuUXv9yO5a",
        "IrON1dLQ2vmde7SqtJhGTXdxVeT9UbiuUXv9yO5a",
    );
}

// =========================================================================
// 3. INDIA AADHAAR API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv97_india_aadhaar_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "india-aadhaar-api-credentials",
        "AADHAARaua_license=BSBI4M5E5W",
        "BSBI4M5E5W",
    );
}

#[test]
fn adv97_india_aadhaar_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "india-aadhaar-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxx",
    );
}

#[test]
fn adv97_india_aadhaar_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "india-aadhaar-api-credentials",
        "AADHAARaua_license=BSBI4\u{200B}M5E5W",
        "BSBI4M5E5W",
    );
}

#[test]
fn adv97_india_aadhaar_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "india-aadhaar-api-credentials",
        "AADHAARaua_license=BSBI4\u{00AD}M5E5W",
        "BSBI4M5E5W",
    );
}

#[test]
fn adv97_india_aadhaar_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "india-aadhaar-api-credentials",
        "AADHAARaua_license=BSBI4\u{200C}M5E5W",
        "BSBI4M5E5W",
    );
}

#[test]
fn adv97_india_aadhaar_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "india-aadhaar-api-credentials",
        "AADHAARaua_license=BSBI4\u{200D}M5E5W",
        "BSBI4M5E5W",
    );
}

#[test]
fn adv97_india_aadhaar_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "india-aadhaar-api-credentials",
        "AADHAARaua_license=BSBI4\u{FEFF}M5E5W",
        "BSBI4M5E5W",
    );
}

#[test]
fn adv97_india_aadhaar_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "india-aadhaar-api-credentials",
        "AADHAARaua_license=BSBI4\u{2060}M5E5W",
        "BSBI4M5E5W",
    );
}

#[test]
fn adv97_india_aadhaar_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "india-aadhaar-api-credentials",
        "AADHAARaua_license=BSBI4\u{180E}M5E5W",
        "BSBI4M5E5W",
    );
}

#[test]
fn adv97_india_aadhaar_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "india-aadhaar-api-credentials",
        "AADHAARaua_license=BSBI4\u{202E}M5E5W",
        "BSBI4M5E5W",
    );
}

#[test]
fn adv97_india_aadhaar_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "india-aadhaar-api-credentials",
        "AADHAARaua_license=BSBI4\u{202C}M5E5W",
        "BSBI4M5E5W",
    );
}

#[test]
fn adv97_india_aadhaar_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "india-aadhaar-api-credentials",
        "AADHAARaua_license=BSBI4\u{200E}M5E5W",
        "BSBI4M5E5W",
    );
}

// =========================================================================
// 4. INFINITE CAMPUS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv97_infinite_campus_api_key_normal_must_fire() {
    assert_detector_fires(
        "infinite-campus-api-key",
        "icampustoken=ANZcW4wlbGyKxSYTt7tRd9mTWo12cjlV",
        "ANZcW4wlbGyKxSYTt7tRd9mTWo12cjlV",
    );
}

#[test]
fn adv97_infinite_campus_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "infinite-campus-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv97_infinite_campus_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "infinite-campus-api-key",
        "icampustoken=ANZcW4wlbGyKxSYT\u{200B}t7tRd9mTWo12cjlV",
        "ANZcW4wlbGyKxSYTt7tRd9mTWo12cjlV",
    );
}

#[test]
fn adv97_infinite_campus_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "infinite-campus-api-key",
        "icampustoken=ANZcW4wlbGyKxSYT\u{00AD}t7tRd9mTWo12cjlV",
        "ANZcW4wlbGyKxSYTt7tRd9mTWo12cjlV",
    );
}

#[test]
fn adv97_infinite_campus_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "infinite-campus-api-key",
        "icampustoken=ANZcW4wlbGyKxSYT\u{200C}t7tRd9mTWo12cjlV",
        "ANZcW4wlbGyKxSYTt7tRd9mTWo12cjlV",
    );
}

#[test]
fn adv97_infinite_campus_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "infinite-campus-api-key",
        "icampustoken=ANZcW4wlbGyKxSYT\u{200D}t7tRd9mTWo12cjlV",
        "ANZcW4wlbGyKxSYTt7tRd9mTWo12cjlV",
    );
}

#[test]
fn adv97_infinite_campus_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "infinite-campus-api-key",
        "icampustoken=ANZcW4wlbGyKxSYT\u{FEFF}t7tRd9mTWo12cjlV",
        "ANZcW4wlbGyKxSYTt7tRd9mTWo12cjlV",
    );
}

#[test]
fn adv97_infinite_campus_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "infinite-campus-api-key",
        "icampustoken=ANZcW4wlbGyKxSYT\u{2060}t7tRd9mTWo12cjlV",
        "ANZcW4wlbGyKxSYTt7tRd9mTWo12cjlV",
    );
}

#[test]
fn adv97_infinite_campus_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "infinite-campus-api-key",
        "icampustoken=ANZcW4wlbGyKxSYT\u{180E}t7tRd9mTWo12cjlV",
        "ANZcW4wlbGyKxSYTt7tRd9mTWo12cjlV",
    );
}

#[test]
fn adv97_infinite_campus_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "infinite-campus-api-key",
        "icampustoken=ANZcW4wlbGyKxSYT\u{202E}t7tRd9mTWo12cjlV",
        "ANZcW4wlbGyKxSYTt7tRd9mTWo12cjlV",
    );
}

#[test]
fn adv97_infinite_campus_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "infinite-campus-api-key",
        "icampustoken=ANZcW4wlbGyKxSYT\u{202C}t7tRd9mTWo12cjlV",
        "ANZcW4wlbGyKxSYTt7tRd9mTWo12cjlV",
    );
}

#[test]
fn adv97_infinite_campus_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "infinite-campus-api-key",
        "icampustoken=ANZcW4wlbGyKxSYT\u{200E}t7tRd9mTWo12cjlV",
        "ANZcW4wlbGyKxSYTt7tRd9mTWo12cjlV",
    );
}

// =========================================================================
// 5. INFLUXDB API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv97_influxdb_api_token_normal_must_fire() {
    assert_detector_fires(
        "influxdb-api-token",
        "INFLUXDB_TOKEN=6IsytRMjujrSGkTlWFg5t8XrmiF2EN-XFnmhw_1tO_pJCBwBwJ",
        "6IsytRMjujrSGkTlWFg5t8XrmiF2EN-XFnmhw_1tO_pJCBwBwJ",
    );
}

#[test]
fn adv97_influxdb_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "influxdb-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv97_influxdb_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "influxdb-api-token",
        "INFLUXDB_TOKEN=6IsytRMjujrSGkTlWFg5t8Xrm\u{200B}iF2EN-XFnmhw_1tO_pJCBwBwJ",
        "6IsytRMjujrSGkTlWFg5t8XrmiF2EN-XFnmhw_1tO_pJCBwBwJ",
    );
}

#[test]
fn adv97_influxdb_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "influxdb-api-token",
        "INFLUXDB_TOKEN=6IsytRMjujrSGkTlWFg5t8Xrm\u{00AD}iF2EN-XFnmhw_1tO_pJCBwBwJ",
        "6IsytRMjujrSGkTlWFg5t8XrmiF2EN-XFnmhw_1tO_pJCBwBwJ",
    );
}

#[test]
fn adv97_influxdb_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "influxdb-api-token",
        "INFLUXDB_TOKEN=6IsytRMjujrSGkTlWFg5t8Xrm\u{200C}iF2EN-XFnmhw_1tO_pJCBwBwJ",
        "6IsytRMjujrSGkTlWFg5t8XrmiF2EN-XFnmhw_1tO_pJCBwBwJ",
    );
}

#[test]
fn adv97_influxdb_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "influxdb-api-token",
        "INFLUXDB_TOKEN=6IsytRMjujrSGkTlWFg5t8Xrm\u{200D}iF2EN-XFnmhw_1tO_pJCBwBwJ",
        "6IsytRMjujrSGkTlWFg5t8XrmiF2EN-XFnmhw_1tO_pJCBwBwJ",
    );
}

#[test]
fn adv97_influxdb_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "influxdb-api-token",
        "INFLUXDB_TOKEN=6IsytRMjujrSGkTlWFg5t8Xrm\u{FEFF}iF2EN-XFnmhw_1tO_pJCBwBwJ",
        "6IsytRMjujrSGkTlWFg5t8XrmiF2EN-XFnmhw_1tO_pJCBwBwJ",
    );
}

#[test]
fn adv97_influxdb_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "influxdb-api-token",
        "INFLUXDB_TOKEN=6IsytRMjujrSGkTlWFg5t8Xrm\u{2060}iF2EN-XFnmhw_1tO_pJCBwBwJ",
        "6IsytRMjujrSGkTlWFg5t8XrmiF2EN-XFnmhw_1tO_pJCBwBwJ",
    );
}

#[test]
fn adv97_influxdb_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "influxdb-api-token",
        "INFLUXDB_TOKEN=6IsytRMjujrSGkTlWFg5t8Xrm\u{180E}iF2EN-XFnmhw_1tO_pJCBwBwJ",
        "6IsytRMjujrSGkTlWFg5t8XrmiF2EN-XFnmhw_1tO_pJCBwBwJ",
    );
}

#[test]
fn adv97_influxdb_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "influxdb-api-token",
        "INFLUXDB_TOKEN=6IsytRMjujrSGkTlWFg5t8Xrm\u{202E}iF2EN-XFnmhw_1tO_pJCBwBwJ",
        "6IsytRMjujrSGkTlWFg5t8XrmiF2EN-XFnmhw_1tO_pJCBwBwJ",
    );
}

#[test]
fn adv97_influxdb_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "influxdb-api-token",
        "INFLUXDB_TOKEN=6IsytRMjujrSGkTlWFg5t8Xrm\u{202C}iF2EN-XFnmhw_1tO_pJCBwBwJ",
        "6IsytRMjujrSGkTlWFg5t8XrmiF2EN-XFnmhw_1tO_pJCBwBwJ",
    );
}

#[test]
fn adv97_influxdb_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "influxdb-api-token",
        "INFLUXDB_TOKEN=6IsytRMjujrSGkTlWFg5t8Xrm\u{200E}iF2EN-XFnmhw_1tO_pJCBwBwJ",
        "6IsytRMjujrSGkTlWFg5t8XrmiF2EN-XFnmhw_1tO_pJCBwBwJ",
    );
}

// =========================================================================
// 6. INFOBIP API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv97_infobip_api_key_normal_must_fire() {
    assert_detector_fires(
        "infobip-api-key",
        "infobip=521605cd-2e1a-7f93-dc93-62773b2dba23",
        "521605cd-2e1a-7f93-dc93-62773b2dba23",
    );
}

#[test]
fn adv97_infobip_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "infobip-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv97_infobip_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "infobip-api-key",
        "infobip=521605cd-2e1a-7f93\u{200B}-dc93-62773b2dba23",
        "521605cd-2e1a-7f93-dc93-62773b2dba23",
    );
}

#[test]
fn adv97_infobip_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "infobip-api-key",
        "infobip=521605cd-2e1a-7f93\u{00AD}-dc93-62773b2dba23",
        "521605cd-2e1a-7f93-dc93-62773b2dba23",
    );
}

#[test]
fn adv97_infobip_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "infobip-api-key",
        "infobip=521605cd-2e1a-7f93\u{200C}-dc93-62773b2dba23",
        "521605cd-2e1a-7f93-dc93-62773b2dba23",
    );
}

#[test]
fn adv97_infobip_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "infobip-api-key",
        "infobip=521605cd-2e1a-7f93\u{200D}-dc93-62773b2dba23",
        "521605cd-2e1a-7f93-dc93-62773b2dba23",
    );
}

#[test]
fn adv97_infobip_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "infobip-api-key",
        "infobip=521605cd-2e1a-7f93\u{FEFF}-dc93-62773b2dba23",
        "521605cd-2e1a-7f93-dc93-62773b2dba23",
    );
}

#[test]
fn adv97_infobip_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "infobip-api-key",
        "infobip=521605cd-2e1a-7f93\u{2060}-dc93-62773b2dba23",
        "521605cd-2e1a-7f93-dc93-62773b2dba23",
    );
}

#[test]
fn adv97_infobip_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "infobip-api-key",
        "infobip=521605cd-2e1a-7f93\u{180E}-dc93-62773b2dba23",
        "521605cd-2e1a-7f93-dc93-62773b2dba23",
    );
}

#[test]
fn adv97_infobip_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "infobip-api-key",
        "infobip=521605cd-2e1a-7f93\u{202E}-dc93-62773b2dba23",
        "521605cd-2e1a-7f93-dc93-62773b2dba23",
    );
}

#[test]
fn adv97_infobip_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "infobip-api-key",
        "infobip=521605cd-2e1a-7f93\u{202C}-dc93-62773b2dba23",
        "521605cd-2e1a-7f93-dc93-62773b2dba23",
    );
}

#[test]
fn adv97_infobip_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "infobip-api-key",
        "infobip=521605cd-2e1a-7f93\u{200E}-dc93-62773b2dba23",
        "521605cd-2e1a-7f93-dc93-62773b2dba23",
    );
}

// =========================================================================
// 7. INFURA PROJECT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv97_infura_project_credentials_normal_must_fire() {
    assert_detector_fires(
        "infura-project-credentials",
        "INFURA_PROJECT_ID=60f93913abadecc09d49fb5365897002",
        "60f93913abadecc09d49fb5365897002",
    );
}

#[test]
fn adv97_infura_project_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "infura-project-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv97_infura_project_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "infura-project-credentials",
        "INFURA_PROJECT_ID=60f93913abadecc0\u{200B}9d49fb5365897002",
        "60f93913abadecc09d49fb5365897002",
    );
}

#[test]
fn adv97_infura_project_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "infura-project-credentials",
        "INFURA_PROJECT_ID=60f93913abadecc0\u{00AD}9d49fb5365897002",
        "60f93913abadecc09d49fb5365897002",
    );
}

#[test]
fn adv97_infura_project_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "infura-project-credentials",
        "INFURA_PROJECT_ID=60f93913abadecc0\u{200C}9d49fb5365897002",
        "60f93913abadecc09d49fb5365897002",
    );
}

#[test]
fn adv97_infura_project_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "infura-project-credentials",
        "INFURA_PROJECT_ID=60f93913abadecc0\u{200D}9d49fb5365897002",
        "60f93913abadecc09d49fb5365897002",
    );
}

#[test]
fn adv97_infura_project_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "infura-project-credentials",
        "INFURA_PROJECT_ID=60f93913abadecc0\u{FEFF}9d49fb5365897002",
        "60f93913abadecc09d49fb5365897002",
    );
}

#[test]
fn adv97_infura_project_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "infura-project-credentials",
        "INFURA_PROJECT_ID=60f93913abadecc0\u{2060}9d49fb5365897002",
        "60f93913abadecc09d49fb5365897002",
    );
}

#[test]
fn adv97_infura_project_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "infura-project-credentials",
        "INFURA_PROJECT_ID=60f93913abadecc0\u{180E}9d49fb5365897002",
        "60f93913abadecc09d49fb5365897002",
    );
}

#[test]
fn adv97_infura_project_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "infura-project-credentials",
        "INFURA_PROJECT_ID=60f93913abadecc0\u{202E}9d49fb5365897002",
        "60f93913abadecc09d49fb5365897002",
    );
}

#[test]
fn adv97_infura_project_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "infura-project-credentials",
        "INFURA_PROJECT_ID=60f93913abadecc0\u{202C}9d49fb5365897002",
        "60f93913abadecc09d49fb5365897002",
    );
}

#[test]
fn adv97_infura_project_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "infura-project-credentials",
        "INFURA_PROJECT_ID=60f93913abadecc0\u{200E}9d49fb5365897002",
        "60f93913abadecc09d49fb5365897002",
    );
}

// =========================================================================
// 8. INSTABUG TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv97_instabug_token_normal_must_fire() {
    assert_detector_fires(
        "instabug-token",
        "Instabug.Builder()=2D 5?rm):=eZdV!^^_l>.Em ! 5lCpF`l ,'UWQDxjwuh_kS1VU34hlJRd_QIzCvD\\",
        "UWQDxjwuh_kS1VU34hlJRd_QIzCvD",
    );
}

#[test]
fn adv97_instabug_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "instabug-token",
        "dummy_prefix_0 =2D 5?rm):=eZdV!^^_l>.Em ! 5lCpF`l ,'xxxxxxxxxxxxxxxxxxxxxxxxxxxxx\\",
    );
}

#[test]
fn adv97_instabug_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "instabug-token",
        "Instabug.Builder()=2D 5?rm):=eZdV!^^_l>.Em ! 5lCpF`l ,'UWQDxjwuh_kS1V\u{200B}U34hlJRd_QIzCvD\\",
        "UWQDxjwuh_kS1VU34hlJRd_QIzCvD",
    );
}

#[test]
fn adv97_instabug_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "instabug-token",
        "Instabug.Builder()=2D 5?rm):=eZdV!^^_l>.Em ! 5lCpF`l ,'UWQDxjwuh_kS1V\u{00AD}U34hlJRd_QIzCvD\\",
        "UWQDxjwuh_kS1VU34hlJRd_QIzCvD",
    );
}

#[test]
fn adv97_instabug_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "instabug-token",
        "Instabug.Builder()=2D 5?rm):=eZdV!^^_l>.Em ! 5lCpF`l ,'UWQDxjwuh_kS1V\u{200C}U34hlJRd_QIzCvD\\",
        "UWQDxjwuh_kS1VU34hlJRd_QIzCvD",
    );
}

#[test]
fn adv97_instabug_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "instabug-token",
        "Instabug.Builder()=2D 5?rm):=eZdV!^^_l>.Em ! 5lCpF`l ,'UWQDxjwuh_kS1V\u{200D}U34hlJRd_QIzCvD\\",
        "UWQDxjwuh_kS1VU34hlJRd_QIzCvD",
    );
}

#[test]
fn adv97_instabug_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "instabug-token",
        "Instabug.Builder()=2D 5?rm):=eZdV!^^_l>.Em ! 5lCpF`l ,'UWQDxjwuh_kS1V\u{FEFF}U34hlJRd_QIzCvD\\",
        "UWQDxjwuh_kS1VU34hlJRd_QIzCvD",
    );
}

#[test]
fn adv97_instabug_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "instabug-token",
        "Instabug.Builder()=2D 5?rm):=eZdV!^^_l>.Em ! 5lCpF`l ,'UWQDxjwuh_kS1V\u{2060}U34hlJRd_QIzCvD\\",
        "UWQDxjwuh_kS1VU34hlJRd_QIzCvD",
    );
}

#[test]
fn adv97_instabug_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "instabug-token",
        "Instabug.Builder()=2D 5?rm):=eZdV!^^_l>.Em ! 5lCpF`l ,'UWQDxjwuh_kS1V\u{180E}U34hlJRd_QIzCvD\\",
        "UWQDxjwuh_kS1VU34hlJRd_QIzCvD",
    );
}

#[test]
fn adv97_instabug_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "instabug-token",
        "Instabug.Builder()=2D 5?rm):=eZdV!^^_l>.Em ! 5lCpF`l ,'UWQDxjwuh_kS1V\u{202E}U34hlJRd_QIzCvD\\",
        "UWQDxjwuh_kS1VU34hlJRd_QIzCvD",
    );
}

#[test]
fn adv97_instabug_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "instabug-token",
        "Instabug.Builder()=2D 5?rm):=eZdV!^^_l>.Em ! 5lCpF`l ,'UWQDxjwuh_kS1V\u{202C}U34hlJRd_QIzCvD\\",
        "UWQDxjwuh_kS1VU34hlJRd_QIzCvD",
    );
}

#[test]
fn adv97_instabug_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "instabug-token",
        "Instabug.Builder()=2D 5?rm):=eZdV!^^_l>.Em ! 5lCpF`l ,'UWQDxjwuh_kS1V\u{200E}U34hlJRd_QIzCvD\\",
        "UWQDxjwuh_kS1VU34hlJRd_QIzCvD",
    );
}

// =========================================================================
// 9. INTEGROMAT WEBHOOK CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv97_integromat_webhook_credentials_normal_must_fire() {
    assert_detector_fires(
        "integromat-webhook-credentials",
        "https://hook.make.com/Qf0zdjh24ijmAisscM87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
        "https://hook.make.com/Qf0zdjh24ijmAisscM87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
    );
}

#[test]
fn adv97_integromat_webhook_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "integromat-webhook-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv97_integromat_webhook_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "integromat-webhook-credentials",
        "https://hook.make.com/Qf0zdjh24ijmAisscM\u{200B}87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
        "https://hook.make.com/Qf0zdjh24ijmAisscM87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
    );
}

#[test]
fn adv97_integromat_webhook_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "integromat-webhook-credentials",
        "https://hook.make.com/Qf0zdjh24ijmAisscM\u{00AD}87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
        "https://hook.make.com/Qf0zdjh24ijmAisscM87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
    );
}

#[test]
fn adv97_integromat_webhook_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "integromat-webhook-credentials",
        "https://hook.make.com/Qf0zdjh24ijmAisscM\u{200C}87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
        "https://hook.make.com/Qf0zdjh24ijmAisscM87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
    );
}

#[test]
fn adv97_integromat_webhook_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "integromat-webhook-credentials",
        "https://hook.make.com/Qf0zdjh24ijmAisscM\u{200D}87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
        "https://hook.make.com/Qf0zdjh24ijmAisscM87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
    );
}

#[test]
fn adv97_integromat_webhook_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "integromat-webhook-credentials",
        "https://hook.make.com/Qf0zdjh24ijmAisscM\u{FEFF}87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
        "https://hook.make.com/Qf0zdjh24ijmAisscM87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
    );
}

#[test]
fn adv97_integromat_webhook_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "integromat-webhook-credentials",
        "https://hook.make.com/Qf0zdjh24ijmAisscM\u{2060}87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
        "https://hook.make.com/Qf0zdjh24ijmAisscM87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
    );
}

#[test]
fn adv97_integromat_webhook_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "integromat-webhook-credentials",
        "https://hook.make.com/Qf0zdjh24ijmAisscM\u{180E}87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
        "https://hook.make.com/Qf0zdjh24ijmAisscM87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
    );
}

#[test]
fn adv97_integromat_webhook_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "integromat-webhook-credentials",
        "https://hook.make.com/Qf0zdjh24ijmAisscM\u{202E}87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
        "https://hook.make.com/Qf0zdjh24ijmAisscM87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
    );
}

#[test]
fn adv97_integromat_webhook_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "integromat-webhook-credentials",
        "https://hook.make.com/Qf0zdjh24ijmAisscM\u{202C}87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
        "https://hook.make.com/Qf0zdjh24ijmAisscM87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
    );
}

#[test]
fn adv97_integromat_webhook_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "integromat-webhook-credentials",
        "https://hook.make.com/Qf0zdjh24ijmAisscM\u{200E}87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
        "https://hook.make.com/Qf0zdjh24ijmAisscM87yqLBR61oGXwXY2BvfnOfb66JyaER9qY7kVJg06d",
    );
}

// =========================================================================
// 10. INTELOWL API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv97_intelowl_api_key_normal_must_fire() {
    assert_detector_fires(
        "intelowl-api-key",
        "intelowlkey=3hjArTco0NPvH-0aKSYr",
        "3hjArTco0NPvH-0aKSYr",
    );
}

#[test]
fn adv97_intelowl_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("intelowl-api-key", "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv97_intelowl_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "intelowl-api-key",
        "intelowlkey=3hjArTco0N\u{200B}PvH-0aKSYr",
        "3hjArTco0NPvH-0aKSYr",
    );
}

#[test]
fn adv97_intelowl_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "intelowl-api-key",
        "intelowlkey=3hjArTco0N\u{00AD}PvH-0aKSYr",
        "3hjArTco0NPvH-0aKSYr",
    );
}

#[test]
fn adv97_intelowl_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "intelowl-api-key",
        "intelowlkey=3hjArTco0N\u{200C}PvH-0aKSYr",
        "3hjArTco0NPvH-0aKSYr",
    );
}

#[test]
fn adv97_intelowl_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "intelowl-api-key",
        "intelowlkey=3hjArTco0N\u{200D}PvH-0aKSYr",
        "3hjArTco0NPvH-0aKSYr",
    );
}

#[test]
fn adv97_intelowl_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "intelowl-api-key",
        "intelowlkey=3hjArTco0N\u{FEFF}PvH-0aKSYr",
        "3hjArTco0NPvH-0aKSYr",
    );
}

#[test]
fn adv97_intelowl_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "intelowl-api-key",
        "intelowlkey=3hjArTco0N\u{2060}PvH-0aKSYr",
        "3hjArTco0NPvH-0aKSYr",
    );
}

#[test]
fn adv97_intelowl_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "intelowl-api-key",
        "intelowlkey=3hjArTco0N\u{180E}PvH-0aKSYr",
        "3hjArTco0NPvH-0aKSYr",
    );
}

#[test]
fn adv97_intelowl_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "intelowl-api-key",
        "intelowlkey=3hjArTco0N\u{202E}PvH-0aKSYr",
        "3hjArTco0NPvH-0aKSYr",
    );
}

#[test]
fn adv97_intelowl_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "intelowl-api-key",
        "intelowlkey=3hjArTco0N\u{202C}PvH-0aKSYr",
        "3hjArTco0NPvH-0aKSYr",
    );
}

#[test]
fn adv97_intelowl_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "intelowl-api-key",
        "intelowlkey=3hjArTco0N\u{200E}PvH-0aKSYr",
        "3hjArTco0NPvH-0aKSYr",
    );
}
