//! Part 135 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates tripadvisor, truelayer, tumblr, turso, twilio, twitter, twocheckout, ubidots, uk, umami detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. TRIPADVISOR API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv135_tripadvisor_api_key_normal_must_fire() {
    assert_detector_fires(
        "tripadvisor-api-key",
        "trip_advisor=aedf902ad3666643f5392685a7ca4a50",
        "aedf902ad3666643f5392685a7ca4a50",
    );
}

#[test]
fn adv135_tripadvisor_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "tripadvisor-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv135_tripadvisor_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "tripadvisor-api-key",
        "trip_advisor=aedf902ad3666643\u{200B}f5392685a7ca4a50",
        "aedf902ad3666643f5392685a7ca4a50",
    );
}

#[test]
fn adv135_tripadvisor_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "tripadvisor-api-key",
        "trip_advisor=aedf902ad3666643\u{00AD}f5392685a7ca4a50",
        "aedf902ad3666643f5392685a7ca4a50",
    );
}

#[test]
fn adv135_tripadvisor_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "tripadvisor-api-key",
        "trip_advisor=aedf902ad3666643\u{200C}f5392685a7ca4a50",
        "aedf902ad3666643f5392685a7ca4a50",
    );
}

#[test]
fn adv135_tripadvisor_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "tripadvisor-api-key",
        "trip_advisor=aedf902ad3666643\u{200D}f5392685a7ca4a50",
        "aedf902ad3666643f5392685a7ca4a50",
    );
}

#[test]
fn adv135_tripadvisor_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "tripadvisor-api-key",
        "trip_advisor=aedf902ad3666643\u{FEFF}f5392685a7ca4a50",
        "aedf902ad3666643f5392685a7ca4a50",
    );
}

#[test]
fn adv135_tripadvisor_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "tripadvisor-api-key",
        "trip_advisor=aedf902ad3666643\u{2060}f5392685a7ca4a50",
        "aedf902ad3666643f5392685a7ca4a50",
    );
}

#[test]
fn adv135_tripadvisor_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "tripadvisor-api-key",
        "trip_advisor=aedf902ad3666643\u{180E}f5392685a7ca4a50",
        "aedf902ad3666643f5392685a7ca4a50",
    );
}

#[test]
fn adv135_tripadvisor_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "tripadvisor-api-key",
        "trip_advisor=aedf902ad3666643\u{202E}f5392685a7ca4a50",
        "aedf902ad3666643f5392685a7ca4a50",
    );
}

#[test]
fn adv135_tripadvisor_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "tripadvisor-api-key",
        "trip_advisor=aedf902ad3666643\u{202C}f5392685a7ca4a50",
        "aedf902ad3666643f5392685a7ca4a50",
    );
}

#[test]
fn adv135_tripadvisor_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "tripadvisor-api-key",
        "trip_advisor=aedf902ad3666643\u{200E}f5392685a7ca4a50",
        "aedf902ad3666643f5392685a7ca4a50",
    );
}

// =========================================================================
// 2. TRUELAYER API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv135_truelayer_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "truelayer-api-credentials",
        "TRUELAYERID=gxay7pfmbpynabqmuwle",
        "gxay7pfmbpynabqmuwle",
    );
}

#[test]
fn adv135_truelayer_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "truelayer-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv135_truelayer_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "truelayer-api-credentials",
        "TRUELAYERID=gxay7pfmbp\u{200B}ynabqmuwle",
        "gxay7pfmbpynabqmuwle",
    );
}

#[test]
fn adv135_truelayer_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "truelayer-api-credentials",
        "TRUELAYERID=gxay7pfmbp\u{00AD}ynabqmuwle",
        "gxay7pfmbpynabqmuwle",
    );
}

#[test]
fn adv135_truelayer_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "truelayer-api-credentials",
        "TRUELAYERID=gxay7pfmbp\u{200C}ynabqmuwle",
        "gxay7pfmbpynabqmuwle",
    );
}

#[test]
fn adv135_truelayer_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "truelayer-api-credentials",
        "TRUELAYERID=gxay7pfmbp\u{200D}ynabqmuwle",
        "gxay7pfmbpynabqmuwle",
    );
}

#[test]
fn adv135_truelayer_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "truelayer-api-credentials",
        "TRUELAYERID=gxay7pfmbp\u{FEFF}ynabqmuwle",
        "gxay7pfmbpynabqmuwle",
    );
}

#[test]
fn adv135_truelayer_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "truelayer-api-credentials",
        "TRUELAYERID=gxay7pfmbp\u{2060}ynabqmuwle",
        "gxay7pfmbpynabqmuwle",
    );
}

#[test]
fn adv135_truelayer_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "truelayer-api-credentials",
        "TRUELAYERID=gxay7pfmbp\u{180E}ynabqmuwle",
        "gxay7pfmbpynabqmuwle",
    );
}

#[test]
fn adv135_truelayer_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "truelayer-api-credentials",
        "TRUELAYERID=gxay7pfmbp\u{202E}ynabqmuwle",
        "gxay7pfmbpynabqmuwle",
    );
}

#[test]
fn adv135_truelayer_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "truelayer-api-credentials",
        "TRUELAYERID=gxay7pfmbp\u{202C}ynabqmuwle",
        "gxay7pfmbpynabqmuwle",
    );
}

#[test]
fn adv135_truelayer_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "truelayer-api-credentials",
        "TRUELAYERID=gxay7pfmbp\u{200E}ynabqmuwle",
        "gxay7pfmbpynabqmuwle",
    );
}

// =========================================================================
// 3. TUMBLR API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv135_tumblr_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "tumblr-api-credentials",
        "tumblr=0L7COzZC7L1Us4KFuA38IgMTNhea3Dgy8xyvfRc36MMFQif73h",
        "0L7COzZC7L1Us4KFuA38IgMTNhea3Dgy8xyvfRc36MMFQif73h",
    );
}

#[test]
fn adv135_tumblr_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "tumblr-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv135_tumblr_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "tumblr-api-credentials",
        "tumblr=0L7COzZC7L1Us4KFuA38IgMTN\u{200B}hea3Dgy8xyvfRc36MMFQif73h",
        "0L7COzZC7L1Us4KFuA38IgMTNhea3Dgy8xyvfRc36MMFQif73h",
    );
}

#[test]
fn adv135_tumblr_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "tumblr-api-credentials",
        "tumblr=0L7COzZC7L1Us4KFuA38IgMTN\u{00AD}hea3Dgy8xyvfRc36MMFQif73h",
        "0L7COzZC7L1Us4KFuA38IgMTNhea3Dgy8xyvfRc36MMFQif73h",
    );
}

#[test]
fn adv135_tumblr_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "tumblr-api-credentials",
        "tumblr=0L7COzZC7L1Us4KFuA38IgMTN\u{200C}hea3Dgy8xyvfRc36MMFQif73h",
        "0L7COzZC7L1Us4KFuA38IgMTNhea3Dgy8xyvfRc36MMFQif73h",
    );
}

#[test]
fn adv135_tumblr_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "tumblr-api-credentials",
        "tumblr=0L7COzZC7L1Us4KFuA38IgMTN\u{200D}hea3Dgy8xyvfRc36MMFQif73h",
        "0L7COzZC7L1Us4KFuA38IgMTNhea3Dgy8xyvfRc36MMFQif73h",
    );
}

#[test]
fn adv135_tumblr_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "tumblr-api-credentials",
        "tumblr=0L7COzZC7L1Us4KFuA38IgMTN\u{FEFF}hea3Dgy8xyvfRc36MMFQif73h",
        "0L7COzZC7L1Us4KFuA38IgMTNhea3Dgy8xyvfRc36MMFQif73h",
    );
}

#[test]
fn adv135_tumblr_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "tumblr-api-credentials",
        "tumblr=0L7COzZC7L1Us4KFuA38IgMTN\u{2060}hea3Dgy8xyvfRc36MMFQif73h",
        "0L7COzZC7L1Us4KFuA38IgMTNhea3Dgy8xyvfRc36MMFQif73h",
    );
}

#[test]
fn adv135_tumblr_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "tumblr-api-credentials",
        "tumblr=0L7COzZC7L1Us4KFuA38IgMTN\u{180E}hea3Dgy8xyvfRc36MMFQif73h",
        "0L7COzZC7L1Us4KFuA38IgMTNhea3Dgy8xyvfRc36MMFQif73h",
    );
}

#[test]
fn adv135_tumblr_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "tumblr-api-credentials",
        "tumblr=0L7COzZC7L1Us4KFuA38IgMTN\u{202E}hea3Dgy8xyvfRc36MMFQif73h",
        "0L7COzZC7L1Us4KFuA38IgMTNhea3Dgy8xyvfRc36MMFQif73h",
    );
}

#[test]
fn adv135_tumblr_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "tumblr-api-credentials",
        "tumblr=0L7COzZC7L1Us4KFuA38IgMTN\u{202C}hea3Dgy8xyvfRc36MMFQif73h",
        "0L7COzZC7L1Us4KFuA38IgMTNhea3Dgy8xyvfRc36MMFQif73h",
    );
}

#[test]
fn adv135_tumblr_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "tumblr-api-credentials",
        "tumblr=0L7COzZC7L1Us4KFuA38IgMTN\u{200E}hea3Dgy8xyvfRc36MMFQif73h",
        "0L7COzZC7L1Us4KFuA38IgMTNhea3Dgy8xyvfRc36MMFQif73h",
    );
}

// =========================================================================
// 4. TURSO EMBEDDED REPLICA TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv135_turso_embedded_replica_token_normal_must_fire() {
    assert_detector_fires(
        "turso-embedded-replica-token",
        "libsql://rYtzWWtuGM68sLiqBQ0.turso.io",
        "libsql://rYtzWWtuGM68sLiqBQ0.turso.io",
    );
}

#[test]
fn adv135_turso_embedded_replica_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "turso-embedded-replica-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv135_turso_embedded_replica_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "turso-embedded-replica-token",
        "libsql://rYtzWWtuG\u{200B}M68sLiqBQ0.turso.io",
        "libsql://rYtzWWtuGM68sLiqBQ0.turso.io",
    );
}

#[test]
fn adv135_turso_embedded_replica_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "turso-embedded-replica-token",
        "libsql://rYtzWWtuG\u{00AD}M68sLiqBQ0.turso.io",
        "libsql://rYtzWWtuGM68sLiqBQ0.turso.io",
    );
}

#[test]
fn adv135_turso_embedded_replica_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "turso-embedded-replica-token",
        "libsql://rYtzWWtuG\u{200C}M68sLiqBQ0.turso.io",
        "libsql://rYtzWWtuGM68sLiqBQ0.turso.io",
    );
}

#[test]
fn adv135_turso_embedded_replica_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "turso-embedded-replica-token",
        "libsql://rYtzWWtuG\u{200D}M68sLiqBQ0.turso.io",
        "libsql://rYtzWWtuGM68sLiqBQ0.turso.io",
    );
}

#[test]
fn adv135_turso_embedded_replica_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "turso-embedded-replica-token",
        "libsql://rYtzWWtuG\u{FEFF}M68sLiqBQ0.turso.io",
        "libsql://rYtzWWtuGM68sLiqBQ0.turso.io",
    );
}

#[test]
fn adv135_turso_embedded_replica_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "turso-embedded-replica-token",
        "libsql://rYtzWWtuG\u{2060}M68sLiqBQ0.turso.io",
        "libsql://rYtzWWtuGM68sLiqBQ0.turso.io",
    );
}

#[test]
fn adv135_turso_embedded_replica_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "turso-embedded-replica-token",
        "libsql://rYtzWWtuG\u{180E}M68sLiqBQ0.turso.io",
        "libsql://rYtzWWtuGM68sLiqBQ0.turso.io",
    );
}

#[test]
fn adv135_turso_embedded_replica_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "turso-embedded-replica-token",
        "libsql://rYtzWWtuG\u{202E}M68sLiqBQ0.turso.io",
        "libsql://rYtzWWtuGM68sLiqBQ0.turso.io",
    );
}

#[test]
fn adv135_turso_embedded_replica_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "turso-embedded-replica-token",
        "libsql://rYtzWWtuG\u{202C}M68sLiqBQ0.turso.io",
        "libsql://rYtzWWtuGM68sLiqBQ0.turso.io",
    );
}

#[test]
fn adv135_turso_embedded_replica_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "turso-embedded-replica-token",
        "libsql://rYtzWWtuG\u{200E}M68sLiqBQ0.turso.io",
        "libsql://rYtzWWtuGM68sLiqBQ0.turso.io",
    );
}

// =========================================================================
// 5. TWILIO WEBHOOK SIGNING SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv135_twilio_webhook_signing_secret_normal_must_fire() {
    assert_detector_fires(
        "twilio-webhook-signing-secret",
        "TWILIOWEBHOOKSECRET=jNPa3Lq7yWAB8ndrOTvoBdKxB15BMcUX",
        "jNPa3Lq7yWAB8ndrOTvoBdKxB15BMcUX",
    );
}

#[test]
fn adv135_twilio_webhook_signing_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "twilio-webhook-signing-secret",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv135_twilio_webhook_signing_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "twilio-webhook-signing-secret",
        "TWILIOWEBHOOKSECRET=jNPa3Lq7yWAB8ndr\u{200B}OTvoBdKxB15BMcUX",
        "jNPa3Lq7yWAB8ndrOTvoBdKxB15BMcUX",
    );
}

#[test]
fn adv135_twilio_webhook_signing_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "twilio-webhook-signing-secret",
        "TWILIOWEBHOOKSECRET=jNPa3Lq7yWAB8ndr\u{00AD}OTvoBdKxB15BMcUX",
        "jNPa3Lq7yWAB8ndrOTvoBdKxB15BMcUX",
    );
}

#[test]
fn adv135_twilio_webhook_signing_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "twilio-webhook-signing-secret",
        "TWILIOWEBHOOKSECRET=jNPa3Lq7yWAB8ndr\u{200C}OTvoBdKxB15BMcUX",
        "jNPa3Lq7yWAB8ndrOTvoBdKxB15BMcUX",
    );
}

#[test]
fn adv135_twilio_webhook_signing_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "twilio-webhook-signing-secret",
        "TWILIOWEBHOOKSECRET=jNPa3Lq7yWAB8ndr\u{200D}OTvoBdKxB15BMcUX",
        "jNPa3Lq7yWAB8ndrOTvoBdKxB15BMcUX",
    );
}

#[test]
fn adv135_twilio_webhook_signing_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "twilio-webhook-signing-secret",
        "TWILIOWEBHOOKSECRET=jNPa3Lq7yWAB8ndr\u{FEFF}OTvoBdKxB15BMcUX",
        "jNPa3Lq7yWAB8ndrOTvoBdKxB15BMcUX",
    );
}

#[test]
fn adv135_twilio_webhook_signing_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "twilio-webhook-signing-secret",
        "TWILIOWEBHOOKSECRET=jNPa3Lq7yWAB8ndr\u{2060}OTvoBdKxB15BMcUX",
        "jNPa3Lq7yWAB8ndrOTvoBdKxB15BMcUX",
    );
}

#[test]
fn adv135_twilio_webhook_signing_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "twilio-webhook-signing-secret",
        "TWILIOWEBHOOKSECRET=jNPa3Lq7yWAB8ndr\u{180E}OTvoBdKxB15BMcUX",
        "jNPa3Lq7yWAB8ndrOTvoBdKxB15BMcUX",
    );
}

#[test]
fn adv135_twilio_webhook_signing_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "twilio-webhook-signing-secret",
        "TWILIOWEBHOOKSECRET=jNPa3Lq7yWAB8ndr\u{202E}OTvoBdKxB15BMcUX",
        "jNPa3Lq7yWAB8ndrOTvoBdKxB15BMcUX",
    );
}

#[test]
fn adv135_twilio_webhook_signing_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "twilio-webhook-signing-secret",
        "TWILIOWEBHOOKSECRET=jNPa3Lq7yWAB8ndr\u{202C}OTvoBdKxB15BMcUX",
        "jNPa3Lq7yWAB8ndrOTvoBdKxB15BMcUX",
    );
}

#[test]
fn adv135_twilio_webhook_signing_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "twilio-webhook-signing-secret",
        "TWILIOWEBHOOKSECRET=jNPa3Lq7yWAB8ndr\u{200E}OTvoBdKxB15BMcUX",
        "jNPa3Lq7yWAB8ndrOTvoBdKxB15BMcUX",
    );
}

// =========================================================================
// 6. TWITTER OAUTH SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv135_twitter_oauth_secret_normal_must_fire() {
    assert_detector_fires(
        "twitter-oauth-secret",
        "TWITTERCLIENTSECRET=iJ18RC-6VioWCQC0Rs-MVNh9V6Ze8zKO",
        "iJ18RC-6VioWCQC0Rs-MVNh9V6Ze8zKO",
    );
}

#[test]
fn adv135_twitter_oauth_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "twitter-oauth-secret",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv135_twitter_oauth_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "twitter-oauth-secret",
        "TWITTERCLIENTSECRET=iJ18RC-6VioWCQC0\u{200B}Rs-MVNh9V6Ze8zKO",
        "iJ18RC-6VioWCQC0Rs-MVNh9V6Ze8zKO",
    );
}

#[test]
fn adv135_twitter_oauth_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "twitter-oauth-secret",
        "TWITTERCLIENTSECRET=iJ18RC-6VioWCQC0\u{00AD}Rs-MVNh9V6Ze8zKO",
        "iJ18RC-6VioWCQC0Rs-MVNh9V6Ze8zKO",
    );
}

#[test]
fn adv135_twitter_oauth_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "twitter-oauth-secret",
        "TWITTERCLIENTSECRET=iJ18RC-6VioWCQC0\u{200C}Rs-MVNh9V6Ze8zKO",
        "iJ18RC-6VioWCQC0Rs-MVNh9V6Ze8zKO",
    );
}

#[test]
fn adv135_twitter_oauth_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "twitter-oauth-secret",
        "TWITTERCLIENTSECRET=iJ18RC-6VioWCQC0\u{200D}Rs-MVNh9V6Ze8zKO",
        "iJ18RC-6VioWCQC0Rs-MVNh9V6Ze8zKO",
    );
}

#[test]
fn adv135_twitter_oauth_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "twitter-oauth-secret",
        "TWITTERCLIENTSECRET=iJ18RC-6VioWCQC0\u{FEFF}Rs-MVNh9V6Ze8zKO",
        "iJ18RC-6VioWCQC0Rs-MVNh9V6Ze8zKO",
    );
}

#[test]
fn adv135_twitter_oauth_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "twitter-oauth-secret",
        "TWITTERCLIENTSECRET=iJ18RC-6VioWCQC0\u{2060}Rs-MVNh9V6Ze8zKO",
        "iJ18RC-6VioWCQC0Rs-MVNh9V6Ze8zKO",
    );
}

#[test]
fn adv135_twitter_oauth_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "twitter-oauth-secret",
        "TWITTERCLIENTSECRET=iJ18RC-6VioWCQC0\u{180E}Rs-MVNh9V6Ze8zKO",
        "iJ18RC-6VioWCQC0Rs-MVNh9V6Ze8zKO",
    );
}

#[test]
fn adv135_twitter_oauth_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "twitter-oauth-secret",
        "TWITTERCLIENTSECRET=iJ18RC-6VioWCQC0\u{202E}Rs-MVNh9V6Ze8zKO",
        "iJ18RC-6VioWCQC0Rs-MVNh9V6Ze8zKO",
    );
}

#[test]
fn adv135_twitter_oauth_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "twitter-oauth-secret",
        "TWITTERCLIENTSECRET=iJ18RC-6VioWCQC0\u{202C}Rs-MVNh9V6Ze8zKO",
        "iJ18RC-6VioWCQC0Rs-MVNh9V6Ze8zKO",
    );
}

#[test]
fn adv135_twitter_oauth_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "twitter-oauth-secret",
        "TWITTERCLIENTSECRET=iJ18RC-6VioWCQC0\u{200E}Rs-MVNh9V6Ze8zKO",
        "iJ18RC-6VioWCQC0Rs-MVNh9V6Ze8zKO",
    );
}

// =========================================================================
// 7. TWOCHECKOUT API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv135_twocheckout_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "twocheckout-api-credentials",
        "twocheckoutmerchant='=:   '366424303731",
        "366424303731",
    );
}

#[test]
fn adv135_twocheckout_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "twocheckout-api-credentials",
        "dummy_prefix_0 ='=:   'xxxxxxxxxxxx",
    );
}

#[test]
fn adv135_twocheckout_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "twocheckout-api-credentials",
        "twocheckoutmerchant='=:   '366424\u{200B}303731",
        "366424303731",
    );
}

#[test]
fn adv135_twocheckout_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "twocheckout-api-credentials",
        "twocheckoutmerchant='=:   '366424\u{00AD}303731",
        "366424303731",
    );
}

#[test]
fn adv135_twocheckout_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "twocheckout-api-credentials",
        "twocheckoutmerchant='=:   '366424\u{200C}303731",
        "366424303731",
    );
}

#[test]
fn adv135_twocheckout_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "twocheckout-api-credentials",
        "twocheckoutmerchant='=:   '366424\u{200D}303731",
        "366424303731",
    );
}

#[test]
fn adv135_twocheckout_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "twocheckout-api-credentials",
        "twocheckoutmerchant='=:   '366424\u{FEFF}303731",
        "366424303731",
    );
}

#[test]
fn adv135_twocheckout_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "twocheckout-api-credentials",
        "twocheckoutmerchant='=:   '366424\u{2060}303731",
        "366424303731",
    );
}

#[test]
fn adv135_twocheckout_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "twocheckout-api-credentials",
        "twocheckoutmerchant='=:   '366424\u{180E}303731",
        "366424303731",
    );
}

#[test]
fn adv135_twocheckout_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "twocheckout-api-credentials",
        "twocheckoutmerchant='=:   '366424\u{202E}303731",
        "366424303731",
    );
}

#[test]
fn adv135_twocheckout_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "twocheckout-api-credentials",
        "twocheckoutmerchant='=:   '366424\u{202C}303731",
        "366424303731",
    );
}

#[test]
fn adv135_twocheckout_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "twocheckout-api-credentials",
        "twocheckoutmerchant='=:   '366424\u{200E}303731",
        "366424303731",
    );
}

// =========================================================================
// 8. UBIDOTS API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv135_ubidots_api_token_normal_must_fire() {
    assert_detector_fires(
        "ubidots-api-token",
        "BBFF-XQ8OBlzu2R0HzEBkpYHfJouztyi1Yx41cHgw5Tvm",
        "BBFF-XQ8OBlzu2R0HzEBkpYHfJouztyi1Yx41cHgw5Tvm",
    );
}

#[test]
fn adv135_ubidots_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ubidots-api-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv135_ubidots_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ubidots-api-token",
        "BBFF-XQ8OBlzu2R0HzEBkp\u{200B}YHfJouztyi1Yx41cHgw5Tvm",
        "BBFF-XQ8OBlzu2R0HzEBkpYHfJouztyi1Yx41cHgw5Tvm",
    );
}

#[test]
fn adv135_ubidots_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ubidots-api-token",
        "BBFF-XQ8OBlzu2R0HzEBkp\u{00AD}YHfJouztyi1Yx41cHgw5Tvm",
        "BBFF-XQ8OBlzu2R0HzEBkpYHfJouztyi1Yx41cHgw5Tvm",
    );
}

#[test]
fn adv135_ubidots_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "ubidots-api-token",
        "BBFF-XQ8OBlzu2R0HzEBkp\u{200C}YHfJouztyi1Yx41cHgw5Tvm",
        "BBFF-XQ8OBlzu2R0HzEBkpYHfJouztyi1Yx41cHgw5Tvm",
    );
}

#[test]
fn adv135_ubidots_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "ubidots-api-token",
        "BBFF-XQ8OBlzu2R0HzEBkp\u{200D}YHfJouztyi1Yx41cHgw5Tvm",
        "BBFF-XQ8OBlzu2R0HzEBkpYHfJouztyi1Yx41cHgw5Tvm",
    );
}

#[test]
fn adv135_ubidots_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "ubidots-api-token",
        "BBFF-XQ8OBlzu2R0HzEBkp\u{FEFF}YHfJouztyi1Yx41cHgw5Tvm",
        "BBFF-XQ8OBlzu2R0HzEBkpYHfJouztyi1Yx41cHgw5Tvm",
    );
}

#[test]
fn adv135_ubidots_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "ubidots-api-token",
        "BBFF-XQ8OBlzu2R0HzEBkp\u{2060}YHfJouztyi1Yx41cHgw5Tvm",
        "BBFF-XQ8OBlzu2R0HzEBkpYHfJouztyi1Yx41cHgw5Tvm",
    );
}

#[test]
fn adv135_ubidots_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "ubidots-api-token",
        "BBFF-XQ8OBlzu2R0HzEBkp\u{180E}YHfJouztyi1Yx41cHgw5Tvm",
        "BBFF-XQ8OBlzu2R0HzEBkpYHfJouztyi1Yx41cHgw5Tvm",
    );
}

#[test]
fn adv135_ubidots_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "ubidots-api-token",
        "BBFF-XQ8OBlzu2R0HzEBkp\u{202E}YHfJouztyi1Yx41cHgw5Tvm",
        "BBFF-XQ8OBlzu2R0HzEBkpYHfJouztyi1Yx41cHgw5Tvm",
    );
}

#[test]
fn adv135_ubidots_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "ubidots-api-token",
        "BBFF-XQ8OBlzu2R0HzEBkp\u{202C}YHfJouztyi1Yx41cHgw5Tvm",
        "BBFF-XQ8OBlzu2R0HzEBkpYHfJouztyi1Yx41cHgw5Tvm",
    );
}

#[test]
fn adv135_ubidots_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "ubidots-api-token",
        "BBFF-XQ8OBlzu2R0HzEBkp\u{200E}YHfJouztyi1Yx41cHgw5Tvm",
        "BBFF-XQ8OBlzu2R0HzEBkpYHfJouztyi1Yx41cHgw5Tvm",
    );
}

// =========================================================================
// 9. UK GOV NOTIFY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv135_uk_gov_notify_api_key_normal_must_fire() {
    assert_detector_fires(
        "uk-gov-notify-api-key",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0ujQHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0ujQHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
    );
}

#[test]
fn adv135_uk_gov_notify_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "uk-gov-notify-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv135_uk_gov_notify_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "uk-gov-notify-api-key",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0uj\u{200B}QHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0ujQHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
    );
}

#[test]
fn adv135_uk_gov_notify_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "uk-gov-notify-api-key",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0uj\u{00AD}QHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0ujQHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
    );
}

#[test]
fn adv135_uk_gov_notify_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "uk-gov-notify-api-key",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0uj\u{200C}QHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0ujQHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
    );
}

#[test]
fn adv135_uk_gov_notify_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "uk-gov-notify-api-key",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0uj\u{200D}QHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0ujQHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
    );
}

#[test]
fn adv135_uk_gov_notify_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "uk-gov-notify-api-key",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0uj\u{FEFF}QHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0ujQHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
    );
}

#[test]
fn adv135_uk_gov_notify_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "uk-gov-notify-api-key",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0uj\u{2060}QHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0ujQHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
    );
}

#[test]
fn adv135_uk_gov_notify_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "uk-gov-notify-api-key",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0uj\u{180E}QHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0ujQHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
    );
}

#[test]
fn adv135_uk_gov_notify_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "uk-gov-notify-api-key",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0uj\u{202E}QHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0ujQHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
    );
}

#[test]
fn adv135_uk_gov_notify_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "uk-gov-notify-api-key",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0uj\u{202C}QHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0ujQHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
    );
}

#[test]
fn adv135_uk_gov_notify_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "uk-gov-notify-api-key",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0uj\u{200E}QHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
        "govuk-notifycvj5q0z_sqygTVcSMHZ-AGEWPRIIbtAxcECtinRP-19f80e1f-0cc6-1d86-1a58-b15f0bcac555-1U0ujQHOU0ZrRq2lGlZtsOIEHykwtcTBlzNCxdAtsCp729RVcIRCxhhj9xRglS7DIHbAR3gKUf7Oevf_Um_zBi9zvV8ovXo_YVqj",
    );
}

// =========================================================================
// 10. UMAMI API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv135_umami_api_key_normal_must_fire() {
    assert_detector_fires(
        "umami-api-key",
        "UMAMI_API_KEY=6ea17ead-9d16-752e-bc57-4e4ac8609e13",
        "6ea17ead-9d16-752e-bc57-4e4ac8609e13",
    );
}

#[test]
fn adv135_umami_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "umami-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv135_umami_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "umami-api-key",
        "UMAMI_API_KEY=6ea17ead-9d16-752e\u{200B}-bc57-4e4ac8609e13",
        "6ea17ead-9d16-752e-bc57-4e4ac8609e13",
    );
}

#[test]
fn adv135_umami_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "umami-api-key",
        "UMAMI_API_KEY=6ea17ead-9d16-752e\u{00AD}-bc57-4e4ac8609e13",
        "6ea17ead-9d16-752e-bc57-4e4ac8609e13",
    );
}

#[test]
fn adv135_umami_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "umami-api-key",
        "UMAMI_API_KEY=6ea17ead-9d16-752e\u{200C}-bc57-4e4ac8609e13",
        "6ea17ead-9d16-752e-bc57-4e4ac8609e13",
    );
}

#[test]
fn adv135_umami_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "umami-api-key",
        "UMAMI_API_KEY=6ea17ead-9d16-752e\u{200D}-bc57-4e4ac8609e13",
        "6ea17ead-9d16-752e-bc57-4e4ac8609e13",
    );
}

#[test]
fn adv135_umami_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "umami-api-key",
        "UMAMI_API_KEY=6ea17ead-9d16-752e\u{FEFF}-bc57-4e4ac8609e13",
        "6ea17ead-9d16-752e-bc57-4e4ac8609e13",
    );
}

#[test]
fn adv135_umami_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "umami-api-key",
        "UMAMI_API_KEY=6ea17ead-9d16-752e\u{2060}-bc57-4e4ac8609e13",
        "6ea17ead-9d16-752e-bc57-4e4ac8609e13",
    );
}

#[test]
fn adv135_umami_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "umami-api-key",
        "UMAMI_API_KEY=6ea17ead-9d16-752e\u{180E}-bc57-4e4ac8609e13",
        "6ea17ead-9d16-752e-bc57-4e4ac8609e13",
    );
}

#[test]
fn adv135_umami_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "umami-api-key",
        "UMAMI_API_KEY=6ea17ead-9d16-752e\u{202E}-bc57-4e4ac8609e13",
        "6ea17ead-9d16-752e-bc57-4e4ac8609e13",
    );
}

#[test]
fn adv135_umami_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "umami-api-key",
        "UMAMI_API_KEY=6ea17ead-9d16-752e\u{202C}-bc57-4e4ac8609e13",
        "6ea17ead-9d16-752e-bc57-4e4ac8609e13",
    );
}

#[test]
fn adv135_umami_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "umami-api-key",
        "UMAMI_API_KEY=6ea17ead-9d16-752e\u{200E}-bc57-4e4ac8609e13",
        "6ea17ead-9d16-752e-bc57-4e4ac8609e13",
    );
}


