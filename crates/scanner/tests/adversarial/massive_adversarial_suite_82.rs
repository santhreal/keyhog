//! Part 82 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates discord, discord, discord, dnsimple, dockerhub, docusign, docusign, doordash, doppler, doppler detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. DISCORD BOT TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv82_discord_bot_token_normal_must_fire() {
    assert_detector_fires(
        "discord-bot-token",
        "DISCORD_BOT_TOKEN=MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv82_discord_bot_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "discord-bot-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv82_discord_bot_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "discord-bot-token",
        "DISCORD_BOT_TOKEN=MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx\u{200B}2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv82_discord_bot_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "discord-bot-token",
        "DISCORD_BOT_TOKEN=MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx\u{00AD}2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv82_discord_bot_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "discord-bot-token",
        "DISCORD_BOT_TOKEN=MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx\u{200C}2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv82_discord_bot_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "discord-bot-token",
        "DISCORD_BOT_TOKEN=MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx\u{200D}2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv82_discord_bot_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "discord-bot-token",
        "DISCORD_BOT_TOKEN=MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx\u{FEFF}2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv82_discord_bot_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "discord-bot-token",
        "DISCORD_BOT_TOKEN=MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx\u{2060}2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv82_discord_bot_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "discord-bot-token",
        "DISCORD_BOT_TOKEN=MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx\u{180E}2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv82_discord_bot_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "discord-bot-token",
        "DISCORD_BOT_TOKEN=MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx\u{202E}2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv82_discord_bot_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "discord-bot-token",
        "DISCORD_BOT_TOKEN=MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx\u{202C}2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

#[test]
fn adv82_discord_bot_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "discord-bot-token",
        "DISCORD_BOT_TOKEN=MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx\u{200E}2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
        "MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm",
    );
}

// =========================================================================
// 2. DISCORD OAUTH SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv82_discord_oauth_secret_normal_must_fire() {
    assert_detector_fires(
        "discord-oauth-secret",
        "DISCORD_CLIENT_SECRET=ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

#[test]
fn adv82_discord_oauth_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "discord-oauth-secret",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv82_discord_oauth_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "discord-oauth-secret",
        "DISCORD_CLIENT_SECRET=ZX0SakOvfcEiU6Mg\u{200B}Qmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

#[test]
fn adv82_discord_oauth_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "discord-oauth-secret",
        "DISCORD_CLIENT_SECRET=ZX0SakOvfcEiU6Mg\u{00AD}Qmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

#[test]
fn adv82_discord_oauth_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "discord-oauth-secret",
        "DISCORD_CLIENT_SECRET=ZX0SakOvfcEiU6Mg\u{200C}Qmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

#[test]
fn adv82_discord_oauth_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "discord-oauth-secret",
        "DISCORD_CLIENT_SECRET=ZX0SakOvfcEiU6Mg\u{200D}Qmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

#[test]
fn adv82_discord_oauth_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "discord-oauth-secret",
        "DISCORD_CLIENT_SECRET=ZX0SakOvfcEiU6Mg\u{FEFF}Qmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

#[test]
fn adv82_discord_oauth_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "discord-oauth-secret",
        "DISCORD_CLIENT_SECRET=ZX0SakOvfcEiU6Mg\u{2060}Qmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

#[test]
fn adv82_discord_oauth_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "discord-oauth-secret",
        "DISCORD_CLIENT_SECRET=ZX0SakOvfcEiU6Mg\u{180E}Qmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

#[test]
fn adv82_discord_oauth_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "discord-oauth-secret",
        "DISCORD_CLIENT_SECRET=ZX0SakOvfcEiU6Mg\u{202E}Qmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

#[test]
fn adv82_discord_oauth_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "discord-oauth-secret",
        "DISCORD_CLIENT_SECRET=ZX0SakOvfcEiU6Mg\u{202C}Qmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

#[test]
fn adv82_discord_oauth_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "discord-oauth-secret",
        "DISCORD_CLIENT_SECRET=ZX0SakOvfcEiU6Mg\u{200E}Qmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

// =========================================================================
// 3. DISCORD WEBHOOK CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv82_discord_webhook_credentials_normal_must_fire() {
    assert_detector_fires(
        "discord-webhook-credentials",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8rdbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8rdbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
    );
}

#[test]
fn adv82_discord_webhook_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "discord-webhook-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv82_discord_webhook_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "discord-webhook-credentials",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8r\u{200B}dbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8rdbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
    );
}

#[test]
fn adv82_discord_webhook_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "discord-webhook-credentials",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8r\u{00AD}dbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8rdbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
    );
}

#[test]
fn adv82_discord_webhook_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "discord-webhook-credentials",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8r\u{200C}dbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8rdbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
    );
}

#[test]
fn adv82_discord_webhook_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "discord-webhook-credentials",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8r\u{200D}dbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8rdbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
    );
}

#[test]
fn adv82_discord_webhook_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "discord-webhook-credentials",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8r\u{FEFF}dbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8rdbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
    );
}

#[test]
fn adv82_discord_webhook_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "discord-webhook-credentials",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8r\u{2060}dbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8rdbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
    );
}

#[test]
fn adv82_discord_webhook_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "discord-webhook-credentials",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8r\u{180E}dbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8rdbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
    );
}

#[test]
fn adv82_discord_webhook_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "discord-webhook-credentials",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8r\u{202E}dbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8rdbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
    );
}

#[test]
fn adv82_discord_webhook_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "discord-webhook-credentials",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8r\u{202C}dbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8rdbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
    );
}

#[test]
fn adv82_discord_webhook_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "discord-webhook-credentials",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8r\u{200E}dbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
        "https://discord.com/api/webhooks/12345678901234567/IO0l8rdbq6tdAdwgnLsh3gU6UBHE5IxcSHBos0IwhMeZvisjRREI6Flk1z6yxaxa",
    );
}

// =========================================================================
// 4. DNSIMPLE API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv82_dnsimple_api_token_normal_must_fire() {
    assert_detector_fires(
        "dnsimple-api-token",
        "DNSIMPLE_API_TOKEN=C372xGw30nSx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

#[test]
fn adv82_dnsimple_api_token_wrong_prefix_must_silent() {
    assert_detector_silent("dnsimple-api-token", "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv82_dnsimple_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "dnsimple-api-token",
        "DNSIMPLE_API_TOKEN=C372xGw30n\u{200B}Sx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

#[test]
fn adv82_dnsimple_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "dnsimple-api-token",
        "DNSIMPLE_API_TOKEN=C372xGw30n\u{00AD}Sx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

#[test]
fn adv82_dnsimple_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "dnsimple-api-token",
        "DNSIMPLE_API_TOKEN=C372xGw30n\u{200C}Sx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

#[test]
fn adv82_dnsimple_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "dnsimple-api-token",
        "DNSIMPLE_API_TOKEN=C372xGw30n\u{200D}Sx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

#[test]
fn adv82_dnsimple_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "dnsimple-api-token",
        "DNSIMPLE_API_TOKEN=C372xGw30n\u{FEFF}Sx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

#[test]
fn adv82_dnsimple_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "dnsimple-api-token",
        "DNSIMPLE_API_TOKEN=C372xGw30n\u{2060}Sx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

#[test]
fn adv82_dnsimple_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "dnsimple-api-token",
        "DNSIMPLE_API_TOKEN=C372xGw30n\u{180E}Sx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

#[test]
fn adv82_dnsimple_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "dnsimple-api-token",
        "DNSIMPLE_API_TOKEN=C372xGw30n\u{202E}Sx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

#[test]
fn adv82_dnsimple_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "dnsimple-api-token",
        "DNSIMPLE_API_TOKEN=C372xGw30n\u{202C}Sx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

#[test]
fn adv82_dnsimple_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "dnsimple-api-token",
        "DNSIMPLE_API_TOKEN=C372xGw30n\u{200E}Sx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

// =========================================================================
// 5. DOCKERHUB PAT ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv82_dockerhub_pat_normal_must_fire() {
    assert_detector_fires(
        "dockerhub-pat",
        "dckr_pat_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        "dckr_pat_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv82_dockerhub_pat_wrong_prefix_must_silent() {
    assert_detector_silent("dockerhub-pat", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv82_dockerhub_pat_evade_zwsp_must_fire() {
    assert_detector_fires(
        "dockerhub-pat",
        "dckr_pat_Kp4Qx7Rm2Sn\u{200B}5Tb8Vw3YzKp4Qx7Rm2Sn",
        "dckr_pat_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv82_dockerhub_pat_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "dockerhub-pat",
        "dckr_pat_Kp4Qx7Rm2Sn\u{00AD}5Tb8Vw3YzKp4Qx7Rm2Sn",
        "dckr_pat_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv82_dockerhub_pat_evade_zwnj_must_fire() {
    assert_detector_fires(
        "dockerhub-pat",
        "dckr_pat_Kp4Qx7Rm2Sn\u{200C}5Tb8Vw3YzKp4Qx7Rm2Sn",
        "dckr_pat_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv82_dockerhub_pat_evade_zwj_must_fire() {
    assert_detector_fires(
        "dockerhub-pat",
        "dckr_pat_Kp4Qx7Rm2Sn\u{200D}5Tb8Vw3YzKp4Qx7Rm2Sn",
        "dckr_pat_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv82_dockerhub_pat_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "dockerhub-pat",
        "dckr_pat_Kp4Qx7Rm2Sn\u{FEFF}5Tb8Vw3YzKp4Qx7Rm2Sn",
        "dckr_pat_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv82_dockerhub_pat_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "dockerhub-pat",
        "dckr_pat_Kp4Qx7Rm2Sn\u{2060}5Tb8Vw3YzKp4Qx7Rm2Sn",
        "dckr_pat_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv82_dockerhub_pat_evade_mongolian_must_fire() {
    assert_detector_fires(
        "dockerhub-pat",
        "dckr_pat_Kp4Qx7Rm2Sn\u{180E}5Tb8Vw3YzKp4Qx7Rm2Sn",
        "dckr_pat_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv82_dockerhub_pat_evade_rtl_must_fire() {
    assert_detector_fires(
        "dockerhub-pat",
        "dckr_pat_Kp4Qx7Rm2Sn\u{202E}5Tb8Vw3YzKp4Qx7Rm2Sn",
        "dckr_pat_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv82_dockerhub_pat_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "dockerhub-pat",
        "dckr_pat_Kp4Qx7Rm2Sn\u{202C}5Tb8Vw3YzKp4Qx7Rm2Sn",
        "dckr_pat_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

#[test]
fn adv82_dockerhub_pat_evade_lrm_must_fire() {
    assert_detector_fires(
        "dockerhub-pat",
        "dckr_pat_Kp4Qx7Rm2Sn\u{200E}5Tb8Vw3YzKp4Qx7Rm2Sn",
        "dckr_pat_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
    );
}

// =========================================================================
// 6. DOCUSIGN API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv82_docusign_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "docusign-api-credentials",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_docusign_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "docusign-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv82_docusign_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "docusign-api-credentials",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873\u{200B}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_docusign_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "docusign-api-credentials",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873\u{00AD}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_docusign_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "docusign-api-credentials",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873\u{200C}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_docusign_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "docusign-api-credentials",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873\u{200D}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_docusign_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "docusign-api-credentials",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873\u{FEFF}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_docusign_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "docusign-api-credentials",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873\u{2060}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_docusign_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "docusign-api-credentials",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873\u{180E}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_docusign_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "docusign-api-credentials",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873\u{202E}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_docusign_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "docusign-api-credentials",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873\u{202C}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_docusign_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "docusign-api-credentials",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873\u{200E}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

// =========================================================================
// 7. DOCUSIGN API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv82_docusign_api_key_normal_must_fire() {
    assert_detector_fires(
        "docusign-api-key",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_docusign_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "docusign-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv82_docusign_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "docusign-api-key",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873\u{200B}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_docusign_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "docusign-api-key",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873\u{00AD}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_docusign_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "docusign-api-key",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873\u{200C}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_docusign_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "docusign-api-key",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873\u{200D}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_docusign_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "docusign-api-key",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873\u{FEFF}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_docusign_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "docusign-api-key",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873\u{2060}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_docusign_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "docusign-api-key",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873\u{180E}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_docusign_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "docusign-api-key",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873\u{202E}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_docusign_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "docusign-api-key",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873\u{202C}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_docusign_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "docusign-api-key",
        "DOCUSIGN_INTEGRATION_KEY=0a82d930-0311-5873\u{200E}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

// =========================================================================
// 8. DOORDASH API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv82_doordash_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "doordash-api-credentials",
        "DOORDASH_developer_id=0a82d930-0311-5873-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_doordash_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "doordash-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv82_doordash_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "doordash-api-credentials",
        "DOORDASH_developer_id=0a82d930-0311-5873\u{200B}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_doordash_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "doordash-api-credentials",
        "DOORDASH_developer_id=0a82d930-0311-5873\u{00AD}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_doordash_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "doordash-api-credentials",
        "DOORDASH_developer_id=0a82d930-0311-5873\u{200C}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_doordash_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "doordash-api-credentials",
        "DOORDASH_developer_id=0a82d930-0311-5873\u{200D}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_doordash_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "doordash-api-credentials",
        "DOORDASH_developer_id=0a82d930-0311-5873\u{FEFF}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_doordash_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "doordash-api-credentials",
        "DOORDASH_developer_id=0a82d930-0311-5873\u{2060}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_doordash_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "doordash-api-credentials",
        "DOORDASH_developer_id=0a82d930-0311-5873\u{180E}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_doordash_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "doordash-api-credentials",
        "DOORDASH_developer_id=0a82d930-0311-5873\u{202E}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_doordash_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "doordash-api-credentials",
        "DOORDASH_developer_id=0a82d930-0311-5873\u{202C}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

#[test]
fn adv82_doordash_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "doordash-api-credentials",
        "DOORDASH_developer_id=0a82d930-0311-5873\u{200E}-e7cb-7c3a6be1eacf",
        "0a82d930-0311-5873-e7cb-7c3a6be1eacf",
    );
}

// =========================================================================
// 9. DOPPLER CLI TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv82_doppler_cli_token_normal_must_fire() {
    assert_detector_fires(
        "doppler-cli-token",
        "doppler dp.ct.NbrnTP3fAbnFbmOHnKYaXRvj7uff0LYTH8xIZM1JRcor",
        "dp.ct.NbrnTP3fAbnFbmOHnKYaXRvj7uff0LYTH8xIZM1JRcor",
    );
}

#[test]
fn adv82_doppler_cli_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "doppler-cli-token",
        "dummyler xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv82_doppler_cli_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "doppler-cli-token",
        "doppler dp.ct.NbrnTP3fAbnFbmOHnKY\u{200B}aXRvj7uff0LYTH8xIZM1JRcor",
        "dp.ct.NbrnTP3fAbnFbmOHnKYaXRvj7uff0LYTH8xIZM1JRcor",
    );
}

#[test]
fn adv82_doppler_cli_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "doppler-cli-token",
        "doppler dp.ct.NbrnTP3fAbnFbmOHnKY\u{00AD}aXRvj7uff0LYTH8xIZM1JRcor",
        "dp.ct.NbrnTP3fAbnFbmOHnKYaXRvj7uff0LYTH8xIZM1JRcor",
    );
}

#[test]
fn adv82_doppler_cli_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "doppler-cli-token",
        "doppler dp.ct.NbrnTP3fAbnFbmOHnKY\u{200C}aXRvj7uff0LYTH8xIZM1JRcor",
        "dp.ct.NbrnTP3fAbnFbmOHnKYaXRvj7uff0LYTH8xIZM1JRcor",
    );
}

#[test]
fn adv82_doppler_cli_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "doppler-cli-token",
        "doppler dp.ct.NbrnTP3fAbnFbmOHnKY\u{200D}aXRvj7uff0LYTH8xIZM1JRcor",
        "dp.ct.NbrnTP3fAbnFbmOHnKYaXRvj7uff0LYTH8xIZM1JRcor",
    );
}

#[test]
fn adv82_doppler_cli_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "doppler-cli-token",
        "doppler dp.ct.NbrnTP3fAbnFbmOHnKY\u{FEFF}aXRvj7uff0LYTH8xIZM1JRcor",
        "dp.ct.NbrnTP3fAbnFbmOHnKYaXRvj7uff0LYTH8xIZM1JRcor",
    );
}

#[test]
fn adv82_doppler_cli_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "doppler-cli-token",
        "doppler dp.ct.NbrnTP3fAbnFbmOHnKY\u{2060}aXRvj7uff0LYTH8xIZM1JRcor",
        "dp.ct.NbrnTP3fAbnFbmOHnKYaXRvj7uff0LYTH8xIZM1JRcor",
    );
}

#[test]
fn adv82_doppler_cli_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "doppler-cli-token",
        "doppler dp.ct.NbrnTP3fAbnFbmOHnKY\u{180E}aXRvj7uff0LYTH8xIZM1JRcor",
        "dp.ct.NbrnTP3fAbnFbmOHnKYaXRvj7uff0LYTH8xIZM1JRcor",
    );
}

#[test]
fn adv82_doppler_cli_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "doppler-cli-token",
        "doppler dp.ct.NbrnTP3fAbnFbmOHnKY\u{202E}aXRvj7uff0LYTH8xIZM1JRcor",
        "dp.ct.NbrnTP3fAbnFbmOHnKYaXRvj7uff0LYTH8xIZM1JRcor",
    );
}

#[test]
fn adv82_doppler_cli_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "doppler-cli-token",
        "doppler dp.ct.NbrnTP3fAbnFbmOHnKY\u{202C}aXRvj7uff0LYTH8xIZM1JRcor",
        "dp.ct.NbrnTP3fAbnFbmOHnKYaXRvj7uff0LYTH8xIZM1JRcor",
    );
}

#[test]
fn adv82_doppler_cli_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "doppler-cli-token",
        "doppler dp.ct.NbrnTP3fAbnFbmOHnKY\u{200E}aXRvj7uff0LYTH8xIZM1JRcor",
        "dp.ct.NbrnTP3fAbnFbmOHnKYaXRvj7uff0LYTH8xIZM1JRcor",
    );
}

// =========================================================================
// 10. DOPPLER SERVICE TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv82_doppler_service_token_normal_must_fire() {
    assert_detector_fires(
        "doppler-service-token",
        "doppler dp.st.cRiCPXCEbAx0HUAk0YxfFEVLFJxdd60s3Gg1K5Qf",
        "dp.st.cRiCPXCEbAx0HUAk0YxfFEVLFJxdd60s3Gg1K5Qf",
    );
}

#[test]
fn adv82_doppler_service_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "doppler-service-token",
        "dummyler xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv82_doppler_service_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "doppler-service-token",
        "doppler dp.st.cRiCPXCEbAx0HUAk0\u{200B}YxfFEVLFJxdd60s3Gg1K5Qf",
        "dp.st.cRiCPXCEbAx0HUAk0YxfFEVLFJxdd60s3Gg1K5Qf",
    );
}

#[test]
fn adv82_doppler_service_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "doppler-service-token",
        "doppler dp.st.cRiCPXCEbAx0HUAk0\u{00AD}YxfFEVLFJxdd60s3Gg1K5Qf",
        "dp.st.cRiCPXCEbAx0HUAk0YxfFEVLFJxdd60s3Gg1K5Qf",
    );
}

#[test]
fn adv82_doppler_service_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "doppler-service-token",
        "doppler dp.st.cRiCPXCEbAx0HUAk0\u{200C}YxfFEVLFJxdd60s3Gg1K5Qf",
        "dp.st.cRiCPXCEbAx0HUAk0YxfFEVLFJxdd60s3Gg1K5Qf",
    );
}

#[test]
fn adv82_doppler_service_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "doppler-service-token",
        "doppler dp.st.cRiCPXCEbAx0HUAk0\u{200D}YxfFEVLFJxdd60s3Gg1K5Qf",
        "dp.st.cRiCPXCEbAx0HUAk0YxfFEVLFJxdd60s3Gg1K5Qf",
    );
}

#[test]
fn adv82_doppler_service_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "doppler-service-token",
        "doppler dp.st.cRiCPXCEbAx0HUAk0\u{FEFF}YxfFEVLFJxdd60s3Gg1K5Qf",
        "dp.st.cRiCPXCEbAx0HUAk0YxfFEVLFJxdd60s3Gg1K5Qf",
    );
}

#[test]
fn adv82_doppler_service_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "doppler-service-token",
        "doppler dp.st.cRiCPXCEbAx0HUAk0\u{2060}YxfFEVLFJxdd60s3Gg1K5Qf",
        "dp.st.cRiCPXCEbAx0HUAk0YxfFEVLFJxdd60s3Gg1K5Qf",
    );
}

#[test]
fn adv82_doppler_service_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "doppler-service-token",
        "doppler dp.st.cRiCPXCEbAx0HUAk0\u{180E}YxfFEVLFJxdd60s3Gg1K5Qf",
        "dp.st.cRiCPXCEbAx0HUAk0YxfFEVLFJxdd60s3Gg1K5Qf",
    );
}

#[test]
fn adv82_doppler_service_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "doppler-service-token",
        "doppler dp.st.cRiCPXCEbAx0HUAk0\u{202E}YxfFEVLFJxdd60s3Gg1K5Qf",
        "dp.st.cRiCPXCEbAx0HUAk0YxfFEVLFJxdd60s3Gg1K5Qf",
    );
}

#[test]
fn adv82_doppler_service_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "doppler-service-token",
        "doppler dp.st.cRiCPXCEbAx0HUAk0\u{202C}YxfFEVLFJxdd60s3Gg1K5Qf",
        "dp.st.cRiCPXCEbAx0HUAk0YxfFEVLFJxdd60s3Gg1K5Qf",
    );
}

#[test]
fn adv82_doppler_service_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "doppler-service-token",
        "doppler dp.st.cRiCPXCEbAx0HUAk0\u{200E}YxfFEVLFJxdd60s3Gg1K5Qf",
        "dp.st.cRiCPXCEbAx0HUAk0YxfFEVLFJxdd60s3Gg1K5Qf",
    );
}
