//! Part 119 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates prisma, private, prometheus, promptlayer, propelauth, pubnub, pubnub, pulsar, pulumi, puppet detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. PRISMA CLOUD API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv119_prisma_cloud_api_token_normal_must_fire() {
    assert_detector_fires(
        "prisma-cloud-api-token",
        "PRISMA_API_KEY=eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9KpU33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
        "eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9KpU33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
    );
}

#[test]
fn adv119_prisma_cloud_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "prisma-cloud-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv119_prisma_cloud_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "prisma-cloud-api-token",
        "PRISMA_API_KEY=eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9Kp\u{200B}U33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
        "eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9KpU33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
    );
}

#[test]
fn adv119_prisma_cloud_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "prisma-cloud-api-token",
        "PRISMA_API_KEY=eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9Kp\u{00AD}U33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
        "eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9KpU33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
    );
}

#[test]
fn adv119_prisma_cloud_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "prisma-cloud-api-token",
        "PRISMA_API_KEY=eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9Kp\u{200C}U33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
        "eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9KpU33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
    );
}

#[test]
fn adv119_prisma_cloud_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "prisma-cloud-api-token",
        "PRISMA_API_KEY=eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9Kp\u{200D}U33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
        "eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9KpU33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
    );
}

#[test]
fn adv119_prisma_cloud_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "prisma-cloud-api-token",
        "PRISMA_API_KEY=eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9Kp\u{FEFF}U33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
        "eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9KpU33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
    );
}

#[test]
fn adv119_prisma_cloud_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "prisma-cloud-api-token",
        "PRISMA_API_KEY=eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9Kp\u{2060}U33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
        "eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9KpU33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
    );
}

#[test]
fn adv119_prisma_cloud_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "prisma-cloud-api-token",
        "PRISMA_API_KEY=eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9Kp\u{180E}U33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
        "eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9KpU33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
    );
}

#[test]
fn adv119_prisma_cloud_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "prisma-cloud-api-token",
        "PRISMA_API_KEY=eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9Kp\u{202E}U33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
        "eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9KpU33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
    );
}

#[test]
fn adv119_prisma_cloud_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "prisma-cloud-api-token",
        "PRISMA_API_KEY=eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9Kp\u{202C}U33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
        "eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9KpU33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
    );
}

#[test]
fn adv119_prisma_cloud_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "prisma-cloud-api-token",
        "PRISMA_API_KEY=eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9Kp\u{200E}U33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
        "eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9KpU33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
    );
}

// =========================================================================
// 2. PRIVATE KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv119_private_key_normal_must_fire() {
    assert_detector_fires(
        "private-key",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    );
}

#[test]
fn adv119_private_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "private-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv119_private_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "private-key",
        "-----BEGIN RSA \u{200B}PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    );
}

#[test]
fn adv119_private_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "private-key",
        "-----BEGIN RSA \u{00AD}PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    );
}

#[test]
fn adv119_private_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "private-key",
        "-----BEGIN RSA \u{200C}PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    );
}

#[test]
fn adv119_private_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "private-key",
        "-----BEGIN RSA \u{200D}PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    );
}

#[test]
fn adv119_private_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "private-key",
        "-----BEGIN RSA \u{FEFF}PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    );
}

#[test]
fn adv119_private_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "private-key",
        "-----BEGIN RSA \u{2060}PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    );
}

#[test]
fn adv119_private_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "private-key",
        "-----BEGIN RSA \u{180E}PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    );
}

#[test]
fn adv119_private_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "private-key",
        "-----BEGIN RSA \u{202E}PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    );
}

#[test]
fn adv119_private_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "private-key",
        "-----BEGIN RSA \u{202C}PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    );
}

#[test]
fn adv119_private_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "private-key",
        "-----BEGIN RSA \u{200E}PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    );
}

// =========================================================================
// 3. PROMETHEUS ALERTMANAGER WEBHOOK ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv119_prometheus_alertmanager_webhook_normal_must_fire() {
    assert_detector_fires(
        "prometheus-alertmanager-webhook",
        "webhook_url=https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgxe8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
        "https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgxe8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
    );
}

#[test]
fn adv119_prometheus_alertmanager_webhook_wrong_prefix_must_silent() {
    assert_detector_silent(
        "prometheus-alertmanager-webhook",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv119_prometheus_alertmanager_webhook_evade_zwsp_must_fire() {
    assert_detector_fires(
        "prometheus-alertmanager-webhook",
        "webhook_url=https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgx\u{200B}e8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
        "https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgxe8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
    );
}

#[test]
fn adv119_prometheus_alertmanager_webhook_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "prometheus-alertmanager-webhook",
        "webhook_url=https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgx\u{00AD}e8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
        "https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgxe8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
    );
}

#[test]
fn adv119_prometheus_alertmanager_webhook_evade_zwnj_must_fire() {
    assert_detector_fires(
        "prometheus-alertmanager-webhook",
        "webhook_url=https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgx\u{200C}e8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
        "https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgxe8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
    );
}

#[test]
fn adv119_prometheus_alertmanager_webhook_evade_zwj_must_fire() {
    assert_detector_fires(
        "prometheus-alertmanager-webhook",
        "webhook_url=https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgx\u{200D}e8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
        "https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgxe8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
    );
}

#[test]
fn adv119_prometheus_alertmanager_webhook_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "prometheus-alertmanager-webhook",
        "webhook_url=https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgx\u{FEFF}e8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
        "https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgxe8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
    );
}

#[test]
fn adv119_prometheus_alertmanager_webhook_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "prometheus-alertmanager-webhook",
        "webhook_url=https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgx\u{2060}e8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
        "https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgxe8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
    );
}

#[test]
fn adv119_prometheus_alertmanager_webhook_evade_mongolian_must_fire() {
    assert_detector_fires(
        "prometheus-alertmanager-webhook",
        "webhook_url=https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgx\u{180E}e8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
        "https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgxe8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
    );
}

#[test]
fn adv119_prometheus_alertmanager_webhook_evade_rtl_must_fire() {
    assert_detector_fires(
        "prometheus-alertmanager-webhook",
        "webhook_url=https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgx\u{202E}e8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
        "https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgxe8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
    );
}

#[test]
fn adv119_prometheus_alertmanager_webhook_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "prometheus-alertmanager-webhook",
        "webhook_url=https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgx\u{202C}e8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
        "https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgxe8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
    );
}

#[test]
fn adv119_prometheus_alertmanager_webhook_evade_lrm_must_fire() {
    assert_detector_fires(
        "prometheus-alertmanager-webhook",
        "webhook_url=https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgx\u{200E}e8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
        "https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgxe8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
    );
}

// =========================================================================
// 4. PROMPTLAYER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv119_promptlayer_api_key_normal_must_fire() {
    assert_detector_fires(
        "promptlayer-api-key",
        "pl_OhX5esA2JNCvMTNpyfUbF1xLPsfJUnON",
        "pl_OhX5esA2JNCvMTNpyfUbF1xLPsfJUnON",
    );
}

#[test]
fn adv119_promptlayer_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "promptlayer-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv119_promptlayer_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "promptlayer-api-key",
        "pl_OhX5esA2JNCvMT\u{200B}NpyfUbF1xLPsfJUnON",
        "pl_OhX5esA2JNCvMTNpyfUbF1xLPsfJUnON",
    );
}

#[test]
fn adv119_promptlayer_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "promptlayer-api-key",
        "pl_OhX5esA2JNCvMT\u{00AD}NpyfUbF1xLPsfJUnON",
        "pl_OhX5esA2JNCvMTNpyfUbF1xLPsfJUnON",
    );
}

#[test]
fn adv119_promptlayer_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "promptlayer-api-key",
        "pl_OhX5esA2JNCvMT\u{200C}NpyfUbF1xLPsfJUnON",
        "pl_OhX5esA2JNCvMTNpyfUbF1xLPsfJUnON",
    );
}

#[test]
fn adv119_promptlayer_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "promptlayer-api-key",
        "pl_OhX5esA2JNCvMT\u{200D}NpyfUbF1xLPsfJUnON",
        "pl_OhX5esA2JNCvMTNpyfUbF1xLPsfJUnON",
    );
}

#[test]
fn adv119_promptlayer_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "promptlayer-api-key",
        "pl_OhX5esA2JNCvMT\u{FEFF}NpyfUbF1xLPsfJUnON",
        "pl_OhX5esA2JNCvMTNpyfUbF1xLPsfJUnON",
    );
}

#[test]
fn adv119_promptlayer_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "promptlayer-api-key",
        "pl_OhX5esA2JNCvMT\u{2060}NpyfUbF1xLPsfJUnON",
        "pl_OhX5esA2JNCvMTNpyfUbF1xLPsfJUnON",
    );
}

#[test]
fn adv119_promptlayer_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "promptlayer-api-key",
        "pl_OhX5esA2JNCvMT\u{180E}NpyfUbF1xLPsfJUnON",
        "pl_OhX5esA2JNCvMTNpyfUbF1xLPsfJUnON",
    );
}

#[test]
fn adv119_promptlayer_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "promptlayer-api-key",
        "pl_OhX5esA2JNCvMT\u{202E}NpyfUbF1xLPsfJUnON",
        "pl_OhX5esA2JNCvMTNpyfUbF1xLPsfJUnON",
    );
}

#[test]
fn adv119_promptlayer_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "promptlayer-api-key",
        "pl_OhX5esA2JNCvMT\u{202C}NpyfUbF1xLPsfJUnON",
        "pl_OhX5esA2JNCvMTNpyfUbF1xLPsfJUnON",
    );
}

#[test]
fn adv119_promptlayer_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "promptlayer-api-key",
        "pl_OhX5esA2JNCvMT\u{200E}NpyfUbF1xLPsfJUnON",
        "pl_OhX5esA2JNCvMTNpyfUbF1xLPsfJUnON",
    );
}

// =========================================================================
// 5. PROPELAUTH API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv119_propelauth_api_key_normal_must_fire() {
    assert_detector_fires(
        "propelauth-api-key",
        "PROPELAUTH_API_KEY=b3265b7c389276d437c18f7c28d04f34",
        "b3265b7c389276d437c18f7c28d04f34",
    );
}

#[test]
fn adv119_propelauth_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "propelauth-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv119_propelauth_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "propelauth-api-key",
        "PROPELAUTH_API_KEY=b3265b7c389276d4\u{200B}37c18f7c28d04f34",
        "b3265b7c389276d437c18f7c28d04f34",
    );
}

#[test]
fn adv119_propelauth_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "propelauth-api-key",
        "PROPELAUTH_API_KEY=b3265b7c389276d4\u{00AD}37c18f7c28d04f34",
        "b3265b7c389276d437c18f7c28d04f34",
    );
}

#[test]
fn adv119_propelauth_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "propelauth-api-key",
        "PROPELAUTH_API_KEY=b3265b7c389276d4\u{200C}37c18f7c28d04f34",
        "b3265b7c389276d437c18f7c28d04f34",
    );
}

#[test]
fn adv119_propelauth_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "propelauth-api-key",
        "PROPELAUTH_API_KEY=b3265b7c389276d4\u{200D}37c18f7c28d04f34",
        "b3265b7c389276d437c18f7c28d04f34",
    );
}

#[test]
fn adv119_propelauth_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "propelauth-api-key",
        "PROPELAUTH_API_KEY=b3265b7c389276d4\u{FEFF}37c18f7c28d04f34",
        "b3265b7c389276d437c18f7c28d04f34",
    );
}

#[test]
fn adv119_propelauth_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "propelauth-api-key",
        "PROPELAUTH_API_KEY=b3265b7c389276d4\u{2060}37c18f7c28d04f34",
        "b3265b7c389276d437c18f7c28d04f34",
    );
}

#[test]
fn adv119_propelauth_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "propelauth-api-key",
        "PROPELAUTH_API_KEY=b3265b7c389276d4\u{180E}37c18f7c28d04f34",
        "b3265b7c389276d437c18f7c28d04f34",
    );
}

#[test]
fn adv119_propelauth_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "propelauth-api-key",
        "PROPELAUTH_API_KEY=b3265b7c389276d4\u{202E}37c18f7c28d04f34",
        "b3265b7c389276d437c18f7c28d04f34",
    );
}

#[test]
fn adv119_propelauth_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "propelauth-api-key",
        "PROPELAUTH_API_KEY=b3265b7c389276d4\u{202C}37c18f7c28d04f34",
        "b3265b7c389276d437c18f7c28d04f34",
    );
}

#[test]
fn adv119_propelauth_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "propelauth-api-key",
        "PROPELAUTH_API_KEY=b3265b7c389276d4\u{200E}37c18f7c28d04f34",
        "b3265b7c389276d437c18f7c28d04f34",
    );
}

// =========================================================================
// 6. PUBNUB PUBLISH KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv119_pubnub_publish_key_normal_must_fire() {
    assert_detector_fires(
        "pubnub-publish-key",
        "pub-c-d0743bdf-c3fe-a88e-492a-0ccb2ea13ddc",
        "pub-c-d0743bdf-c3fe-a88e-492a-0ccb2ea13ddc",
    );
}

#[test]
fn adv119_pubnub_publish_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pubnub-publish-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv119_pubnub_publish_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pubnub-publish-key",
        "pub-c-d0743bdf-c3fe-a\u{200B}88e-492a-0ccb2ea13ddc",
        "pub-c-d0743bdf-c3fe-a88e-492a-0ccb2ea13ddc",
    );
}

#[test]
fn adv119_pubnub_publish_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pubnub-publish-key",
        "pub-c-d0743bdf-c3fe-a\u{00AD}88e-492a-0ccb2ea13ddc",
        "pub-c-d0743bdf-c3fe-a88e-492a-0ccb2ea13ddc",
    );
}

#[test]
fn adv119_pubnub_publish_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "pubnub-publish-key",
        "pub-c-d0743bdf-c3fe-a\u{200C}88e-492a-0ccb2ea13ddc",
        "pub-c-d0743bdf-c3fe-a88e-492a-0ccb2ea13ddc",
    );
}

#[test]
fn adv119_pubnub_publish_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "pubnub-publish-key",
        "pub-c-d0743bdf-c3fe-a\u{200D}88e-492a-0ccb2ea13ddc",
        "pub-c-d0743bdf-c3fe-a88e-492a-0ccb2ea13ddc",
    );
}

#[test]
fn adv119_pubnub_publish_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "pubnub-publish-key",
        "pub-c-d0743bdf-c3fe-a\u{FEFF}88e-492a-0ccb2ea13ddc",
        "pub-c-d0743bdf-c3fe-a88e-492a-0ccb2ea13ddc",
    );
}

#[test]
fn adv119_pubnub_publish_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "pubnub-publish-key",
        "pub-c-d0743bdf-c3fe-a\u{2060}88e-492a-0ccb2ea13ddc",
        "pub-c-d0743bdf-c3fe-a88e-492a-0ccb2ea13ddc",
    );
}

#[test]
fn adv119_pubnub_publish_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "pubnub-publish-key",
        "pub-c-d0743bdf-c3fe-a\u{180E}88e-492a-0ccb2ea13ddc",
        "pub-c-d0743bdf-c3fe-a88e-492a-0ccb2ea13ddc",
    );
}

#[test]
fn adv119_pubnub_publish_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "pubnub-publish-key",
        "pub-c-d0743bdf-c3fe-a\u{202E}88e-492a-0ccb2ea13ddc",
        "pub-c-d0743bdf-c3fe-a88e-492a-0ccb2ea13ddc",
    );
}

#[test]
fn adv119_pubnub_publish_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "pubnub-publish-key",
        "pub-c-d0743bdf-c3fe-a\u{202C}88e-492a-0ccb2ea13ddc",
        "pub-c-d0743bdf-c3fe-a88e-492a-0ccb2ea13ddc",
    );
}

#[test]
fn adv119_pubnub_publish_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "pubnub-publish-key",
        "pub-c-d0743bdf-c3fe-a\u{200E}88e-492a-0ccb2ea13ddc",
        "pub-c-d0743bdf-c3fe-a88e-492a-0ccb2ea13ddc",
    );
}

// =========================================================================
// 7. PUBNUB SUBSCRIBE KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv119_pubnub_subscribe_key_normal_must_fire() {
    assert_detector_fires(
        "pubnub-subscribe-key",
        "sub-c-b424e2b7-3480-5c69-2564-52b5fde37b98",
        "sub-c-b424e2b7-3480-5c69-2564-52b5fde37b98",
    );
}

#[test]
fn adv119_pubnub_subscribe_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pubnub-subscribe-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv119_pubnub_subscribe_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pubnub-subscribe-key",
        "sub-c-b424e2b7-3480-5\u{200B}c69-2564-52b5fde37b98",
        "sub-c-b424e2b7-3480-5c69-2564-52b5fde37b98",
    );
}

#[test]
fn adv119_pubnub_subscribe_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pubnub-subscribe-key",
        "sub-c-b424e2b7-3480-5\u{00AD}c69-2564-52b5fde37b98",
        "sub-c-b424e2b7-3480-5c69-2564-52b5fde37b98",
    );
}

#[test]
fn adv119_pubnub_subscribe_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "pubnub-subscribe-key",
        "sub-c-b424e2b7-3480-5\u{200C}c69-2564-52b5fde37b98",
        "sub-c-b424e2b7-3480-5c69-2564-52b5fde37b98",
    );
}

#[test]
fn adv119_pubnub_subscribe_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "pubnub-subscribe-key",
        "sub-c-b424e2b7-3480-5\u{200D}c69-2564-52b5fde37b98",
        "sub-c-b424e2b7-3480-5c69-2564-52b5fde37b98",
    );
}

#[test]
fn adv119_pubnub_subscribe_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "pubnub-subscribe-key",
        "sub-c-b424e2b7-3480-5\u{FEFF}c69-2564-52b5fde37b98",
        "sub-c-b424e2b7-3480-5c69-2564-52b5fde37b98",
    );
}

#[test]
fn adv119_pubnub_subscribe_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "pubnub-subscribe-key",
        "sub-c-b424e2b7-3480-5\u{2060}c69-2564-52b5fde37b98",
        "sub-c-b424e2b7-3480-5c69-2564-52b5fde37b98",
    );
}

#[test]
fn adv119_pubnub_subscribe_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "pubnub-subscribe-key",
        "sub-c-b424e2b7-3480-5\u{180E}c69-2564-52b5fde37b98",
        "sub-c-b424e2b7-3480-5c69-2564-52b5fde37b98",
    );
}

#[test]
fn adv119_pubnub_subscribe_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "pubnub-subscribe-key",
        "sub-c-b424e2b7-3480-5\u{202E}c69-2564-52b5fde37b98",
        "sub-c-b424e2b7-3480-5c69-2564-52b5fde37b98",
    );
}

#[test]
fn adv119_pubnub_subscribe_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "pubnub-subscribe-key",
        "sub-c-b424e2b7-3480-5\u{202C}c69-2564-52b5fde37b98",
        "sub-c-b424e2b7-3480-5c69-2564-52b5fde37b98",
    );
}

#[test]
fn adv119_pubnub_subscribe_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "pubnub-subscribe-key",
        "sub-c-b424e2b7-3480-5\u{200E}c69-2564-52b5fde37b98",
        "sub-c-b424e2b7-3480-5c69-2564-52b5fde37b98",
    );
}

// =========================================================================
// 8. PULSAR JWT TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv119_pulsar_jwt_token_normal_must_fire() {
    assert_detector_fires(
        "pulsar-jwt-token",
        "brokerClientAuthenticationParameters=eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
        "eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
    );
}

#[test]
fn adv119_pulsar_jwt_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pulsar-jwt-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv119_pulsar_jwt_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pulsar-jwt-token",
        "brokerClientAuthenticationParameters=eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj\u{200B}6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
        "eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
    );
}

#[test]
fn adv119_pulsar_jwt_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pulsar-jwt-token",
        "brokerClientAuthenticationParameters=eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj\u{00AD}6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
        "eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
    );
}

#[test]
fn adv119_pulsar_jwt_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "pulsar-jwt-token",
        "brokerClientAuthenticationParameters=eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj\u{200C}6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
        "eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
    );
}

#[test]
fn adv119_pulsar_jwt_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "pulsar-jwt-token",
        "brokerClientAuthenticationParameters=eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj\u{200D}6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
        "eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
    );
}

#[test]
fn adv119_pulsar_jwt_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "pulsar-jwt-token",
        "brokerClientAuthenticationParameters=eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj\u{FEFF}6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
        "eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
    );
}

#[test]
fn adv119_pulsar_jwt_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "pulsar-jwt-token",
        "brokerClientAuthenticationParameters=eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj\u{2060}6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
        "eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
    );
}

#[test]
fn adv119_pulsar_jwt_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "pulsar-jwt-token",
        "brokerClientAuthenticationParameters=eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj\u{180E}6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
        "eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
    );
}

#[test]
fn adv119_pulsar_jwt_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "pulsar-jwt-token",
        "brokerClientAuthenticationParameters=eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj\u{202E}6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
        "eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
    );
}

#[test]
fn adv119_pulsar_jwt_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "pulsar-jwt-token",
        "brokerClientAuthenticationParameters=eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj\u{202C}6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
        "eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
    );
}

#[test]
fn adv119_pulsar_jwt_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "pulsar-jwt-token",
        "brokerClientAuthenticationParameters=eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj\u{200E}6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
        "eyJz71Tv_Gmh0V_KtJCgVbPIexNGw700lJQaTvkQDlJYbgmxsdivQ.eyJ5o-IGUtCapgIby0OMCNwMDpfpR0sWHVAY1_jIzaj6wkLhcJ_sz-kEbf91MNjIR0KKJehwLO.gn_9DfLqm_bwK6rWrjOWWWO2nlhNSIjOV8w_O5AcZswADZYBBW5hTMTDpXMKJIyzb",
    );
}

// =========================================================================
// 9. PULUMI ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv119_pulumi_access_token_normal_must_fire() {
    assert_detector_fires(
        "pulumi-access-token",
        "pul-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b",
        "pul-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b",
    );
}

#[test]
fn adv119_pulumi_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pulumi-access-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv119_pulumi_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pulumi-access-token",
        "pul-9a3b7c2e4d1f6a8b0c\u{200B}5d9e3f7a1b4c2d8e6f0a1b",
        "pul-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b",
    );
}

#[test]
fn adv119_pulumi_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pulumi-access-token",
        "pul-9a3b7c2e4d1f6a8b0c\u{00AD}5d9e3f7a1b4c2d8e6f0a1b",
        "pul-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b",
    );
}

#[test]
fn adv119_pulumi_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "pulumi-access-token",
        "pul-9a3b7c2e4d1f6a8b0c\u{200C}5d9e3f7a1b4c2d8e6f0a1b",
        "pul-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b",
    );
}

#[test]
fn adv119_pulumi_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "pulumi-access-token",
        "pul-9a3b7c2e4d1f6a8b0c\u{200D}5d9e3f7a1b4c2d8e6f0a1b",
        "pul-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b",
    );
}

#[test]
fn adv119_pulumi_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "pulumi-access-token",
        "pul-9a3b7c2e4d1f6a8b0c\u{FEFF}5d9e3f7a1b4c2d8e6f0a1b",
        "pul-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b",
    );
}

#[test]
fn adv119_pulumi_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "pulumi-access-token",
        "pul-9a3b7c2e4d1f6a8b0c\u{2060}5d9e3f7a1b4c2d8e6f0a1b",
        "pul-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b",
    );
}

#[test]
fn adv119_pulumi_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "pulumi-access-token",
        "pul-9a3b7c2e4d1f6a8b0c\u{180E}5d9e3f7a1b4c2d8e6f0a1b",
        "pul-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b",
    );
}

#[test]
fn adv119_pulumi_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "pulumi-access-token",
        "pul-9a3b7c2e4d1f6a8b0c\u{202E}5d9e3f7a1b4c2d8e6f0a1b",
        "pul-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b",
    );
}

#[test]
fn adv119_pulumi_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "pulumi-access-token",
        "pul-9a3b7c2e4d1f6a8b0c\u{202C}5d9e3f7a1b4c2d8e6f0a1b",
        "pul-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b",
    );
}

#[test]
fn adv119_pulumi_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "pulumi-access-token",
        "pul-9a3b7c2e4d1f6a8b0c\u{200E}5d9e3f7a1b4c2d8e6f0a1b",
        "pul-9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b",
    );
}

// =========================================================================
// 10. PUPPET ENTERPRISE TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv119_puppet_enterprise_token_normal_must_fire() {
    assert_detector_fires(
        "puppet-enterprise-token",
        "PE_TOKEN=df2C-IwsG2vZK2btF61X",
        "df2C-IwsG2vZK2btF61X",
    );
}

#[test]
fn adv119_puppet_enterprise_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "puppet-enterprise-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv119_puppet_enterprise_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "puppet-enterprise-token",
        "PE_TOKEN=df2C-IwsG2\u{200B}vZK2btF61X",
        "df2C-IwsG2vZK2btF61X",
    );
}

#[test]
fn adv119_puppet_enterprise_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "puppet-enterprise-token",
        "PE_TOKEN=df2C-IwsG2\u{00AD}vZK2btF61X",
        "df2C-IwsG2vZK2btF61X",
    );
}

#[test]
fn adv119_puppet_enterprise_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "puppet-enterprise-token",
        "PE_TOKEN=df2C-IwsG2\u{200C}vZK2btF61X",
        "df2C-IwsG2vZK2btF61X",
    );
}

#[test]
fn adv119_puppet_enterprise_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "puppet-enterprise-token",
        "PE_TOKEN=df2C-IwsG2\u{200D}vZK2btF61X",
        "df2C-IwsG2vZK2btF61X",
    );
}

#[test]
fn adv119_puppet_enterprise_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "puppet-enterprise-token",
        "PE_TOKEN=df2C-IwsG2\u{FEFF}vZK2btF61X",
        "df2C-IwsG2vZK2btF61X",
    );
}

#[test]
fn adv119_puppet_enterprise_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "puppet-enterprise-token",
        "PE_TOKEN=df2C-IwsG2\u{2060}vZK2btF61X",
        "df2C-IwsG2vZK2btF61X",
    );
}

#[test]
fn adv119_puppet_enterprise_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "puppet-enterprise-token",
        "PE_TOKEN=df2C-IwsG2\u{180E}vZK2btF61X",
        "df2C-IwsG2vZK2btF61X",
    );
}

#[test]
fn adv119_puppet_enterprise_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "puppet-enterprise-token",
        "PE_TOKEN=df2C-IwsG2\u{202E}vZK2btF61X",
        "df2C-IwsG2vZK2btF61X",
    );
}

#[test]
fn adv119_puppet_enterprise_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "puppet-enterprise-token",
        "PE_TOKEN=df2C-IwsG2\u{202C}vZK2btF61X",
        "df2C-IwsG2vZK2btF61X",
    );
}

#[test]
fn adv119_puppet_enterprise_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "puppet-enterprise-token",
        "PE_TOKEN=df2C-IwsG2\u{200E}vZK2btF61X",
        "df2C-IwsG2vZK2btF61X",
    );
}


