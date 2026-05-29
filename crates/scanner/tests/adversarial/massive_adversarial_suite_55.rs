//! Part 55 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates practicepanther, prestashop, presto, prisma, private, prometheus, promptlayer, propelauth, pubnub, pubnub detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. PRACTICEPANTHER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv55_practicepanther_api_key_normal_must_fire() {
    assert_detector_fires(
        "practicepanther-api-key",
        "PRACTICEPANTHER_API_KEY=7YyNdbgZbHjVYPyfQSEuWajO7Ei3lyUMx24hMWUY",
        "7YyNdbgZbHjVYPyfQSEuWajO7Ei3lyUMx24hMWUY",
    );
}

#[test]
fn adv55_practicepanther_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "practicepanther-api-key",
        "dummy_prefix_0 =xxxNdbgZbHjVYPyfQSEuWajO7Ei3lyUMx24hMWUY",
    );
}

#[test]
fn adv55_practicepanther_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "practicepanther-api-key",
        "PRACTICEPANTHER_API_KEY=7YyNdbgZbHjVYPyfQSEu\u{200B}WajO7Ei3lyUMx24hMWUY",
        "7YyNdbgZbHjVYPyfQSEuWajO7Ei3lyUMx24hMWUY",
    );
}

#[test]
fn adv55_practicepanther_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "practicepanther-api-key",
        "PRACTICEPANTHER_API_KEY=7YyNdbgZbHjVYPyfQSEu\u{00AD}WajO7Ei3lyUMx24hMWUY",
        "7YyNdbgZbHjVYPyfQSEuWajO7Ei3lyUMx24hMWUY",
    );
}

// =========================================================================
// 2. PRESTASHOP API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv55_prestashop_api_key_normal_must_fire() {
    assert_detector_fires(
        "prestashop-api-key",
        "prestashop=7t5dnTAM6RRaSPjZYCjoE8fkySGigMY0",
        "7t5dnTAM6RRaSPjZYCjoE8fkySGigMY0",
    );
}

#[test]
fn adv55_prestashop_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "prestashop-api-key",
        "dummy_prefix_0 =xxxdnTAM6RRaSPjZYCjoE8fkySGigMY0",
    );
}

#[test]
fn adv55_prestashop_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "prestashop-api-key",
        "prestashop=7t5dnTAM6RRaSPjZ\u{200B}YCjoE8fkySGigMY0",
        "7t5dnTAM6RRaSPjZYCjoE8fkySGigMY0",
    );
}

#[test]
fn adv55_prestashop_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "prestashop-api-key",
        "prestashop=7t5dnTAM6RRaSPjZ\u{00AD}YCjoE8fkySGigMY0",
        "7t5dnTAM6RRaSPjZYCjoE8fkySGigMY0",
    );
}

// =========================================================================
// 3. PRESTO TRINO CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv55_presto_trino_credentials_normal_must_fire() {
    assert_detector_fires(
        "presto-trino-credentials",
        "TRINO_URL=trino://admin:SecretPass123@trino.example.com:8080",
        "SecretPass123",
    );
}

#[test]
fn adv55_presto_trino_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "presto-trino-credentials",
        "dummy_prefix_0 =trino://admin:xxxretPass123@trino.example.com:8080",
    );
}

#[test]
fn adv55_presto_trino_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "presto-trino-credentials",
        "TRINO_URL=trino://admin:Secret\u{200B}Pass123@trino.example.com:8080",
        "SecretPass123",
    );
}

#[test]
fn adv55_presto_trino_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "presto-trino-credentials",
        "TRINO_URL=trino://admin:Secret\u{00AD}Pass123@trino.example.com:8080",
        "SecretPass123",
    );
}

// =========================================================================
// 4. PRISMA CLOUD API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv55_prisma_cloud_api_token_normal_must_fire() {
    assert_detector_fires(
        "prisma-cloud-api-token",
        "PRISMA_API_KEY=eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9KpU33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
        "eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9KpU33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
    );
}

#[test]
fn adv55_prisma_cloud_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "prisma-cloud-api-token",
        "dummy_prefix_0 =xxx1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9KpU33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
    );
}

#[test]
fn adv55_prisma_cloud_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "prisma-cloud-api-token",
        "PRISMA_API_KEY=eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9Kp\u{200B}U33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
        "eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9KpU33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
    );
}

#[test]
fn adv55_prisma_cloud_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "prisma-cloud-api-token",
        "PRISMA_API_KEY=eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9Kp\u{00AD}U33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
        "eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9KpU33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
    );
}

// =========================================================================
// 5. PRIVATE KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv55_private_key_normal_must_fire() {
    assert_detector_fires(
        "private-key",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    );
}

#[test]
fn adv55_private_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "private-key",
        "dummy-BEGIN RSA PRIVATE KEY-----",
    );
}

#[test]
fn adv55_private_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "private-key",
        "-----BEGIN RSA \u{200B}PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    );
}

#[test]
fn adv55_private_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "private-key",
        "-----BEGIN RSA \u{00AD}PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    );
}

// =========================================================================
// 6. PROMETHEUS ALERTMANAGER WEBHOOK ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv55_prometheus_alertmanager_webhook_normal_must_fire() {
    assert_detector_fires(
        "prometheus-alertmanager-webhook",
        "webhook_url=https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgxe8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
        "https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgxe8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
    );
}

#[test]
fn adv55_prometheus_alertmanager_webhook_wrong_prefix_must_silent() {
    assert_detector_silent(
        "prometheus-alertmanager-webhook",
        "dummy_prefix_0 =xxxps://_EAl6PnnHt219ecRFVqmq.KCUwXJEgxe8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
    );
}

#[test]
fn adv55_prometheus_alertmanager_webhook_evade_zwsp_must_fire() {
    assert_detector_fires(
        "prometheus-alertmanager-webhook",
        "webhook_url=https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgx\u{200B}e8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
        "https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgxe8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
    );
}

#[test]
fn adv55_prometheus_alertmanager_webhook_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "prometheus-alertmanager-webhook",
        "webhook_url=https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgx\u{00AD}e8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
        "https://_EAl6PnnHt219ecRFVqmq.KCUwXJEgxe8lSfCNbSuBUhXRem2nao7nKXJrNvv/hooks/Iy",
    );
}

// =========================================================================
// 7. PROMPTLAYER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv55_promptlayer_api_key_normal_must_fire() {
    assert_detector_fires(
        "promptlayer-api-key",
        "pl_OhX5esA2JNCvMTNpyfUbF1xLPsfJUnON",
        "pl_OhX5esA2JNCvMTNpyfUbF1xLPsfJUnON",
    );
}

#[test]
fn adv55_promptlayer_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "promptlayer-api-key",
        "dummyhX5esA2JNCvMTNpyfUbF1xLPsfJUnON",
    );
}

#[test]
fn adv55_promptlayer_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "promptlayer-api-key",
        "pl_OhX5esA2JNCvMT\u{200B}NpyfUbF1xLPsfJUnON",
        "pl_OhX5esA2JNCvMTNpyfUbF1xLPsfJUnON",
    );
}

#[test]
fn adv55_promptlayer_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "promptlayer-api-key",
        "pl_OhX5esA2JNCvMT\u{00AD}NpyfUbF1xLPsfJUnON",
        "pl_OhX5esA2JNCvMTNpyfUbF1xLPsfJUnON",
    );
}

// =========================================================================
// 8. PROPELAUTH API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv55_propelauth_api_key_normal_must_fire() {
    assert_detector_fires(
        "propelauth-api-key",
        "PROPELAUTH_API_KEY=b3265b7c389276d437c18f7c28d04f34",
        "b3265b7c389276d437c18f7c28d04f34",
    );
}

#[test]
fn adv55_propelauth_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "propelauth-api-key",
        "dummy_prefix_0 =xxx65b7c389276d437c18f7c28d04f34",
    );
}

#[test]
fn adv55_propelauth_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "propelauth-api-key",
        "PROPELAUTH_API_KEY=b3265b7c389276d4\u{200B}37c18f7c28d04f34",
        "b3265b7c389276d437c18f7c28d04f34",
    );
}

#[test]
fn adv55_propelauth_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "propelauth-api-key",
        "PROPELAUTH_API_KEY=b3265b7c389276d4\u{00AD}37c18f7c28d04f34",
        "b3265b7c389276d437c18f7c28d04f34",
    );
}

// =========================================================================
// 9. PUBNUB PUBLISH KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv55_pubnub_publish_key_normal_must_fire() {
    assert_detector_fires(
        "pubnub-publish-key",
        "pub-c-d0743bdf-c3fe-a88e-492a-0ccb2ea13ddc",
        "pub-c-d0743bdf-c3fe-a88e-492a-0ccb2ea13ddc",
    );
}

#[test]
fn adv55_pubnub_publish_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pubnub-publish-key",
        "dummyc-d0743bdf-c3fe-a88e-492a-0ccb2ea13ddc",
    );
}

#[test]
fn adv55_pubnub_publish_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pubnub-publish-key",
        "pub-c-d0743bdf-c3fe-a\u{200B}88e-492a-0ccb2ea13ddc",
        "pub-c-d0743bdf-c3fe-a88e-492a-0ccb2ea13ddc",
    );
}

#[test]
fn adv55_pubnub_publish_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pubnub-publish-key",
        "pub-c-d0743bdf-c3fe-a\u{00AD}88e-492a-0ccb2ea13ddc",
        "pub-c-d0743bdf-c3fe-a88e-492a-0ccb2ea13ddc",
    );
}

// =========================================================================
// 10. PUBNUB SUBSCRIBE KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv55_pubnub_subscribe_key_normal_must_fire() {
    assert_detector_fires(
        "pubnub-subscribe-key",
        "sub-c-b424e2b7-3480-5c69-2564-52b5fde37b98",
        "sub-c-b424e2b7-3480-5c69-2564-52b5fde37b98",
    );
}

#[test]
fn adv55_pubnub_subscribe_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pubnub-subscribe-key",
        "dummyc-b424e2b7-3480-5c69-2564-52b5fde37b98",
    );
}

#[test]
fn adv55_pubnub_subscribe_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pubnub-subscribe-key",
        "sub-c-b424e2b7-3480-5\u{200B}c69-2564-52b5fde37b98",
        "sub-c-b424e2b7-3480-5c69-2564-52b5fde37b98",
    );
}

#[test]
fn adv55_pubnub_subscribe_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pubnub-subscribe-key",
        "sub-c-b424e2b7-3480-5\u{00AD}c69-2564-52b5fde37b98",
        "sub-c-b424e2b7-3480-5c69-2564-52b5fde37b98",
    );
}


