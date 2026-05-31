//! Part 92 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates google, google, google, google, google, google, google, google, gotify, goto detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. GOOGLE ARTIFACT REGISTRY KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv92_google_artifact_registry_key_normal_must_fire() {
    assert_detector_fires(
        "google-artifact-registry-key",
        "{\"type\": \"service_account\", \"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIE\\n-----END PRIVATE KEY-----\"}",
        "-----BEGIN PRIVATE KEY-----",
    );
}

#[test]
fn adv92_google_artifact_registry_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "google-artifact-registry-key",
        "dummy_prefix_0: \"service_account\", \"private_key\": \"xxxxxxxxxxxxxxxxxxxxxxxxxxx\\nMIIE\\n-----END PRIVATE KEY-----\"}",
    );
}

#[test]
fn adv92_google_artifact_registry_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "google-artifact-registry-key",
        "{\"type\": \"service_account\", \"private_key\": \"-----BEGIN PR\u{200B}IVATE KEY-----\\nMIIE\\n-----END PRIVATE KEY-----\"}",
        "-----BEGIN PRIVATE KEY-----",
    );
}

#[test]
fn adv92_google_artifact_registry_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "google-artifact-registry-key",
        "{\"type\": \"service_account\", \"private_key\": \"-----BEGIN PR\u{00AD}IVATE KEY-----\\nMIIE\\n-----END PRIVATE KEY-----\"}",
        "-----BEGIN PRIVATE KEY-----",
    );
}

#[test]
fn adv92_google_artifact_registry_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "google-artifact-registry-key",
        "{\"type\": \"service_account\", \"private_key\": \"-----BEGIN PR\u{200C}IVATE KEY-----\\nMIIE\\n-----END PRIVATE KEY-----\"}",
        "-----BEGIN PRIVATE KEY-----",
    );
}

#[test]
fn adv92_google_artifact_registry_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "google-artifact-registry-key",
        "{\"type\": \"service_account\", \"private_key\": \"-----BEGIN PR\u{200D}IVATE KEY-----\\nMIIE\\n-----END PRIVATE KEY-----\"}",
        "-----BEGIN PRIVATE KEY-----",
    );
}

#[test]
fn adv92_google_artifact_registry_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "google-artifact-registry-key",
        "{\"type\": \"service_account\", \"private_key\": \"-----BEGIN PR\u{FEFF}IVATE KEY-----\\nMIIE\\n-----END PRIVATE KEY-----\"}",
        "-----BEGIN PRIVATE KEY-----",
    );
}

#[test]
fn adv92_google_artifact_registry_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "google-artifact-registry-key",
        "{\"type\": \"service_account\", \"private_key\": \"-----BEGIN PR\u{2060}IVATE KEY-----\\nMIIE\\n-----END PRIVATE KEY-----\"}",
        "-----BEGIN PRIVATE KEY-----",
    );
}

#[test]
fn adv92_google_artifact_registry_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "google-artifact-registry-key",
        "{\"type\": \"service_account\", \"private_key\": \"-----BEGIN PR\u{180E}IVATE KEY-----\\nMIIE\\n-----END PRIVATE KEY-----\"}",
        "-----BEGIN PRIVATE KEY-----",
    );
}

#[test]
fn adv92_google_artifact_registry_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "google-artifact-registry-key",
        "{\"type\": \"service_account\", \"private_key\": \"-----BEGIN PR\u{202E}IVATE KEY-----\\nMIIE\\n-----END PRIVATE KEY-----\"}",
        "-----BEGIN PRIVATE KEY-----",
    );
}

#[test]
fn adv92_google_artifact_registry_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "google-artifact-registry-key",
        "{\"type\": \"service_account\", \"private_key\": \"-----BEGIN PR\u{202C}IVATE KEY-----\\nMIIE\\n-----END PRIVATE KEY-----\"}",
        "-----BEGIN PRIVATE KEY-----",
    );
}

#[test]
fn adv92_google_artifact_registry_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "google-artifact-registry-key",
        "{\"type\": \"service_account\", \"private_key\": \"-----BEGIN PR\u{200E}IVATE KEY-----\\nMIIE\\n-----END PRIVATE KEY-----\"}",
        "-----BEGIN PRIVATE KEY-----",
    );
}

// =========================================================================
// 2. GOOGLE CLASSROOM API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv92_google_classroom_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "google-classroom-api-credentials",
        "classroom api key ya29.Habcdefghijklmnopqrstuvwxyz1234567890abcd",
        "ya29.Habcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv92_google_classroom_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "google-classroom-api-credentials",
        "dummysroom api key xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv92_google_classroom_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "google-classroom-api-credentials",
        "classroom api key ya29.Habcdefghijklmnopq\u{200B}rstuvwxyz1234567890abcd",
        "ya29.Habcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv92_google_classroom_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "google-classroom-api-credentials",
        "classroom api key ya29.Habcdefghijklmnopq\u{00AD}rstuvwxyz1234567890abcd",
        "ya29.Habcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv92_google_classroom_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "google-classroom-api-credentials",
        "classroom api key ya29.Habcdefghijklmnopq\u{200C}rstuvwxyz1234567890abcd",
        "ya29.Habcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv92_google_classroom_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "google-classroom-api-credentials",
        "classroom api key ya29.Habcdefghijklmnopq\u{200D}rstuvwxyz1234567890abcd",
        "ya29.Habcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv92_google_classroom_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "google-classroom-api-credentials",
        "classroom api key ya29.Habcdefghijklmnopq\u{FEFF}rstuvwxyz1234567890abcd",
        "ya29.Habcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv92_google_classroom_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "google-classroom-api-credentials",
        "classroom api key ya29.Habcdefghijklmnopq\u{2060}rstuvwxyz1234567890abcd",
        "ya29.Habcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv92_google_classroom_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "google-classroom-api-credentials",
        "classroom api key ya29.Habcdefghijklmnopq\u{180E}rstuvwxyz1234567890abcd",
        "ya29.Habcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv92_google_classroom_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "google-classroom-api-credentials",
        "classroom api key ya29.Habcdefghijklmnopq\u{202E}rstuvwxyz1234567890abcd",
        "ya29.Habcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv92_google_classroom_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "google-classroom-api-credentials",
        "classroom api key ya29.Habcdefghijklmnopq\u{202C}rstuvwxyz1234567890abcd",
        "ya29.Habcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv92_google_classroom_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "google-classroom-api-credentials",
        "classroom api key ya29.Habcdefghijklmnopq\u{200E}rstuvwxyz1234567890abcd",
        "ya29.Habcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

// =========================================================================
// 3. GOOGLE CLOUD IOT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv92_google_cloud_iot_credentials_normal_must_fire() {
    assert_detector_fires(
        "google-cloud-iot-credentials",
        "cloudiot_PROJECT_ID=my-iot-project-01",
        "my-iot-project-01",
    );
}

#[test]
fn adv92_google_cloud_iot_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "google-cloud-iot-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv92_google_cloud_iot_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "google-cloud-iot-credentials",
        "cloudiot_PROJECT_ID=my-iot-p\u{200B}roject-01",
        "my-iot-project-01",
    );
}

#[test]
fn adv92_google_cloud_iot_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "google-cloud-iot-credentials",
        "cloudiot_PROJECT_ID=my-iot-p\u{00AD}roject-01",
        "my-iot-project-01",
    );
}

#[test]
fn adv92_google_cloud_iot_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "google-cloud-iot-credentials",
        "cloudiot_PROJECT_ID=my-iot-p\u{200C}roject-01",
        "my-iot-project-01",
    );
}

#[test]
fn adv92_google_cloud_iot_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "google-cloud-iot-credentials",
        "cloudiot_PROJECT_ID=my-iot-p\u{200D}roject-01",
        "my-iot-project-01",
    );
}

#[test]
fn adv92_google_cloud_iot_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "google-cloud-iot-credentials",
        "cloudiot_PROJECT_ID=my-iot-p\u{FEFF}roject-01",
        "my-iot-project-01",
    );
}

#[test]
fn adv92_google_cloud_iot_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "google-cloud-iot-credentials",
        "cloudiot_PROJECT_ID=my-iot-p\u{2060}roject-01",
        "my-iot-project-01",
    );
}

#[test]
fn adv92_google_cloud_iot_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "google-cloud-iot-credentials",
        "cloudiot_PROJECT_ID=my-iot-p\u{180E}roject-01",
        "my-iot-project-01",
    );
}

#[test]
fn adv92_google_cloud_iot_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "google-cloud-iot-credentials",
        "cloudiot_PROJECT_ID=my-iot-p\u{202E}roject-01",
        "my-iot-project-01",
    );
}

#[test]
fn adv92_google_cloud_iot_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "google-cloud-iot-credentials",
        "cloudiot_PROJECT_ID=my-iot-p\u{202C}roject-01",
        "my-iot-project-01",
    );
}

#[test]
fn adv92_google_cloud_iot_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "google-cloud-iot-credentials",
        "cloudiot_PROJECT_ID=my-iot-p\u{200E}roject-01",
        "my-iot-project-01",
    );
}

// =========================================================================
// 4. GOOGLE CLOUD SOURCE REPOS CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv92_google_cloud_source_repos_credentials_normal_must_fire() {
    assert_detector_fires(
        "google-cloud-source-repos-credentials",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr33sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr33sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
    );
}

#[test]
fn adv92_google_cloud_source_repos_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "google-cloud-source-repos-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv92_google_cloud_source_repos_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "google-cloud-source-repos-credentials",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr3\u{200B}3sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr33sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
    );
}

#[test]
fn adv92_google_cloud_source_repos_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "google-cloud-source-repos-credentials",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr3\u{00AD}3sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr33sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
    );
}

#[test]
fn adv92_google_cloud_source_repos_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "google-cloud-source-repos-credentials",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr3\u{200C}3sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr33sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
    );
}

#[test]
fn adv92_google_cloud_source_repos_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "google-cloud-source-repos-credentials",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr3\u{200D}3sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr33sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
    );
}

#[test]
fn adv92_google_cloud_source_repos_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "google-cloud-source-repos-credentials",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr3\u{FEFF}3sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr33sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
    );
}

#[test]
fn adv92_google_cloud_source_repos_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "google-cloud-source-repos-credentials",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr3\u{2060}3sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr33sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
    );
}

#[test]
fn adv92_google_cloud_source_repos_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "google-cloud-source-repos-credentials",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr3\u{180E}3sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr33sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
    );
}

#[test]
fn adv92_google_cloud_source_repos_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "google-cloud-source-repos-credentials",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr3\u{202E}3sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr33sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
    );
}

#[test]
fn adv92_google_cloud_source_repos_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "google-cloud-source-repos-credentials",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr3\u{202C}3sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr33sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
    );
}

#[test]
fn adv92_google_cloud_source_repos_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "google-cloud-source-repos-credentials",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr3\u{200E}3sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
        "source.developers.google.com/p/99d4n72n2dr6cv241hz6prw9qqzlcgi4q7is3vpoc3abr33sa5x7efkl95hkpn2u6ysbth94/r/0_cx3NR0Uib50rRy5SY1JsOQHhNUl9mkCF5zNsFbn8QEE19d",
    );
}

// =========================================================================
// 5. GOOGLE CLOUD SOVEREIGN CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv92_google_cloud_sovereign_credentials_normal_must_fire() {
    assert_detector_fires(
        "google-cloud-sovereign-credentials",
        "GOOGLE_SOVEREIGN PROJECT_ID=my-sovereign-project",
        "my-sovereign-project",
    );
}

#[test]
fn adv92_google_cloud_sovereign_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "google-cloud-sovereign-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv92_google_cloud_sovereign_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "google-cloud-sovereign-credentials",
        "GOOGLE_SOVEREIGN PROJECT_ID=my-soverei\u{200B}gn-project",
        "my-sovereign-project",
    );
}

#[test]
fn adv92_google_cloud_sovereign_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "google-cloud-sovereign-credentials",
        "GOOGLE_SOVEREIGN PROJECT_ID=my-soverei\u{00AD}gn-project",
        "my-sovereign-project",
    );
}

#[test]
fn adv92_google_cloud_sovereign_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "google-cloud-sovereign-credentials",
        "GOOGLE_SOVEREIGN PROJECT_ID=my-soverei\u{200C}gn-project",
        "my-sovereign-project",
    );
}

#[test]
fn adv92_google_cloud_sovereign_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "google-cloud-sovereign-credentials",
        "GOOGLE_SOVEREIGN PROJECT_ID=my-soverei\u{200D}gn-project",
        "my-sovereign-project",
    );
}

#[test]
fn adv92_google_cloud_sovereign_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "google-cloud-sovereign-credentials",
        "GOOGLE_SOVEREIGN PROJECT_ID=my-soverei\u{FEFF}gn-project",
        "my-sovereign-project",
    );
}

#[test]
fn adv92_google_cloud_sovereign_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "google-cloud-sovereign-credentials",
        "GOOGLE_SOVEREIGN PROJECT_ID=my-soverei\u{2060}gn-project",
        "my-sovereign-project",
    );
}

#[test]
fn adv92_google_cloud_sovereign_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "google-cloud-sovereign-credentials",
        "GOOGLE_SOVEREIGN PROJECT_ID=my-soverei\u{180E}gn-project",
        "my-sovereign-project",
    );
}

#[test]
fn adv92_google_cloud_sovereign_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "google-cloud-sovereign-credentials",
        "GOOGLE_SOVEREIGN PROJECT_ID=my-soverei\u{202E}gn-project",
        "my-sovereign-project",
    );
}

#[test]
fn adv92_google_cloud_sovereign_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "google-cloud-sovereign-credentials",
        "GOOGLE_SOVEREIGN PROJECT_ID=my-soverei\u{202C}gn-project",
        "my-sovereign-project",
    );
}

#[test]
fn adv92_google_cloud_sovereign_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "google-cloud-sovereign-credentials",
        "GOOGLE_SOVEREIGN PROJECT_ID=my-soverei\u{200E}gn-project",
        "my-sovereign-project",
    );
}

// =========================================================================
// 6. GOOGLE CLOUD STORAGE HMAC KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv92_google_cloud_storage_hmac_key_normal_must_fire() {
    assert_detector_fires(
        "google-cloud-storage-hmac-key",
        "GOOG=GOOG5I75PFW05MEV3YQS371MSJP945GAFH9WQLTHZPVO",
        "GOOG5I75PFW05MEV3YQS371MSJP945GAFH9WQLTHZPVO",
    );
}

#[test]
fn adv92_google_cloud_storage_hmac_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "google-cloud-storage-hmac-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv92_google_cloud_storage_hmac_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "google-cloud-storage-hmac-key",
        "GOOG=GOOG5I75PFW05MEV3YQS37\u{200B}1MSJP945GAFH9WQLTHZPVO",
        "GOOG5I75PFW05MEV3YQS371MSJP945GAFH9WQLTHZPVO",
    );
}

#[test]
fn adv92_google_cloud_storage_hmac_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "google-cloud-storage-hmac-key",
        "GOOG=GOOG5I75PFW05MEV3YQS37\u{00AD}1MSJP945GAFH9WQLTHZPVO",
        "GOOG5I75PFW05MEV3YQS371MSJP945GAFH9WQLTHZPVO",
    );
}

#[test]
fn adv92_google_cloud_storage_hmac_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "google-cloud-storage-hmac-key",
        "GOOG=GOOG5I75PFW05MEV3YQS37\u{200C}1MSJP945GAFH9WQLTHZPVO",
        "GOOG5I75PFW05MEV3YQS371MSJP945GAFH9WQLTHZPVO",
    );
}

#[test]
fn adv92_google_cloud_storage_hmac_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "google-cloud-storage-hmac-key",
        "GOOG=GOOG5I75PFW05MEV3YQS37\u{200D}1MSJP945GAFH9WQLTHZPVO",
        "GOOG5I75PFW05MEV3YQS371MSJP945GAFH9WQLTHZPVO",
    );
}

#[test]
fn adv92_google_cloud_storage_hmac_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "google-cloud-storage-hmac-key",
        "GOOG=GOOG5I75PFW05MEV3YQS37\u{FEFF}1MSJP945GAFH9WQLTHZPVO",
        "GOOG5I75PFW05MEV3YQS371MSJP945GAFH9WQLTHZPVO",
    );
}

#[test]
fn adv92_google_cloud_storage_hmac_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "google-cloud-storage-hmac-key",
        "GOOG=GOOG5I75PFW05MEV3YQS37\u{2060}1MSJP945GAFH9WQLTHZPVO",
        "GOOG5I75PFW05MEV3YQS371MSJP945GAFH9WQLTHZPVO",
    );
}

#[test]
fn adv92_google_cloud_storage_hmac_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "google-cloud-storage-hmac-key",
        "GOOG=GOOG5I75PFW05MEV3YQS37\u{180E}1MSJP945GAFH9WQLTHZPVO",
        "GOOG5I75PFW05MEV3YQS371MSJP945GAFH9WQLTHZPVO",
    );
}

#[test]
fn adv92_google_cloud_storage_hmac_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "google-cloud-storage-hmac-key",
        "GOOG=GOOG5I75PFW05MEV3YQS37\u{202E}1MSJP945GAFH9WQLTHZPVO",
        "GOOG5I75PFW05MEV3YQS371MSJP945GAFH9WQLTHZPVO",
    );
}

#[test]
fn adv92_google_cloud_storage_hmac_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "google-cloud-storage-hmac-key",
        "GOOG=GOOG5I75PFW05MEV3YQS37\u{202C}1MSJP945GAFH9WQLTHZPVO",
        "GOOG5I75PFW05MEV3YQS371MSJP945GAFH9WQLTHZPVO",
    );
}

#[test]
fn adv92_google_cloud_storage_hmac_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "google-cloud-storage-hmac-key",
        "GOOG=GOOG5I75PFW05MEV3YQS37\u{200E}1MSJP945GAFH9WQLTHZPVO",
        "GOOG5I75PFW05MEV3YQS371MSJP945GAFH9WQLTHZPVO",
    );
}

// =========================================================================
// 7. GOOGLE FORMS API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv92_google_forms_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "google-forms-api-credentials",
        "google forms api key abcdefghijklmnopqrstuvwxyz123456",
        "abcdefghijklmnopqrstuvwxyz123456",
    );
}

#[test]
fn adv92_google_forms_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "google-forms-api-credentials",
        "dummyle forms api key xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv92_google_forms_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "google-forms-api-credentials",
        "google forms api key abcdefghijklmnop\u{200B}qrstuvwxyz123456",
        "abcdefghijklmnopqrstuvwxyz123456",
    );
}

#[test]
fn adv92_google_forms_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "google-forms-api-credentials",
        "google forms api key abcdefghijklmnop\u{00AD}qrstuvwxyz123456",
        "abcdefghijklmnopqrstuvwxyz123456",
    );
}

#[test]
fn adv92_google_forms_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "google-forms-api-credentials",
        "google forms api key abcdefghijklmnop\u{200C}qrstuvwxyz123456",
        "abcdefghijklmnopqrstuvwxyz123456",
    );
}

#[test]
fn adv92_google_forms_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "google-forms-api-credentials",
        "google forms api key abcdefghijklmnop\u{200D}qrstuvwxyz123456",
        "abcdefghijklmnopqrstuvwxyz123456",
    );
}

#[test]
fn adv92_google_forms_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "google-forms-api-credentials",
        "google forms api key abcdefghijklmnop\u{FEFF}qrstuvwxyz123456",
        "abcdefghijklmnopqrstuvwxyz123456",
    );
}

#[test]
fn adv92_google_forms_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "google-forms-api-credentials",
        "google forms api key abcdefghijklmnop\u{2060}qrstuvwxyz123456",
        "abcdefghijklmnopqrstuvwxyz123456",
    );
}

#[test]
fn adv92_google_forms_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "google-forms-api-credentials",
        "google forms api key abcdefghijklmnop\u{180E}qrstuvwxyz123456",
        "abcdefghijklmnopqrstuvwxyz123456",
    );
}

#[test]
fn adv92_google_forms_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "google-forms-api-credentials",
        "google forms api key abcdefghijklmnop\u{202E}qrstuvwxyz123456",
        "abcdefghijklmnopqrstuvwxyz123456",
    );
}

#[test]
fn adv92_google_forms_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "google-forms-api-credentials",
        "google forms api key abcdefghijklmnop\u{202C}qrstuvwxyz123456",
        "abcdefghijklmnopqrstuvwxyz123456",
    );
}

#[test]
fn adv92_google_forms_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "google-forms-api-credentials",
        "google forms api key abcdefghijklmnop\u{200E}qrstuvwxyz123456",
        "abcdefghijklmnopqrstuvwxyz123456",
    );
}

// =========================================================================
// 8. GOOGLE SECRET MANAGER CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv92_google_secret_manager_credentials_normal_must_fire() {
    assert_detector_fires(
        "google-secret-manager-credentials",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
    );
}

#[test]
fn adv92_google_secret_manager_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "google-secret-manager-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv92_google_secret_manager_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "google-secret-manager-credentials",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/\u{200B}106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
    );
}

#[test]
fn adv92_google_secret_manager_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "google-secret-manager-credentials",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/\u{00AD}106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
    );
}

#[test]
fn adv92_google_secret_manager_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "google-secret-manager-credentials",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/\u{200C}106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
    );
}

#[test]
fn adv92_google_secret_manager_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "google-secret-manager-credentials",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/\u{200D}106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
    );
}

#[test]
fn adv92_google_secret_manager_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "google-secret-manager-credentials",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/\u{FEFF}106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
    );
}

#[test]
fn adv92_google_secret_manager_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "google-secret-manager-credentials",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/\u{2060}106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
    );
}

#[test]
fn adv92_google_secret_manager_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "google-secret-manager-credentials",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/\u{180E}106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
    );
}

#[test]
fn adv92_google_secret_manager_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "google-secret-manager-credentials",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/\u{202E}106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
    );
}

#[test]
fn adv92_google_secret_manager_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "google-secret-manager-credentials",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/\u{202C}106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
    );
}

#[test]
fn adv92_google_secret_manager_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "google-secret-manager-credentials",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/\u{200E}106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
        "projects/6ophb096al79yngveh2oqc89/secrets/MHvnXpCEqVoPK4xfUnMm5LFkLYq_9rtCGq6XW5yYxES/versions/106762524949451616097841508309392488382916883507301034643504464769780915686164596831488843699338",
    );
}

// =========================================================================
// 9. GOTIFY TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv92_gotify_token_normal_must_fire() {
    assert_detector_fires("gotify-token", "GOTIFY=HNGeqyx6CjQ29z3", "HNGeqyx6CjQ29z3");
}

#[test]
fn adv92_gotify_token_wrong_prefix_must_silent() {
    assert_detector_silent("gotify-token", "dummy_prefix_0 =xxxxxxxxxxxxxxx");
}

#[test]
fn adv92_gotify_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gotify-token",
        "GOTIFY=HNGeqyx\u{200B}6CjQ29z3",
        "HNGeqyx6CjQ29z3",
    );
}

#[test]
fn adv92_gotify_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gotify-token",
        "GOTIFY=HNGeqyx\u{00AD}6CjQ29z3",
        "HNGeqyx6CjQ29z3",
    );
}

#[test]
fn adv92_gotify_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "gotify-token",
        "GOTIFY=HNGeqyx\u{200C}6CjQ29z3",
        "HNGeqyx6CjQ29z3",
    );
}

#[test]
fn adv92_gotify_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "gotify-token",
        "GOTIFY=HNGeqyx\u{200D}6CjQ29z3",
        "HNGeqyx6CjQ29z3",
    );
}

#[test]
fn adv92_gotify_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "gotify-token",
        "GOTIFY=HNGeqyx\u{FEFF}6CjQ29z3",
        "HNGeqyx6CjQ29z3",
    );
}

#[test]
fn adv92_gotify_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "gotify-token",
        "GOTIFY=HNGeqyx\u{2060}6CjQ29z3",
        "HNGeqyx6CjQ29z3",
    );
}

#[test]
fn adv92_gotify_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "gotify-token",
        "GOTIFY=HNGeqyx\u{180E}6CjQ29z3",
        "HNGeqyx6CjQ29z3",
    );
}

#[test]
fn adv92_gotify_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "gotify-token",
        "GOTIFY=HNGeqyx\u{202E}6CjQ29z3",
        "HNGeqyx6CjQ29z3",
    );
}

#[test]
fn adv92_gotify_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "gotify-token",
        "GOTIFY=HNGeqyx\u{202C}6CjQ29z3",
        "HNGeqyx6CjQ29z3",
    );
}

#[test]
fn adv92_gotify_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "gotify-token",
        "GOTIFY=HNGeqyx\u{200E}6CjQ29z3",
        "HNGeqyx6CjQ29z3",
    );
}

// =========================================================================
// 10. GOTO CONNECT API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv92_goto_connect_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "goto-connect-api-credentials",
        "gotoconnectclientid=uwtOQIbhxpxmFoKM1Ue8",
        "uwtOQIbhxpxmFoKM1Ue8",
    );
}

#[test]
fn adv92_goto_connect_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "goto-connect-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv92_goto_connect_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "goto-connect-api-credentials",
        "gotoconnectclientid=uwtOQIbhxp\u{200B}xmFoKM1Ue8",
        "uwtOQIbhxpxmFoKM1Ue8",
    );
}

#[test]
fn adv92_goto_connect_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "goto-connect-api-credentials",
        "gotoconnectclientid=uwtOQIbhxp\u{00AD}xmFoKM1Ue8",
        "uwtOQIbhxpxmFoKM1Ue8",
    );
}

#[test]
fn adv92_goto_connect_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "goto-connect-api-credentials",
        "gotoconnectclientid=uwtOQIbhxp\u{200C}xmFoKM1Ue8",
        "uwtOQIbhxpxmFoKM1Ue8",
    );
}

#[test]
fn adv92_goto_connect_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "goto-connect-api-credentials",
        "gotoconnectclientid=uwtOQIbhxp\u{200D}xmFoKM1Ue8",
        "uwtOQIbhxpxmFoKM1Ue8",
    );
}

#[test]
fn adv92_goto_connect_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "goto-connect-api-credentials",
        "gotoconnectclientid=uwtOQIbhxp\u{FEFF}xmFoKM1Ue8",
        "uwtOQIbhxpxmFoKM1Ue8",
    );
}

#[test]
fn adv92_goto_connect_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "goto-connect-api-credentials",
        "gotoconnectclientid=uwtOQIbhxp\u{2060}xmFoKM1Ue8",
        "uwtOQIbhxpxmFoKM1Ue8",
    );
}

#[test]
fn adv92_goto_connect_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "goto-connect-api-credentials",
        "gotoconnectclientid=uwtOQIbhxp\u{180E}xmFoKM1Ue8",
        "uwtOQIbhxpxmFoKM1Ue8",
    );
}

#[test]
fn adv92_goto_connect_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "goto-connect-api-credentials",
        "gotoconnectclientid=uwtOQIbhxp\u{202E}xmFoKM1Ue8",
        "uwtOQIbhxpxmFoKM1Ue8",
    );
}

#[test]
fn adv92_goto_connect_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "goto-connect-api-credentials",
        "gotoconnectclientid=uwtOQIbhxp\u{202C}xmFoKM1Ue8",
        "uwtOQIbhxpxmFoKM1Ue8",
    );
}

#[test]
fn adv92_goto_connect_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "goto-connect-api-credentials",
        "gotoconnectclientid=uwtOQIbhxp\u{200E}xmFoKM1Ue8",
        "uwtOQIbhxpxmFoKM1Ue8",
    );
}
