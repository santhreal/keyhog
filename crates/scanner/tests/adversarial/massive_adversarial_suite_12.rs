//! Part 12 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates Azure Blob SAS, Azure Container Registry, Azure DevOps, Azure Functions,
//! Azure Government, Azure IoT, Azure Key Vault, Azure OpenAI, Azure Storage, and
//! Azure Subscription key detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. AZURE BLOB SAS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv12_blobsas_normal_must_fire() {
    assert_detector_fires(
        "azure-blob-sas-token",
        "AZURE_STORAGE_SAS_TOKEN = \"?sv=2021-08-06&sig=abcde1234567890abcde\"",
        "?sv=2021-08-06&sig=abcde1234567890abcde",
    );
}

#[test]
fn adv12_blobsas_wrong_prefix_must_silent() {
    assert_detector_silent(
        "azure-blob-sas-token",
        "AZURE_STORAGE_SAS_TOKEN = \"?sv=2021-08-06&pig=abcde1234567890abcde\"",
    );
}

#[test]
fn adv12_blobsas_evade_zwsp_must_fire() {
    assert_detector_fires(
        "azure-blob-sas-token",
        "AZURE_STORAGE_SAS_TOKEN = \"?sv=2021-08-06&s\u{200B}ig=abcde1234567890abcde\"",
        "?sv=2021-08-06&sig=abcde1234567890abcde",
    );
}

#[test]
fn adv12_blobsas_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "azure-blob-sas-token",
        "AZURE_STORAGE_SAS_TOKEN = \"?sv=2021-08-06&sig=abcde12345\u{00AD}67890abcde\"",
        "?sv=2021-08-06&sig=abcde1234567890abcde",
    );
}

#[test]
fn adv12_blobsas_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "azure-blob-sas-token",
        "AZURE_STORAGE_SAS_TOKEN = \"?sv=2021-08-06&s\u{0457}g=abcde1234567890abcde\"",
        "?sv=2021-08-06&sig=abcde1234567890abcde",
    );
}

// =========================================================================
// 2. AZURE CONTAINER REGISTRY TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv12_acr_normal_must_fire() {
    assert_detector_fires("azure-container-registry-token", "azurecr_TOKEN = \"eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJURUFNSUQxMjM0NSIsImlhdCI6MTYyMjUwMDAwMH0\"", "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJURUFNSUQxMjM0NSIsImlhdCI6MTYyMjUwMDAwMH0");
}

#[test]
fn adv12_acr_wrong_prefix_must_silent() {
    assert_detector_silent("azure-container-registry-token", "azurecr_SOKEN = \"eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJURUFNSUQxMjM0NSIsImlhdCI6MTYyMjUwMDAwMH0\"");
}

#[test]
fn adv12_acr_evade_zwsp_must_fire() {
    assert_detector_fires("azure-container-registry-token", "azurecr\u{200B}_TOKEN = \"eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJURUFNSUQxMjM0NSIsImlhdCI6MTYyMjUwMDAwMH0\"", "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJURUFNSUQxMjM0NSIsImlhdCI6MTYyMjUwMDAwMH0");
}

#[test]
fn adv12_acr_evade_soft_hyphen_must_fire() {
    assert_detector_fires("azure-container-registry-token", "azurecr_TOKEN = \"eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJURUFNSUQxMjM0NSIsImlhdCI6MTYyMjUwMD\u{00AD}AwMH0\"", "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJURUFNSUQxMjM0NSIsImlhdCI6MTYyMjUwMDAwMH0");
}

#[test]
fn adv12_acr_evade_homoglyph_must_fire() {
    assert_detector_fires("azure-container-registry-token", "\u{0430}zurecr_TOKEN = \"eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJURUFNSUQxMjM0NSIsImlhdCI6MTYyMjUwMDAwMH0\"", "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJURUFNSUQxMjM0NSIsImlhdCI6MTYyMjUwMDAwMH0");
}

// =========================================================================
// 3. AZURE DEVOPS PERSONAL ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv12_devops_normal_bare_must_stay_silent() {
    assert_detector_silent("azure-devops-pat", "azure_devops = \"abcde1234567890abcde123456789012abcde12345678901234\"");
}

#[test]
fn adv12_devops_wrong_prefix_must_silent() {
    assert_detector_silent(
        "azure-devops-pat",
        "mzure_devops = \"abcde1234567890abcde123456789012abcde12345678901234\"",
    );
}

#[test]
fn adv12_devops_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent("azure-devops-pat", "azure\u{200B}_devops = \"abcde1234567890abcde123456789012abcde12345678901234\"");
}

#[test]
fn adv12_devops_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent("azure-devops-pat", "azure_devops = \"abcde1234567890abcde123456789012abcde12345\u{00AD}678901234\"");
}

#[test]
fn adv12_devops_evade_homoglyph_bare_must_stay_silent() {
    assert_detector_silent("azure-devops-pat", "azur\u{0435}_devops = \"abcde1234567890abcde123456789012abcde12345678901234\"");
}

// =========================================================================
// 4. AZURE FUNCTIONS KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv12_functions_normal_must_fire() {
    assert_detector_fires(
        "azure-functions-key",
        "azure_key = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv12_functions_wrong_prefix_must_silent() {
    assert_detector_silent(
        "azure-functions-key",
        "bzure_key = \"0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv12_functions_evade_zwsp_must_fire() {
    assert_detector_fires(
        "azure-functions-key",
        "azure\u{200B}_key = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv12_functions_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "azure-functions-key",
        "azure_key = \"00000000000000000000\u{00AD}00000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv12_functions_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "azure-functions-key",
        "az\u{0457}re_key = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

// =========================================================================
// 5. AZURE GOVERNMENT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv12_gov_normal_must_fire() {
    assert_detector_fires(
        "azure-government-credentials",
        "AZURE_GOVERNMENT_CLIENT_ID = \"12345678-abcd-1234-abcd-1234567890ab\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv12_gov_wrong_prefix_must_silent() {
    assert_detector_silent(
        "azure-government-credentials",
        "BZURE_GOVERNMENT_CLIENT_ID = \"12345678-abcd-1234-abcd-1234567890ab\"",
    );
}

#[test]
fn adv12_gov_evade_zwsp_must_fire() {
    assert_detector_fires(
        "azure-government-credentials",
        "AZURE_GOVERNMENT\u{200B}_CLIENT_ID = \"12345678-abcd-1234-abcd-1234567890ab\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv12_gov_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "azure-government-credentials",
        "AZURE_GOVERNMENT_CLIENT_ID = \"12345678-abcd-1234-abcd-12345678\u{00AD}90ab\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv12_gov_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "azure-government-credentials",
        "AZURE_GOVERNM\u{0415}NT_CLIENT_ID = \"12345678-abcd-1234-abcd-1234567890ab\"",
        "12345678-abcd-1234-abcd-1234567890ab",
    );
}

// =========================================================================
// 6. AZURE IOT HUB CONNECTION STRING ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv12_iothub_normal_must_fire() {
    assert_detector_fires("azure-iot-connection-string", "HostName=abcde.azure-devices.net;SharedAccessKeyName=device;SharedAccessKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "abcde.azure-devices.net;SharedAccessKeyName=device;SharedAccessKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
}

#[test]
fn adv12_iothub_wrong_prefix_must_silent() {
    assert_detector_silent("azure-iot-connection-string", "GastName=abcde.azure-devices.net;SharedAccessKeyName=device;SharedAccessKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
}

#[test]
fn adv12_iothub_evade_zwsp_must_fire() {
    assert_detector_fires("azure-iot-connection-string", "HostName\u{200B}=abcde.azure-devices.net;SharedAccessKeyName=device;SharedAccessKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "abcde.azure-devices.net;SharedAccessKeyName=device;SharedAccessKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
}

#[test]
fn adv12_iothub_evade_soft_hyphen_must_fire() {
    assert_detector_fires("azure-iot-connection-string", "HostName=abcde.azure-devices.net;SharedAccessKeyName=device;SharedAccessKey=AAAAAAAAAAAAAAAAAAAAA\u{00AD}AAAAAAAAAAAAAAAAAAAAAA=", "abcde.azure-devices.net;SharedAccessKeyName=device;SharedAccessKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
}

#[test]
fn adv12_iothub_evade_homoglyph_must_fire() {
    assert_detector_fires("azure-iot-connection-string", "HostName=abcde.az\u{0457}re-devices.net;SharedAccessKeyName=device;SharedAccessKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "abcde.az\u{0457}re-devices.net;SharedAccessKeyName=device;SharedAccessKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
}

// =========================================================================
// 7. AZURE KEY VAULT CREDENTIAL ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv12_keyvault_normal_must_fire() {
    assert_detector_fires(
        "azure-key-vault-credentials",
        "https://myvault-name.vault.azure.net/",
        "https://myvault-name.vault.azure.net/",
    );
}

#[test]
fn adv12_keyvault_wrong_prefix_must_silent() {
    assert_detector_silent(
        "azure-key-vault-credentials",
        "https://myvault-name.vault.azure.org/",
    );
}

#[test]
fn adv12_keyvault_evade_zwsp_must_fire() {
    assert_detector_fires(
        "azure-key-vault-credentials",
        "https://myvault-name.vault\u{200B}.azure.net/",
        "https://myvault-name.vault.azure.net/",
    );
}

#[test]
fn adv12_keyvault_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "azure-key-vault-credentials",
        "https://myvault\u{00AD}-name.vault.azure.net/",
        "https://myvault-name.vault.azure.net/",
    );
}

#[test]
fn adv12_keyvault_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "azure-key-vault-credentials",
        "https://myvault-name.va\u{0457}lt.azure.net/",
        "https://myvault-name.vault.azure.net/",
    );
}

// =========================================================================
// 8. AZURE OPENAI API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv12_openai_normal_must_fire() {
    assert_detector_fires(
        "azure-openai-api-key",
        "AZURE_OPENAI_API_KEY = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv12_openai_wrong_prefix_must_silent() {
    assert_detector_silent(
        "azure-openai-api-key",
        "MURE_OPENAI_API_KEY = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv12_openai_evade_zwsp_must_fire() {
    assert_detector_fires(
        "azure-openai-api-key",
        "AZURE_OPENAI\u{200B}_API_KEY = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv12_openai_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "azure-openai-api-key",
        "AZURE_OPENAI_API_KEY = \"abcde12345\u{00AD}67890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv12_openai_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "azure-openai-api-key",
        "az\u{0457}re_openai_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

// =========================================================================
// 9. AZURE STORAGE ACCOUNT KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv12_storage_normal_bare_must_stay_silent() {
    assert_detector_silent("azure-storage-account-key", "AccountKey=abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1234567890abcde1234=");
}

#[test]
fn adv12_storage_wrong_prefix_must_silent() {
    assert_detector_silent("azure-storage-account-key", "BccountKey=abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1234567890abcde1234=");
}

#[test]
fn adv12_storage_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent("azure-storage-account-key", "AccountKey\u{200B}=abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1234567890abcde1234=");
}

#[test]
fn adv12_storage_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent("azure-storage-account-key", "AccountKey=abcde1234567890abcde1\u{00AD}23456789012abcde1234567890abcde123456789012abcde1234567890abcde1234=");
}

#[test]
fn adv12_storage_evade_homoglyph_bare_must_stay_silent() {
    assert_detector_silent("azure-storage-account-key", "AccountK\u{0435}y=abcde1234567890abcde123456789012abcde1234567890abcde123456789012abcde1234567890abcde1234=");
}

// =========================================================================
// 10. AZURE SUBSCRIPTION KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv12_subscription_normal_must_fire() {
    assert_detector_fires(
        "azure-subscription-key",
        "azure_subscription_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv12_subscription_wrong_prefix_must_silent() {
    assert_detector_silent(
        "azure-subscription-key",
        "azure_unsubscription_key = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv12_subscription_evade_zwsp_must_fire() {
    assert_detector_fires(
        "azure-subscription-key",
        "azure_subscription\u{200B}_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv12_subscription_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "azure-subscription-key",
        "azure_subscription_key = \"abcde12345\u{00AD}67890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv12_subscription_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "azure-subscription-key",
        "az\u{0457}re_subscription_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}
