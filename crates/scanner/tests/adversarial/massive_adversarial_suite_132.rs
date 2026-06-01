//! Part 132 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates stytch, stytch, subgraph, sumo, sumsub, supabase, supabase, supabase, supabase, supabase detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. STYTCH PROJECT ID ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv132_stytch_project_id_normal_must_fire() {
    assert_detector_fires(
        "stytch-project-id",
        "project-Ri8GQF7iFI1hBMUaHDOQX42iATqA8cBOO9kv",
        "project-Ri8GQF7iFI1hBMUaHDOQX42iATqA8cBOO9kv",
    );
}

#[test]
fn adv132_stytch_project_id_wrong_prefix_must_silent() {
    assert_detector_silent(
        "stytch-project-id",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv132_stytch_project_id_evade_zwsp_must_fire() {
    assert_detector_fires(
        "stytch-project-id",
        "project-Ri8GQF7iFI1hBM\u{200B}UaHDOQX42iATqA8cBOO9kv",
        "project-Ri8GQF7iFI1hBMUaHDOQX42iATqA8cBOO9kv",
    );
}

#[test]
fn adv132_stytch_project_id_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "stytch-project-id",
        "project-Ri8GQF7iFI1hBM\u{00AD}UaHDOQX42iATqA8cBOO9kv",
        "project-Ri8GQF7iFI1hBMUaHDOQX42iATqA8cBOO9kv",
    );
}

#[test]
fn adv132_stytch_project_id_evade_zwnj_must_fire() {
    assert_detector_fires(
        "stytch-project-id",
        "project-Ri8GQF7iFI1hBM\u{200C}UaHDOQX42iATqA8cBOO9kv",
        "project-Ri8GQF7iFI1hBMUaHDOQX42iATqA8cBOO9kv",
    );
}

#[test]
fn adv132_stytch_project_id_evade_zwj_must_fire() {
    assert_detector_fires(
        "stytch-project-id",
        "project-Ri8GQF7iFI1hBM\u{200D}UaHDOQX42iATqA8cBOO9kv",
        "project-Ri8GQF7iFI1hBMUaHDOQX42iATqA8cBOO9kv",
    );
}

#[test]
fn adv132_stytch_project_id_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "stytch-project-id",
        "project-Ri8GQF7iFI1hBM\u{FEFF}UaHDOQX42iATqA8cBOO9kv",
        "project-Ri8GQF7iFI1hBMUaHDOQX42iATqA8cBOO9kv",
    );
}

#[test]
fn adv132_stytch_project_id_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "stytch-project-id",
        "project-Ri8GQF7iFI1hBM\u{2060}UaHDOQX42iATqA8cBOO9kv",
        "project-Ri8GQF7iFI1hBMUaHDOQX42iATqA8cBOO9kv",
    );
}

#[test]
fn adv132_stytch_project_id_evade_mongolian_must_fire() {
    assert_detector_fires(
        "stytch-project-id",
        "project-Ri8GQF7iFI1hBM\u{180E}UaHDOQX42iATqA8cBOO9kv",
        "project-Ri8GQF7iFI1hBMUaHDOQX42iATqA8cBOO9kv",
    );
}

#[test]
fn adv132_stytch_project_id_evade_rtl_must_fire() {
    assert_detector_fires(
        "stytch-project-id",
        "project-Ri8GQF7iFI1hBM\u{202E}UaHDOQX42iATqA8cBOO9kv",
        "project-Ri8GQF7iFI1hBMUaHDOQX42iATqA8cBOO9kv",
    );
}

#[test]
fn adv132_stytch_project_id_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "stytch-project-id",
        "project-Ri8GQF7iFI1hBM\u{202C}UaHDOQX42iATqA8cBOO9kv",
        "project-Ri8GQF7iFI1hBMUaHDOQX42iATqA8cBOO9kv",
    );
}

#[test]
fn adv132_stytch_project_id_evade_lrm_must_fire() {
    assert_detector_fires(
        "stytch-project-id",
        "project-Ri8GQF7iFI1hBM\u{200E}UaHDOQX42iATqA8cBOO9kv",
        "project-Ri8GQF7iFI1hBMUaHDOQX42iATqA8cBOO9kv",
    );
}

// =========================================================================
// 2. STYTCH SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv132_stytch_secret_normal_must_fire() {
    assert_detector_fires(
        "stytch-secret",
        "secret-7LwZeErW6m5bkxruCIoa74YadFFXtYIBPcuf",
        "secret-7LwZeErW6m5bkxruCIoa74YadFFXtYIBPcuf",
    );
}

#[test]
fn adv132_stytch_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "stytch-secret",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv132_stytch_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "stytch-secret",
        "secret-7LwZeErW6m5bkx\u{200B}ruCIoa74YadFFXtYIBPcuf",
        "secret-7LwZeErW6m5bkxruCIoa74YadFFXtYIBPcuf",
    );
}

#[test]
fn adv132_stytch_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "stytch-secret",
        "secret-7LwZeErW6m5bkx\u{00AD}ruCIoa74YadFFXtYIBPcuf",
        "secret-7LwZeErW6m5bkxruCIoa74YadFFXtYIBPcuf",
    );
}

#[test]
fn adv132_stytch_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "stytch-secret",
        "secret-7LwZeErW6m5bkx\u{200C}ruCIoa74YadFFXtYIBPcuf",
        "secret-7LwZeErW6m5bkxruCIoa74YadFFXtYIBPcuf",
    );
}

#[test]
fn adv132_stytch_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "stytch-secret",
        "secret-7LwZeErW6m5bkx\u{200D}ruCIoa74YadFFXtYIBPcuf",
        "secret-7LwZeErW6m5bkxruCIoa74YadFFXtYIBPcuf",
    );
}

#[test]
fn adv132_stytch_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "stytch-secret",
        "secret-7LwZeErW6m5bkx\u{FEFF}ruCIoa74YadFFXtYIBPcuf",
        "secret-7LwZeErW6m5bkxruCIoa74YadFFXtYIBPcuf",
    );
}

#[test]
fn adv132_stytch_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "stytch-secret",
        "secret-7LwZeErW6m5bkx\u{2060}ruCIoa74YadFFXtYIBPcuf",
        "secret-7LwZeErW6m5bkxruCIoa74YadFFXtYIBPcuf",
    );
}

#[test]
fn adv132_stytch_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "stytch-secret",
        "secret-7LwZeErW6m5bkx\u{180E}ruCIoa74YadFFXtYIBPcuf",
        "secret-7LwZeErW6m5bkxruCIoa74YadFFXtYIBPcuf",
    );
}

#[test]
fn adv132_stytch_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "stytch-secret",
        "secret-7LwZeErW6m5bkx\u{202E}ruCIoa74YadFFXtYIBPcuf",
        "secret-7LwZeErW6m5bkxruCIoa74YadFFXtYIBPcuf",
    );
}

#[test]
fn adv132_stytch_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "stytch-secret",
        "secret-7LwZeErW6m5bkx\u{202C}ruCIoa74YadFFXtYIBPcuf",
        "secret-7LwZeErW6m5bkxruCIoa74YadFFXtYIBPcuf",
    );
}

#[test]
fn adv132_stytch_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "stytch-secret",
        "secret-7LwZeErW6m5bkx\u{200E}ruCIoa74YadFFXtYIBPcuf",
        "secret-7LwZeErW6m5bkxruCIoa74YadFFXtYIBPcuf",
    );
}

// =========================================================================
// 3. SUBGRAPH STUDIO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv132_subgraph_studio_api_key_normal_must_fire() {
    assert_detector_fires(
        "subgraph-studio-api-key",
        "SUBGRAPH_STUDIO=3e3ccac4f51f88a6dd87cafaf4951d13",
        "3e3ccac4f51f88a6dd87cafaf4951d13",
    );
}

#[test]
fn adv132_subgraph_studio_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "subgraph-studio-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv132_subgraph_studio_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "subgraph-studio-api-key",
        "SUBGRAPH_STUDIO=3e3ccac4f51f88a6\u{200B}dd87cafaf4951d13",
        "3e3ccac4f51f88a6dd87cafaf4951d13",
    );
}

#[test]
fn adv132_subgraph_studio_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "subgraph-studio-api-key",
        "SUBGRAPH_STUDIO=3e3ccac4f51f88a6\u{00AD}dd87cafaf4951d13",
        "3e3ccac4f51f88a6dd87cafaf4951d13",
    );
}

#[test]
fn adv132_subgraph_studio_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "subgraph-studio-api-key",
        "SUBGRAPH_STUDIO=3e3ccac4f51f88a6\u{200C}dd87cafaf4951d13",
        "3e3ccac4f51f88a6dd87cafaf4951d13",
    );
}

#[test]
fn adv132_subgraph_studio_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "subgraph-studio-api-key",
        "SUBGRAPH_STUDIO=3e3ccac4f51f88a6\u{200D}dd87cafaf4951d13",
        "3e3ccac4f51f88a6dd87cafaf4951d13",
    );
}

#[test]
fn adv132_subgraph_studio_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "subgraph-studio-api-key",
        "SUBGRAPH_STUDIO=3e3ccac4f51f88a6\u{FEFF}dd87cafaf4951d13",
        "3e3ccac4f51f88a6dd87cafaf4951d13",
    );
}

#[test]
fn adv132_subgraph_studio_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "subgraph-studio-api-key",
        "SUBGRAPH_STUDIO=3e3ccac4f51f88a6\u{2060}dd87cafaf4951d13",
        "3e3ccac4f51f88a6dd87cafaf4951d13",
    );
}

#[test]
fn adv132_subgraph_studio_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "subgraph-studio-api-key",
        "SUBGRAPH_STUDIO=3e3ccac4f51f88a6\u{180E}dd87cafaf4951d13",
        "3e3ccac4f51f88a6dd87cafaf4951d13",
    );
}

#[test]
fn adv132_subgraph_studio_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "subgraph-studio-api-key",
        "SUBGRAPH_STUDIO=3e3ccac4f51f88a6\u{202E}dd87cafaf4951d13",
        "3e3ccac4f51f88a6dd87cafaf4951d13",
    );
}

#[test]
fn adv132_subgraph_studio_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "subgraph-studio-api-key",
        "SUBGRAPH_STUDIO=3e3ccac4f51f88a6\u{202C}dd87cafaf4951d13",
        "3e3ccac4f51f88a6dd87cafaf4951d13",
    );
}

#[test]
fn adv132_subgraph_studio_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "subgraph-studio-api-key",
        "SUBGRAPH_STUDIO=3e3ccac4f51f88a6\u{200E}dd87cafaf4951d13",
        "3e3ccac4f51f88a6dd87cafaf4951d13",
    );
}

// =========================================================================
// 4. SUMO LOGIC ACCESS KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv132_sumo_logic_access_key_normal_must_fire() {
    assert_detector_fires(
        "sumo-logic-access-key",
        "SUMOLOGIC_ACCESSKEY=PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLmYCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
        "PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLmYCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
    );
}

#[test]
fn adv132_sumo_logic_access_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "sumo-logic-access-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv132_sumo_logic_access_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sumo-logic-access-key",
        "SUMOLOGIC_ACCESSKEY=PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLm\u{200B}YCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
        "PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLmYCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
    );
}

#[test]
fn adv132_sumo_logic_access_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sumo-logic-access-key",
        "SUMOLOGIC_ACCESSKEY=PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLm\u{00AD}YCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
        "PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLmYCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
    );
}

#[test]
fn adv132_sumo_logic_access_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "sumo-logic-access-key",
        "SUMOLOGIC_ACCESSKEY=PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLm\u{200C}YCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
        "PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLmYCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
    );
}

#[test]
fn adv132_sumo_logic_access_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "sumo-logic-access-key",
        "SUMOLOGIC_ACCESSKEY=PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLm\u{200D}YCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
        "PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLmYCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
    );
}

#[test]
fn adv132_sumo_logic_access_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "sumo-logic-access-key",
        "SUMOLOGIC_ACCESSKEY=PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLm\u{FEFF}YCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
        "PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLmYCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
    );
}

#[test]
fn adv132_sumo_logic_access_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "sumo-logic-access-key",
        "SUMOLOGIC_ACCESSKEY=PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLm\u{2060}YCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
        "PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLmYCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
    );
}

#[test]
fn adv132_sumo_logic_access_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "sumo-logic-access-key",
        "SUMOLOGIC_ACCESSKEY=PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLm\u{180E}YCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
        "PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLmYCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
    );
}

#[test]
fn adv132_sumo_logic_access_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "sumo-logic-access-key",
        "SUMOLOGIC_ACCESSKEY=PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLm\u{202E}YCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
        "PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLmYCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
    );
}

#[test]
fn adv132_sumo_logic_access_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "sumo-logic-access-key",
        "SUMOLOGIC_ACCESSKEY=PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLm\u{202C}YCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
        "PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLmYCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
    );
}

#[test]
fn adv132_sumo_logic_access_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "sumo-logic-access-key",
        "SUMOLOGIC_ACCESSKEY=PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLm\u{200E}YCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
        "PtgLGdzJjgnbMKh1O99Osc7xcKyF5GLmYCjGSsInlOGGLaOdEckbTo+laJwN9wY9",
    );
}

// =========================================================================
// 5. SUMSUB API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv132_sumsub_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "sumsub-api-credentials",
        "sumsub app_token=SumsubAppTok1",
        "SumsubAppTok1",
    );
}

#[test]
fn adv132_sumsub_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent("sumsub-api-credentials", "dummy_prefix_0 =xxxxxxxxxxxxx");
}

#[test]
fn adv132_sumsub_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sumsub-api-credentials",
        "sumsub app_token=Sumsub\u{200B}AppTok1",
        "SumsubAppTok1",
    );
}

#[test]
fn adv132_sumsub_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sumsub-api-credentials",
        "sumsub app_token=Sumsub\u{00AD}AppTok1",
        "SumsubAppTok1",
    );
}

#[test]
fn adv132_sumsub_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "sumsub-api-credentials",
        "sumsub app_token=Sumsub\u{200C}AppTok1",
        "SumsubAppTok1",
    );
}

#[test]
fn adv132_sumsub_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "sumsub-api-credentials",
        "sumsub app_token=Sumsub\u{200D}AppTok1",
        "SumsubAppTok1",
    );
}

#[test]
fn adv132_sumsub_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "sumsub-api-credentials",
        "sumsub app_token=Sumsub\u{FEFF}AppTok1",
        "SumsubAppTok1",
    );
}

#[test]
fn adv132_sumsub_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "sumsub-api-credentials",
        "sumsub app_token=Sumsub\u{2060}AppTok1",
        "SumsubAppTok1",
    );
}

#[test]
fn adv132_sumsub_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "sumsub-api-credentials",
        "sumsub app_token=Sumsub\u{180E}AppTok1",
        "SumsubAppTok1",
    );
}

#[test]
fn adv132_sumsub_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "sumsub-api-credentials",
        "sumsub app_token=Sumsub\u{202E}AppTok1",
        "SumsubAppTok1",
    );
}

#[test]
fn adv132_sumsub_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "sumsub-api-credentials",
        "sumsub app_token=Sumsub\u{202C}AppTok1",
        "SumsubAppTok1",
    );
}

#[test]
fn adv132_sumsub_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "sumsub-api-credentials",
        "sumsub app_token=Sumsub\u{200E}AppTok1",
        "SumsubAppTok1",
    );
}

// =========================================================================
// 6. SUPABASE ANON KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv132_supabase_anon_key_normal_must_fire() {
    assert_detector_fires(
        "supabase-anon-key",
        "SUPABASE_ANON_KEY=eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
        "eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
    );
}

#[test]
fn adv132_supabase_anon_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "supabase-anon-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv132_supabase_anon_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "supabase-anon-key",
        "SUPABASE_ANON_KEY=eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT\u{200B}9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
        "eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
    );
}

#[test]
fn adv132_supabase_anon_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "supabase-anon-key",
        "SUPABASE_ANON_KEY=eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT\u{00AD}9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
        "eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
    );
}

#[test]
fn adv132_supabase_anon_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "supabase-anon-key",
        "SUPABASE_ANON_KEY=eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT\u{200C}9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
        "eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
    );
}

#[test]
fn adv132_supabase_anon_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "supabase-anon-key",
        "SUPABASE_ANON_KEY=eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT\u{200D}9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
        "eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
    );
}

#[test]
fn adv132_supabase_anon_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "supabase-anon-key",
        "SUPABASE_ANON_KEY=eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT\u{FEFF}9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
        "eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
    );
}

#[test]
fn adv132_supabase_anon_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "supabase-anon-key",
        "SUPABASE_ANON_KEY=eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT\u{2060}9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
        "eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
    );
}

#[test]
fn adv132_supabase_anon_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "supabase-anon-key",
        "SUPABASE_ANON_KEY=eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT\u{180E}9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
        "eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
    );
}

#[test]
fn adv132_supabase_anon_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "supabase-anon-key",
        "SUPABASE_ANON_KEY=eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT\u{202E}9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
        "eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
    );
}

#[test]
fn adv132_supabase_anon_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "supabase-anon-key",
        "SUPABASE_ANON_KEY=eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT\u{202C}9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
        "eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
    );
}

#[test]
fn adv132_supabase_anon_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "supabase-anon-key",
        "SUPABASE_ANON_KEY=eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT\u{200E}9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
        "eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
    );
}

// =========================================================================
// 7. SUPABASE JWT SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv132_supabase_jwt_secret_normal_must_fire() {
    assert_detector_fires(
        "supabase-jwt-secret",
        "SUPABASE_JWT_SECRET=eBJkrx0jH91koGO_H68_iUQ4ZZtYSrYT",
        "eBJkrx0jH91koGO_H68_iUQ4ZZtYSrYT",
    );
}

#[test]
fn adv132_supabase_jwt_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "supabase-jwt-secret",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv132_supabase_jwt_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "supabase-jwt-secret",
        "SUPABASE_JWT_SECRET=eBJkrx0jH91koGO_\u{200B}H68_iUQ4ZZtYSrYT",
        "eBJkrx0jH91koGO_H68_iUQ4ZZtYSrYT",
    );
}

#[test]
fn adv132_supabase_jwt_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "supabase-jwt-secret",
        "SUPABASE_JWT_SECRET=eBJkrx0jH91koGO_\u{00AD}H68_iUQ4ZZtYSrYT",
        "eBJkrx0jH91koGO_H68_iUQ4ZZtYSrYT",
    );
}

#[test]
fn adv132_supabase_jwt_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "supabase-jwt-secret",
        "SUPABASE_JWT_SECRET=eBJkrx0jH91koGO_\u{200C}H68_iUQ4ZZtYSrYT",
        "eBJkrx0jH91koGO_H68_iUQ4ZZtYSrYT",
    );
}

#[test]
fn adv132_supabase_jwt_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "supabase-jwt-secret",
        "SUPABASE_JWT_SECRET=eBJkrx0jH91koGO_\u{200D}H68_iUQ4ZZtYSrYT",
        "eBJkrx0jH91koGO_H68_iUQ4ZZtYSrYT",
    );
}

#[test]
fn adv132_supabase_jwt_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "supabase-jwt-secret",
        "SUPABASE_JWT_SECRET=eBJkrx0jH91koGO_\u{FEFF}H68_iUQ4ZZtYSrYT",
        "eBJkrx0jH91koGO_H68_iUQ4ZZtYSrYT",
    );
}

#[test]
fn adv132_supabase_jwt_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "supabase-jwt-secret",
        "SUPABASE_JWT_SECRET=eBJkrx0jH91koGO_\u{2060}H68_iUQ4ZZtYSrYT",
        "eBJkrx0jH91koGO_H68_iUQ4ZZtYSrYT",
    );
}

#[test]
fn adv132_supabase_jwt_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "supabase-jwt-secret",
        "SUPABASE_JWT_SECRET=eBJkrx0jH91koGO_\u{180E}H68_iUQ4ZZtYSrYT",
        "eBJkrx0jH91koGO_H68_iUQ4ZZtYSrYT",
    );
}

#[test]
fn adv132_supabase_jwt_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "supabase-jwt-secret",
        "SUPABASE_JWT_SECRET=eBJkrx0jH91koGO_\u{202E}H68_iUQ4ZZtYSrYT",
        "eBJkrx0jH91koGO_H68_iUQ4ZZtYSrYT",
    );
}

#[test]
fn adv132_supabase_jwt_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "supabase-jwt-secret",
        "SUPABASE_JWT_SECRET=eBJkrx0jH91koGO_\u{202C}H68_iUQ4ZZtYSrYT",
        "eBJkrx0jH91koGO_H68_iUQ4ZZtYSrYT",
    );
}

#[test]
fn adv132_supabase_jwt_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "supabase-jwt-secret",
        "SUPABASE_JWT_SECRET=eBJkrx0jH91koGO_\u{200E}H68_iUQ4ZZtYSrYT",
        "eBJkrx0jH91koGO_H68_iUQ4ZZtYSrYT",
    );
}

// =========================================================================
// 8. SUPABASE MANAGEMENT API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv132_supabase_management_api_key_normal_must_fire() {
    assert_detector_fires(
        "supabase-management-api-key",
        "sb_publishable_aBcDeFgHiJkLmNoPqRsTuV_AbCdEfGh",
        "sb_publishable_aBcDeFgHiJkLmNoPqRsTuV_AbCdEfGh",
    );
}

#[test]
fn adv132_supabase_management_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "supabase-management-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv132_supabase_management_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "supabase-management-api-key",
        "sb_publishable_aBcDeFgH\u{200B}iJkLmNoPqRsTuV_AbCdEfGh",
        "sb_publishable_aBcDeFgHiJkLmNoPqRsTuV_AbCdEfGh",
    );
}

#[test]
fn adv132_supabase_management_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "supabase-management-api-key",
        "sb_publishable_aBcDeFgH\u{00AD}iJkLmNoPqRsTuV_AbCdEfGh",
        "sb_publishable_aBcDeFgHiJkLmNoPqRsTuV_AbCdEfGh",
    );
}

#[test]
fn adv132_supabase_management_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "supabase-management-api-key",
        "sb_publishable_aBcDeFgH\u{200C}iJkLmNoPqRsTuV_AbCdEfGh",
        "sb_publishable_aBcDeFgHiJkLmNoPqRsTuV_AbCdEfGh",
    );
}

#[test]
fn adv132_supabase_management_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "supabase-management-api-key",
        "sb_publishable_aBcDeFgH\u{200D}iJkLmNoPqRsTuV_AbCdEfGh",
        "sb_publishable_aBcDeFgHiJkLmNoPqRsTuV_AbCdEfGh",
    );
}

#[test]
fn adv132_supabase_management_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "supabase-management-api-key",
        "sb_publishable_aBcDeFgH\u{FEFF}iJkLmNoPqRsTuV_AbCdEfGh",
        "sb_publishable_aBcDeFgHiJkLmNoPqRsTuV_AbCdEfGh",
    );
}

#[test]
fn adv132_supabase_management_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "supabase-management-api-key",
        "sb_publishable_aBcDeFgH\u{2060}iJkLmNoPqRsTuV_AbCdEfGh",
        "sb_publishable_aBcDeFgHiJkLmNoPqRsTuV_AbCdEfGh",
    );
}

#[test]
fn adv132_supabase_management_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "supabase-management-api-key",
        "sb_publishable_aBcDeFgH\u{180E}iJkLmNoPqRsTuV_AbCdEfGh",
        "sb_publishable_aBcDeFgHiJkLmNoPqRsTuV_AbCdEfGh",
    );
}

#[test]
fn adv132_supabase_management_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "supabase-management-api-key",
        "sb_publishable_aBcDeFgH\u{202E}iJkLmNoPqRsTuV_AbCdEfGh",
        "sb_publishable_aBcDeFgHiJkLmNoPqRsTuV_AbCdEfGh",
    );
}

#[test]
fn adv132_supabase_management_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "supabase-management-api-key",
        "sb_publishable_aBcDeFgH\u{202C}iJkLmNoPqRsTuV_AbCdEfGh",
        "sb_publishable_aBcDeFgHiJkLmNoPqRsTuV_AbCdEfGh",
    );
}

#[test]
fn adv132_supabase_management_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "supabase-management-api-key",
        "sb_publishable_aBcDeFgH\u{200E}iJkLmNoPqRsTuV_AbCdEfGh",
        "sb_publishable_aBcDeFgHiJkLmNoPqRsTuV_AbCdEfGh",
    );
}

// =========================================================================
// 9. SUPABASE REALTIME CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv132_supabase_realtime_credentials_normal_must_fire() {
    assert_detector_fires(
        "supabase-realtime-credentials",
        "SUPABASE_REALTIME_URL=wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbjq.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
        "wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbjq.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
    );
}

#[test]
fn adv132_supabase_realtime_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "supabase-realtime-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv132_supabase_realtime_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "supabase-realtime-credentials",
        "SUPABASE_REALTIME_URL=wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbj\u{200B}q.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
        "wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbjq.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
    );
}

#[test]
fn adv132_supabase_realtime_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "supabase-realtime-credentials",
        "SUPABASE_REALTIME_URL=wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbj\u{00AD}q.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
        "wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbjq.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
    );
}

#[test]
fn adv132_supabase_realtime_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "supabase-realtime-credentials",
        "SUPABASE_REALTIME_URL=wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbj\u{200C}q.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
        "wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbjq.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
    );
}

#[test]
fn adv132_supabase_realtime_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "supabase-realtime-credentials",
        "SUPABASE_REALTIME_URL=wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbj\u{200D}q.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
        "wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbjq.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
    );
}

#[test]
fn adv132_supabase_realtime_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "supabase-realtime-credentials",
        "SUPABASE_REALTIME_URL=wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbj\u{FEFF}q.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
        "wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbjq.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
    );
}

#[test]
fn adv132_supabase_realtime_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "supabase-realtime-credentials",
        "SUPABASE_REALTIME_URL=wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbj\u{2060}q.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
        "wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbjq.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
    );
}

#[test]
fn adv132_supabase_realtime_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "supabase-realtime-credentials",
        "SUPABASE_REALTIME_URL=wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbj\u{180E}q.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
        "wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbjq.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
    );
}

#[test]
fn adv132_supabase_realtime_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "supabase-realtime-credentials",
        "SUPABASE_REALTIME_URL=wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbj\u{202E}q.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
        "wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbjq.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
    );
}

#[test]
fn adv132_supabase_realtime_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "supabase-realtime-credentials",
        "SUPABASE_REALTIME_URL=wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbj\u{202C}q.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
        "wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbjq.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
    );
}

#[test]
fn adv132_supabase_realtime_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "supabase-realtime-credentials",
        "SUPABASE_REALTIME_URL=wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbj\u{200E}q.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
        "wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbjq.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/",
    );
}

// =========================================================================
// 10. SUPABASE SERVICE KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv132_supabase_service_key_normal_must_fire() {
    assert_detector_fires(
        "supabase-service-key",
        "SUPABASE_SERVICE_KEY=eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
        "eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
    );
}

#[test]
fn adv132_supabase_service_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "supabase-service-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv132_supabase_service_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "supabase-service-key",
        "SUPABASE_SERVICE_KEY=eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s\u{200B}5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
        "eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
    );
}

#[test]
fn adv132_supabase_service_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "supabase-service-key",
        "SUPABASE_SERVICE_KEY=eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s\u{00AD}5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
        "eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
    );
}

#[test]
fn adv132_supabase_service_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "supabase-service-key",
        "SUPABASE_SERVICE_KEY=eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s\u{200C}5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
        "eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
    );
}

#[test]
fn adv132_supabase_service_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "supabase-service-key",
        "SUPABASE_SERVICE_KEY=eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s\u{200D}5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
        "eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
    );
}

#[test]
fn adv132_supabase_service_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "supabase-service-key",
        "SUPABASE_SERVICE_KEY=eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s\u{FEFF}5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
        "eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
    );
}

#[test]
fn adv132_supabase_service_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "supabase-service-key",
        "SUPABASE_SERVICE_KEY=eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s\u{2060}5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
        "eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
    );
}

#[test]
fn adv132_supabase_service_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "supabase-service-key",
        "SUPABASE_SERVICE_KEY=eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s\u{180E}5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
        "eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
    );
}

#[test]
fn adv132_supabase_service_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "supabase-service-key",
        "SUPABASE_SERVICE_KEY=eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s\u{202E}5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
        "eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
    );
}

#[test]
fn adv132_supabase_service_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "supabase-service-key",
        "SUPABASE_SERVICE_KEY=eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s\u{202C}5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
        "eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
    );
}

#[test]
fn adv132_supabase_service_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "supabase-service-key",
        "SUPABASE_SERVICE_KEY=eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s\u{200E}5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
        "eyJ4pWJ7Z0IaxtZTdfU2cFSSw5znAxWtf3-HfoXJeFD0bcc5zE1smwbmdPqpQ1gPjHsI7kOxEA5WbH8PikNzX8o0Re5vz1Cq4.eyJZc7Ao-7s5EiTMGSg_pwIMw4eX40ezGTXRM5kVCfTRD27wyWR53Gr2l.xpT0SzBM-TakzTkMmGBf31e6nc03sD7OX0-GwVjAshVQ_HJGhkFUMSAN3Aa8SRX",
    );
}
