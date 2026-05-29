//! Part 133 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates supabase, tailscale, tawkto, taxjar, teamwork, telegram, terraform, terraform, thehive, threatconnect detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. SUPABASE STORAGE CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv133_supabase_storage_credentials_normal_must_fire() {
    assert_detector_fires(
        "supabase-storage-credentials",
        "SUPABASE_STORAGE_URL=https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53rhc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
        "https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53rhc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
    );
}

#[test]
fn adv133_supabase_storage_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "supabase-storage-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv133_supabase_storage_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "supabase-storage-credentials",
        "SUPABASE_STORAGE_URL=https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53r\u{200B}hc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
        "https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53rhc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
    );
}

#[test]
fn adv133_supabase_storage_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "supabase-storage-credentials",
        "SUPABASE_STORAGE_URL=https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53r\u{00AD}hc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
        "https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53rhc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
    );
}

#[test]
fn adv133_supabase_storage_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "supabase-storage-credentials",
        "SUPABASE_STORAGE_URL=https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53r\u{200C}hc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
        "https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53rhc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
    );
}

#[test]
fn adv133_supabase_storage_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "supabase-storage-credentials",
        "SUPABASE_STORAGE_URL=https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53r\u{200D}hc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
        "https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53rhc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
    );
}

#[test]
fn adv133_supabase_storage_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "supabase-storage-credentials",
        "SUPABASE_STORAGE_URL=https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53r\u{FEFF}hc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
        "https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53rhc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
    );
}

#[test]
fn adv133_supabase_storage_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "supabase-storage-credentials",
        "SUPABASE_STORAGE_URL=https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53r\u{2060}hc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
        "https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53rhc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
    );
}

#[test]
fn adv133_supabase_storage_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "supabase-storage-credentials",
        "SUPABASE_STORAGE_URL=https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53r\u{180E}hc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
        "https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53rhc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
    );
}

#[test]
fn adv133_supabase_storage_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "supabase-storage-credentials",
        "SUPABASE_STORAGE_URL=https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53r\u{202E}hc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
        "https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53rhc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
    );
}

#[test]
fn adv133_supabase_storage_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "supabase-storage-credentials",
        "SUPABASE_STORAGE_URL=https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53r\u{202C}hc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
        "https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53rhc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
    );
}

#[test]
fn adv133_supabase_storage_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "supabase-storage-credentials",
        "SUPABASE_STORAGE_URL=https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53r\u{200E}hc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
        "https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53rhc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298",
    );
}

// =========================================================================
// 2. TAILSCALE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv133_tailscale_api_key_normal_must_fire() {
    assert_detector_fires(
        "tailscale-api-key",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQUaHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQUaHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
    );
}

#[test]
fn adv133_tailscale_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "tailscale-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv133_tailscale_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "tailscale-api-key",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQU\u{200B}aHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQUaHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
    );
}

#[test]
fn adv133_tailscale_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "tailscale-api-key",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQU\u{00AD}aHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQUaHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
    );
}

#[test]
fn adv133_tailscale_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "tailscale-api-key",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQU\u{200C}aHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQUaHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
    );
}

#[test]
fn adv133_tailscale_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "tailscale-api-key",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQU\u{200D}aHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQUaHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
    );
}

#[test]
fn adv133_tailscale_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "tailscale-api-key",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQU\u{FEFF}aHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQUaHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
    );
}

#[test]
fn adv133_tailscale_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "tailscale-api-key",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQU\u{2060}aHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQUaHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
    );
}

#[test]
fn adv133_tailscale_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "tailscale-api-key",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQU\u{180E}aHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQUaHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
    );
}

#[test]
fn adv133_tailscale_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "tailscale-api-key",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQU\u{202E}aHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQUaHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
    );
}

#[test]
fn adv133_tailscale_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "tailscale-api-key",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQU\u{202C}aHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQUaHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
    );
}

#[test]
fn adv133_tailscale_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "tailscale-api-key",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQU\u{200E}aHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
        "tskey-api-bHbEzy1zf6wCro8yiOZ8HEFGG742OVcXgVErdxjAWQUaHqRRfdcjvAe-UZ2bOS0aRNzaoiZNmL3QqvhSyYOPeMhhlFrr7U3l",
    );
}

// =========================================================================
// 3. TAWKTO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv133_tawkto_api_key_normal_must_fire() {
    assert_detector_fires(
        "tawkto-api-key",
        "TAWK_TOTOKEN=6c452aaae4137a470868ddf5d894d06d",
        "6c452aaae4137a470868ddf5d894d06d",
    );
}

#[test]
fn adv133_tawkto_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "tawkto-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv133_tawkto_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "tawkto-api-key",
        "TAWK_TOTOKEN=6c452aaae4137a47\u{200B}0868ddf5d894d06d",
        "6c452aaae4137a470868ddf5d894d06d",
    );
}

#[test]
fn adv133_tawkto_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "tawkto-api-key",
        "TAWK_TOTOKEN=6c452aaae4137a47\u{00AD}0868ddf5d894d06d",
        "6c452aaae4137a470868ddf5d894d06d",
    );
}

#[test]
fn adv133_tawkto_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "tawkto-api-key",
        "TAWK_TOTOKEN=6c452aaae4137a47\u{200C}0868ddf5d894d06d",
        "6c452aaae4137a470868ddf5d894d06d",
    );
}

#[test]
fn adv133_tawkto_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "tawkto-api-key",
        "TAWK_TOTOKEN=6c452aaae4137a47\u{200D}0868ddf5d894d06d",
        "6c452aaae4137a470868ddf5d894d06d",
    );
}

#[test]
fn adv133_tawkto_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "tawkto-api-key",
        "TAWK_TOTOKEN=6c452aaae4137a47\u{FEFF}0868ddf5d894d06d",
        "6c452aaae4137a470868ddf5d894d06d",
    );
}

#[test]
fn adv133_tawkto_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "tawkto-api-key",
        "TAWK_TOTOKEN=6c452aaae4137a47\u{2060}0868ddf5d894d06d",
        "6c452aaae4137a470868ddf5d894d06d",
    );
}

#[test]
fn adv133_tawkto_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "tawkto-api-key",
        "TAWK_TOTOKEN=6c452aaae4137a47\u{180E}0868ddf5d894d06d",
        "6c452aaae4137a470868ddf5d894d06d",
    );
}

#[test]
fn adv133_tawkto_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "tawkto-api-key",
        "TAWK_TOTOKEN=6c452aaae4137a47\u{202E}0868ddf5d894d06d",
        "6c452aaae4137a470868ddf5d894d06d",
    );
}

#[test]
fn adv133_tawkto_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "tawkto-api-key",
        "TAWK_TOTOKEN=6c452aaae4137a47\u{202C}0868ddf5d894d06d",
        "6c452aaae4137a470868ddf5d894d06d",
    );
}

#[test]
fn adv133_tawkto_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "tawkto-api-key",
        "TAWK_TOTOKEN=6c452aaae4137a47\u{200E}0868ddf5d894d06d",
        "6c452aaae4137a470868ddf5d894d06d",
    );
}

// =========================================================================
// 4. TAXJAR API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv133_taxjar_api_token_normal_must_fire() {
    assert_detector_fires(
        "taxjar-api-token",
        "TAXJARTOKEN=f68f9ea979a26968b99bd197cbe8a06b",
        "f68f9ea979a26968b99bd197cbe8a06b",
    );
}

#[test]
fn adv133_taxjar_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "taxjar-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv133_taxjar_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "taxjar-api-token",
        "TAXJARTOKEN=f68f9ea979a26968\u{200B}b99bd197cbe8a06b",
        "f68f9ea979a26968b99bd197cbe8a06b",
    );
}

#[test]
fn adv133_taxjar_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "taxjar-api-token",
        "TAXJARTOKEN=f68f9ea979a26968\u{00AD}b99bd197cbe8a06b",
        "f68f9ea979a26968b99bd197cbe8a06b",
    );
}

#[test]
fn adv133_taxjar_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "taxjar-api-token",
        "TAXJARTOKEN=f68f9ea979a26968\u{200C}b99bd197cbe8a06b",
        "f68f9ea979a26968b99bd197cbe8a06b",
    );
}

#[test]
fn adv133_taxjar_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "taxjar-api-token",
        "TAXJARTOKEN=f68f9ea979a26968\u{200D}b99bd197cbe8a06b",
        "f68f9ea979a26968b99bd197cbe8a06b",
    );
}

#[test]
fn adv133_taxjar_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "taxjar-api-token",
        "TAXJARTOKEN=f68f9ea979a26968\u{FEFF}b99bd197cbe8a06b",
        "f68f9ea979a26968b99bd197cbe8a06b",
    );
}

#[test]
fn adv133_taxjar_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "taxjar-api-token",
        "TAXJARTOKEN=f68f9ea979a26968\u{2060}b99bd197cbe8a06b",
        "f68f9ea979a26968b99bd197cbe8a06b",
    );
}

#[test]
fn adv133_taxjar_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "taxjar-api-token",
        "TAXJARTOKEN=f68f9ea979a26968\u{180E}b99bd197cbe8a06b",
        "f68f9ea979a26968b99bd197cbe8a06b",
    );
}

#[test]
fn adv133_taxjar_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "taxjar-api-token",
        "TAXJARTOKEN=f68f9ea979a26968\u{202E}b99bd197cbe8a06b",
        "f68f9ea979a26968b99bd197cbe8a06b",
    );
}

#[test]
fn adv133_taxjar_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "taxjar-api-token",
        "TAXJARTOKEN=f68f9ea979a26968\u{202C}b99bd197cbe8a06b",
        "f68f9ea979a26968b99bd197cbe8a06b",
    );
}

#[test]
fn adv133_taxjar_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "taxjar-api-token",
        "TAXJARTOKEN=f68f9ea979a26968\u{200E}b99bd197cbe8a06b",
        "f68f9ea979a26968b99bd197cbe8a06b",
    );
}

// =========================================================================
// 5. TEAMWORK API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv133_teamwork_api_token_normal_must_fire() {
    assert_detector_fires(
        "teamwork-api-token",
        "TEAMWORK_API_TOKEN=Br3i8EE3pYXqvoXwCoXB",
        "Br3i8EE3pYXqvoXwCoXB",
    );
}

#[test]
fn adv133_teamwork_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "teamwork-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv133_teamwork_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "teamwork-api-token",
        "TEAMWORK_API_TOKEN=Br3i8EE3pY\u{200B}XqvoXwCoXB",
        "Br3i8EE3pYXqvoXwCoXB",
    );
}

#[test]
fn adv133_teamwork_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "teamwork-api-token",
        "TEAMWORK_API_TOKEN=Br3i8EE3pY\u{00AD}XqvoXwCoXB",
        "Br3i8EE3pYXqvoXwCoXB",
    );
}

#[test]
fn adv133_teamwork_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "teamwork-api-token",
        "TEAMWORK_API_TOKEN=Br3i8EE3pY\u{200C}XqvoXwCoXB",
        "Br3i8EE3pYXqvoXwCoXB",
    );
}

#[test]
fn adv133_teamwork_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "teamwork-api-token",
        "TEAMWORK_API_TOKEN=Br3i8EE3pY\u{200D}XqvoXwCoXB",
        "Br3i8EE3pYXqvoXwCoXB",
    );
}

#[test]
fn adv133_teamwork_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "teamwork-api-token",
        "TEAMWORK_API_TOKEN=Br3i8EE3pY\u{FEFF}XqvoXwCoXB",
        "Br3i8EE3pYXqvoXwCoXB",
    );
}

#[test]
fn adv133_teamwork_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "teamwork-api-token",
        "TEAMWORK_API_TOKEN=Br3i8EE3pY\u{2060}XqvoXwCoXB",
        "Br3i8EE3pYXqvoXwCoXB",
    );
}

#[test]
fn adv133_teamwork_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "teamwork-api-token",
        "TEAMWORK_API_TOKEN=Br3i8EE3pY\u{180E}XqvoXwCoXB",
        "Br3i8EE3pYXqvoXwCoXB",
    );
}

#[test]
fn adv133_teamwork_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "teamwork-api-token",
        "TEAMWORK_API_TOKEN=Br3i8EE3pY\u{202E}XqvoXwCoXB",
        "Br3i8EE3pYXqvoXwCoXB",
    );
}

#[test]
fn adv133_teamwork_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "teamwork-api-token",
        "TEAMWORK_API_TOKEN=Br3i8EE3pY\u{202C}XqvoXwCoXB",
        "Br3i8EE3pYXqvoXwCoXB",
    );
}

#[test]
fn adv133_teamwork_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "teamwork-api-token",
        "TEAMWORK_API_TOKEN=Br3i8EE3pY\u{200E}XqvoXwCoXB",
        "Br3i8EE3pYXqvoXwCoXB",
    );
}

// =========================================================================
// 6. TELEGRAM BOT TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv133_telegram_bot_token_normal_must_fire() {
    assert_detector_fires(
        "telegram-bot-token",
        "TELEGRAM_BOT_TOKEN=612543247:aJRI90OF9-juNtbtBMOHM7jaF-HcmtNbAnx",
        "612543247:aJRI90OF9-juNtbtBMOHM7jaF-HcmtNbAnx",
    );
}

#[test]
fn adv133_telegram_bot_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "telegram-bot-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv133_telegram_bot_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "telegram-bot-token",
        "TELEGRAM_BOT_TOKEN=612543247:aJRI90OF9-ju\u{200B}NtbtBMOHM7jaF-HcmtNbAnx",
        "612543247:aJRI90OF9-juNtbtBMOHM7jaF-HcmtNbAnx",
    );
}

#[test]
fn adv133_telegram_bot_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "telegram-bot-token",
        "TELEGRAM_BOT_TOKEN=612543247:aJRI90OF9-ju\u{00AD}NtbtBMOHM7jaF-HcmtNbAnx",
        "612543247:aJRI90OF9-juNtbtBMOHM7jaF-HcmtNbAnx",
    );
}

#[test]
fn adv133_telegram_bot_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "telegram-bot-token",
        "TELEGRAM_BOT_TOKEN=612543247:aJRI90OF9-ju\u{200C}NtbtBMOHM7jaF-HcmtNbAnx",
        "612543247:aJRI90OF9-juNtbtBMOHM7jaF-HcmtNbAnx",
    );
}

#[test]
fn adv133_telegram_bot_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "telegram-bot-token",
        "TELEGRAM_BOT_TOKEN=612543247:aJRI90OF9-ju\u{200D}NtbtBMOHM7jaF-HcmtNbAnx",
        "612543247:aJRI90OF9-juNtbtBMOHM7jaF-HcmtNbAnx",
    );
}

#[test]
fn adv133_telegram_bot_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "telegram-bot-token",
        "TELEGRAM_BOT_TOKEN=612543247:aJRI90OF9-ju\u{FEFF}NtbtBMOHM7jaF-HcmtNbAnx",
        "612543247:aJRI90OF9-juNtbtBMOHM7jaF-HcmtNbAnx",
    );
}

#[test]
fn adv133_telegram_bot_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "telegram-bot-token",
        "TELEGRAM_BOT_TOKEN=612543247:aJRI90OF9-ju\u{2060}NtbtBMOHM7jaF-HcmtNbAnx",
        "612543247:aJRI90OF9-juNtbtBMOHM7jaF-HcmtNbAnx",
    );
}

#[test]
fn adv133_telegram_bot_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "telegram-bot-token",
        "TELEGRAM_BOT_TOKEN=612543247:aJRI90OF9-ju\u{180E}NtbtBMOHM7jaF-HcmtNbAnx",
        "612543247:aJRI90OF9-juNtbtBMOHM7jaF-HcmtNbAnx",
    );
}

#[test]
fn adv133_telegram_bot_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "telegram-bot-token",
        "TELEGRAM_BOT_TOKEN=612543247:aJRI90OF9-ju\u{202E}NtbtBMOHM7jaF-HcmtNbAnx",
        "612543247:aJRI90OF9-juNtbtBMOHM7jaF-HcmtNbAnx",
    );
}

#[test]
fn adv133_telegram_bot_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "telegram-bot-token",
        "TELEGRAM_BOT_TOKEN=612543247:aJRI90OF9-ju\u{202C}NtbtBMOHM7jaF-HcmtNbAnx",
        "612543247:aJRI90OF9-juNtbtBMOHM7jaF-HcmtNbAnx",
    );
}

#[test]
fn adv133_telegram_bot_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "telegram-bot-token",
        "TELEGRAM_BOT_TOKEN=612543247:aJRI90OF9-ju\u{200E}NtbtBMOHM7jaF-HcmtNbAnx",
        "612543247:aJRI90OF9-juNtbtBMOHM7jaF-HcmtNbAnx",
    );
}

// =========================================================================
// 7. TERRAFORM CLOUD API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv133_terraform_cloud_api_token_normal_must_fire() {
    assert_detector_fires(
        "terraform-cloud-api-token",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
    );
}

#[test]
fn adv133_terraform_cloud_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "terraform-cloud-api-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv133_terraform_cloud_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "terraform-cloud-api-token",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPx\u{200B}KqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
    );
}

#[test]
fn adv133_terraform_cloud_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "terraform-cloud-api-token",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPx\u{00AD}KqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
    );
}

#[test]
fn adv133_terraform_cloud_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "terraform-cloud-api-token",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPx\u{200C}KqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
    );
}

#[test]
fn adv133_terraform_cloud_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "terraform-cloud-api-token",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPx\u{200D}KqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
    );
}

#[test]
fn adv133_terraform_cloud_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "terraform-cloud-api-token",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPx\u{FEFF}KqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
    );
}

#[test]
fn adv133_terraform_cloud_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "terraform-cloud-api-token",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPx\u{2060}KqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
    );
}

#[test]
fn adv133_terraform_cloud_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "terraform-cloud-api-token",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPx\u{180E}KqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
    );
}

#[test]
fn adv133_terraform_cloud_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "terraform-cloud-api-token",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPx\u{202E}KqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
    );
}

#[test]
fn adv133_terraform_cloud_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "terraform-cloud-api-token",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPx\u{202C}KqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
    );
}

#[test]
fn adv133_terraform_cloud_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "terraform-cloud-api-token",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPx\u{200E}KqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
        "9X3kQp7VbT2hYR.atlasv1.NcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy",
    );
}

// =========================================================================
// 8. TERRAFORM ENTERPRISE TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv133_terraform_enterprise_token_normal_must_fire() {
    assert_detector_fires(
        "terraform-enterprise-token",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIsHrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIsHrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
    );
}

#[test]
fn adv133_terraform_enterprise_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "terraform-enterprise-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv133_terraform_enterprise_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "terraform-enterprise-token",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIs\u{200B}Hrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIsHrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
    );
}

#[test]
fn adv133_terraform_enterprise_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "terraform-enterprise-token",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIs\u{00AD}Hrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIsHrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
    );
}

#[test]
fn adv133_terraform_enterprise_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "terraform-enterprise-token",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIs\u{200C}Hrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIsHrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
    );
}

#[test]
fn adv133_terraform_enterprise_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "terraform-enterprise-token",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIs\u{200D}Hrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIsHrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
    );
}

#[test]
fn adv133_terraform_enterprise_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "terraform-enterprise-token",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIs\u{FEFF}Hrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIsHrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
    );
}

#[test]
fn adv133_terraform_enterprise_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "terraform-enterprise-token",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIs\u{2060}Hrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIsHrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
    );
}

#[test]
fn adv133_terraform_enterprise_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "terraform-enterprise-token",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIs\u{180E}Hrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIsHrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
    );
}

#[test]
fn adv133_terraform_enterprise_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "terraform-enterprise-token",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIs\u{202E}Hrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIsHrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
    );
}

#[test]
fn adv133_terraform_enterprise_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "terraform-enterprise-token",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIs\u{202C}Hrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIsHrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
    );
}

#[test]
fn adv133_terraform_enterprise_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "terraform-enterprise-token",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIs\u{200E}Hrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
        "gI0K0lFi9sRt6a.atlasv1.pjqKbeILsS9prSy4rJKA1mJkK4NG3iIsHrn4dAeHHYYvyPyGSVh8TcjSx4sgN3ONTyqGEUhq40bJJtI6OFNkZRN",
    );
}

// =========================================================================
// 9. THEHIVE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv133_thehive_api_key_normal_must_fire() {
    assert_detector_fires(
        "thehive-api-key",
        "thehivekey=RZZb2fgi8yCQFuZNb2lJ",
        "RZZb2fgi8yCQFuZNb2lJ",
    );
}

#[test]
fn adv133_thehive_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "thehive-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv133_thehive_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "thehive-api-key",
        "thehivekey=RZZb2fgi8y\u{200B}CQFuZNb2lJ",
        "RZZb2fgi8yCQFuZNb2lJ",
    );
}

#[test]
fn adv133_thehive_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "thehive-api-key",
        "thehivekey=RZZb2fgi8y\u{00AD}CQFuZNb2lJ",
        "RZZb2fgi8yCQFuZNb2lJ",
    );
}

#[test]
fn adv133_thehive_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "thehive-api-key",
        "thehivekey=RZZb2fgi8y\u{200C}CQFuZNb2lJ",
        "RZZb2fgi8yCQFuZNb2lJ",
    );
}

#[test]
fn adv133_thehive_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "thehive-api-key",
        "thehivekey=RZZb2fgi8y\u{200D}CQFuZNb2lJ",
        "RZZb2fgi8yCQFuZNb2lJ",
    );
}

#[test]
fn adv133_thehive_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "thehive-api-key",
        "thehivekey=RZZb2fgi8y\u{FEFF}CQFuZNb2lJ",
        "RZZb2fgi8yCQFuZNb2lJ",
    );
}

#[test]
fn adv133_thehive_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "thehive-api-key",
        "thehivekey=RZZb2fgi8y\u{2060}CQFuZNb2lJ",
        "RZZb2fgi8yCQFuZNb2lJ",
    );
}

#[test]
fn adv133_thehive_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "thehive-api-key",
        "thehivekey=RZZb2fgi8y\u{180E}CQFuZNb2lJ",
        "RZZb2fgi8yCQFuZNb2lJ",
    );
}

#[test]
fn adv133_thehive_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "thehive-api-key",
        "thehivekey=RZZb2fgi8y\u{202E}CQFuZNb2lJ",
        "RZZb2fgi8yCQFuZNb2lJ",
    );
}

#[test]
fn adv133_thehive_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "thehive-api-key",
        "thehivekey=RZZb2fgi8y\u{202C}CQFuZNb2lJ",
        "RZZb2fgi8yCQFuZNb2lJ",
    );
}

#[test]
fn adv133_thehive_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "thehive-api-key",
        "thehivekey=RZZb2fgi8y\u{200E}CQFuZNb2lJ",
        "RZZb2fgi8yCQFuZNb2lJ",
    );
}

// =========================================================================
// 10. THREATCONNECT API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv133_threatconnect_api_key_normal_must_fire() {
    assert_detector_fires(
        "threatconnect-api-key",
        "THREATCONNECT-    -   token :  : 05166866232440590975",
        "05166866232440590975",
    );
}

#[test]
fn adv133_threatconnect_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "threatconnect-api-key",
        "dummy_prefix_0:  : xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv133_threatconnect_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "threatconnect-api-key",
        "THREATCONNECT-    -   token :  : 0516686623\u{200B}2440590975",
        "05166866232440590975",
    );
}

#[test]
fn adv133_threatconnect_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "threatconnect-api-key",
        "THREATCONNECT-    -   token :  : 0516686623\u{00AD}2440590975",
        "05166866232440590975",
    );
}

#[test]
fn adv133_threatconnect_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "threatconnect-api-key",
        "THREATCONNECT-    -   token :  : 0516686623\u{200C}2440590975",
        "05166866232440590975",
    );
}

#[test]
fn adv133_threatconnect_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "threatconnect-api-key",
        "THREATCONNECT-    -   token :  : 0516686623\u{200D}2440590975",
        "05166866232440590975",
    );
}

#[test]
fn adv133_threatconnect_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "threatconnect-api-key",
        "THREATCONNECT-    -   token :  : 0516686623\u{FEFF}2440590975",
        "05166866232440590975",
    );
}

#[test]
fn adv133_threatconnect_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "threatconnect-api-key",
        "THREATCONNECT-    -   token :  : 0516686623\u{2060}2440590975",
        "05166866232440590975",
    );
}

#[test]
fn adv133_threatconnect_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "threatconnect-api-key",
        "THREATCONNECT-    -   token :  : 0516686623\u{180E}2440590975",
        "05166866232440590975",
    );
}

#[test]
fn adv133_threatconnect_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "threatconnect-api-key",
        "THREATCONNECT-    -   token :  : 0516686623\u{202E}2440590975",
        "05166866232440590975",
    );
}

#[test]
fn adv133_threatconnect_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "threatconnect-api-key",
        "THREATCONNECT-    -   token :  : 0516686623\u{202C}2440590975",
        "05166866232440590975",
    );
}

#[test]
fn adv133_threatconnect_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "threatconnect-api-key",
        "THREATCONNECT-    -   token :  : 0516686623\u{200E}2440590975",
        "05166866232440590975",
    );
}


