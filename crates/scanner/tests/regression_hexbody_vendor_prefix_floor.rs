//! Recall + precision contract for distinctive-prefix, pure-hex-body vendor
//! tokens whose prefix was missing from `confidence::KNOWN_PREFIXES`.
//!
//! ROOT CAUSE (dogfood 2026-06-30): a service-anchored detector whose regex is
//! `<distinctive-prefix>[a-f0-9]{N}` (Shopify `shpat_`, Brevo `xkeysib-`,
//! RubyGems `rubygems_`, Postman `PMAK-`, Shippo `shippo_live_`, Flipt
//! `flipt_`) earns almost no entropy/shape signal from its pure-hex body, so
//! `compute_confidence` normalises a bare-token match below the 0.40 floor and
//! `apply_post_ml_penalties` crushes it further — the match is silently dropped
//! as `below_min_confidence`. deepseek `sk-<32hex>` survived the IDENTICAL hex
//! body only because `sk-` was in `KNOWN_PREFIXES` (earning the 0.8 floor that
//! is applied AFTER the penalties) while `shpat_<32hex>` was not: a real recall
//! bug on critical-severity vendor tokens.
//!
//! This suite is SELF-VALIDATING: it proves each newly-floored prefix surfaces
//! its exact-shape token on BOTH CPU backends (recall), and that the floor does
//! NOT over-lift — a degenerate all-zero body and a bad-checksum token stay
//! suppressed (precision). It also source-locks the enrolment so the fix cannot
//! silently regress.

mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::OnceLock;

const CPU_BACKENDS: [ScanBackend; 2] = [ScanBackend::SimdCpu, ScanBackend::CpuFallback];

// Exact-shape tokens: `<prefix><valid-length high-entropy lowercase hex>`.
// The hex bodies are varied (not degenerate) and carry no placeholder word.
const SHOPAT: &str = "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"; // shpat_ + 32
const SHOPCA: &str = "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"; // shpca_ + 32
const SHOPSS: &str = "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"; // shpss_ + 32
const BREVO: &str = "xkeysib-4e1d93c6b8072a5f9e13d0c7b4a8623f1a2b3c4d5e6f70819a0b1c2d3e4f5061"; // + 64
const RUBYGEMS: &str = "rubygems_4e1d93c6b8072a5f9e13d0c7b4a8623f1a2b3c4d5e6f7081"; // + 48
const POSTMAN: &str = "PMAK-4e1d93c6b8072a5f9e13d0c7-b4a8623f1a2b3c4d5e6f70819a0b1c2d3e"; // 24-34
const SHIPPO: &str = "shippo_live_4e1d93c6b8072a5f9e13d0c7b4a8623f"; // + 32
const FLIPT: &str = "flipt_4e1d93c6b8072a5f9e13d0c7b4a8623f1a2b3c4d"; // + 40

fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors =
            keyhog_core::load_detectors(&support::paths::detector_dir()).expect("detectors");
        CompiledScanner::compile(detectors).expect("compile")
    })
}

fn chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "hexbody-prefix-floor".into(),
            path: Some("fixtures/tokens.env".into()),
            ..Default::default()
        },
    }
}

fn reports_on_both(detector: &str, text: &str, credential: &str) -> bool {
    let scanner = scanner();
    CPU_BACKENDS.iter().all(|&backend| {
        scanner.clear_fragment_cache();
        scanner
            .scan_with_backend(&chunk(text), backend)
            .iter()
            .any(|m| m.detector_id.as_ref() == detector && m.credential.as_ref() == credential)
    })
}

fn detector_absent_on_both(detector: &str, text: &str) -> bool {
    let scanner = scanner();
    CPU_BACKENDS.iter().all(|&backend| {
        scanner.clear_fragment_cache();
        scanner
            .scan_with_backend(&chunk(text), backend)
            .iter()
            .all(|m| m.detector_id.as_ref() != detector)
    })
}

/// Emit two recall tests per case: bare `API_TOKEN=` context (no vendor keyword,
/// the exact context that was dropping the token) and end-of-input.
macro_rules! recall_case {
    ($env:ident, $eof:ident, $det:expr, $tok:expr) => {
        #[test]
        fn $env() {
            assert!(
                reports_on_both($det, &format!("API_TOKEN={}\n", $tok), $tok),
                "{} must surface its exact hex token in a bare API_TOKEN= context \
                 (the recall bug this floor fixes)",
                $det
            );
        }
        #[test]
        fn $eof() {
            assert!(
                reports_on_both($det, $tok, $tok),
                "{} must surface its exact hex token at end of input",
                $det
            );
        }
    };
}

recall_case!(
    shopify_admin_env_reports,
    shopify_admin_eof_reports,
    "shopify-admin-api-token",
    SHOPAT
);
recall_case!(
    shopify_access_env_reports,
    shopify_access_eof_reports,
    "shopify-access-token",
    SHOPCA
);
recall_case!(
    shopify_storefront_env_reports,
    shopify_storefront_eof_reports,
    "shopify-storefront-api-token",
    SHOPSS
);
recall_case!(brevo_env_reports, brevo_eof_reports, "brevo-api-key", BREVO);
recall_case!(
    rubygems_env_reports,
    rubygems_eof_reports,
    "rubygems-api-key",
    RUBYGEMS
);
recall_case!(
    postman_env_reports,
    postman_eof_reports,
    "postman-api-key",
    POSTMAN
);
recall_case!(
    shippo_env_reports,
    shippo_eof_reports,
    "shippo-api-token",
    SHIPPO
);
recall_case!(
    flipt_env_reports,
    flipt_eof_reports,
    "flipt-api-token",
    FLIPT
);

// ---- precision: the floor must NOT over-lift ----

#[test]
fn shopify_admin_degenerate_all_zero_body_stays_suppressed() {
    // A 32-`0` body is a `is_degenerate_repeat` value; `known_prefix_confidence_floor`
    // returns None for it, so it must NOT be lifted to a finding.
    let degenerate = "shpat_00000000000000000000000000000000";
    assert!(
        detector_absent_on_both(
            "shopify-admin-api-token",
            &format!("API_TOKEN={degenerate}\n")
        ),
        "a degenerate all-zero body must not be floored into a shopify finding"
    );
}

#[test]
fn brevo_degenerate_all_zero_body_stays_suppressed() {
    let degenerate = format!("xkeysib-{}", "0".repeat(64));
    assert!(
        detector_absent_on_both("brevo-api-key", &format!("API_TOKEN={degenerate}\n")),
        "a degenerate all-zero body must not be floored into a brevo finding"
    );
}

#[test]
fn bad_checksum_npm_still_suppressed_despite_floor() {
    // `npm_` IS in KNOWN_PREFIXES and IS checksum-gated. The known-prefix floor
    // (0.8) is applied before the checksum policy, which returns None on an
    // invalid CRC and DROPS the match — the floor must never resurrect a
    // checksum-invalid token. This fabricated body has an invalid CRC32.
    let bad = "npm_aK9mZ2xQ7wB4nR1tY6vC3sJ8fG5hL0pP2oM7";
    assert!(
        detector_absent_on_both("npm-access-token", &format!("API_TOKEN={bad}\n")),
        "a checksum-invalid npm token must stay dropped even though npm_ is floored"
    );
}

// ---- differential: shpat_ now behaves like the sk- control on identical bytes ----

#[test]
fn shopify_admin_reports_like_deepseek_on_identical_hex_context() {
    let hex = "4e1d93c6b8072a5f9e13d0c7b4a8623f"; // 32 hex
    let shpat = format!("shpat_{hex}");
    let sk = format!("sk-{hex}");
    assert!(
        reports_on_both(
            "shopify-admin-api-token",
            &format!("API_TOKEN={shpat}\n"),
            &shpat
        ),
        "shpat_<32hex> must surface just like the sk- control on the identical body"
    );
    assert!(
        reports_on_both("deepseek-api-key", &format!("API_TOKEN={sk}\n"), &sk),
        "deepseek sk-<32hex> control must keep reporting (no regression)"
    );
}

// ---- source-lock: the enrolment cannot silently regress ----

#[test]
fn known_prefixes_contains_every_new_hexbody_prefix() {
    // Read the canonical list through the crate's test seam so a future edit
    // that drops one of these prefixes fails here, not silently in the field.
    let expected = [
        "shpat_",
        "shpca_",
        "shpss_",
        "xkeysib-",
        "rubygems_",
        "PMAK-",
        "shippo_live_",
        "flipt_",
    ];
    for prefix in expected {
        assert!(
            keyhog_scanner::testing::confidence::known_prefix_confidence_floor(&format!(
                "{prefix}deadbeef"
            ))
            .is_some(),
            "prefix {prefix:?} must earn the known-prefix confidence floor"
        );
    }
}
