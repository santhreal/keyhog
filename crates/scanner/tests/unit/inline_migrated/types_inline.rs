//! Migrated from src/types.rs

use keyhog_core::ScanConfig;
use keyhog_scanner::testing::multiline::MultilineConfig;
use keyhog_scanner::ScannerConfig;

mod sanitise_tests {
    use super::*;

    fn baseline_config() -> ScannerConfig {
        // MC-01: ScannerConfig wraps the canonical ScanConfig plus
        // scanner-local knobs. Shared knobs live on `.scan`; the asserts below
        // reach them via Deref (`c.min_confidence`).
        ScannerConfig {
            scan: ScanConfig {
                max_decode_depth: 5,
                validate_decode: true,
                entropy_enabled: true,
                entropy_threshold: 4.5,
                entropy_in_source_files: false,
                entropy_ml_authoritative: true,
                generic_keyword_low_entropy: true,
                #[cfg(not(feature = "ml"))]
                ml_enabled: false,
                ml_weight: 0.6,
                min_confidence: 0.3,
                unicode_normalization: true,
                max_decode_bytes: 65_536,
                max_matches_per_chunk: 1000,
                scan_comments: false,
                known_prefixes: vec![],
                secret_keywords: vec![],
                test_keywords: vec![],
                placeholder_keywords: vec![],
                ..ScanConfig::default()
            },
            multiline: MultilineConfig::default(),
            penalize_test_paths: true,
            per_chunk_timeout_ms: None,
            ..ScannerConfig::default()
        }
    }

    #[test]
    fn sanitise_clamps_negative_min_confidence() {
        let mut c = baseline_config();
        c.min_confidence = -5.0;
        c.sanitise();
        assert_eq!(c.min_confidence, 0.0);
    }

    #[test]
    fn sanitise_clamps_supra_unit_ml_weight() {
        let mut c = baseline_config();
        c.ml_weight = 99.0;
        c.sanitise();
        assert_eq!(c.ml_weight, 1.0);
    }

    #[test]
    fn sanitise_replaces_nan_min_confidence() {
        let mut c = baseline_config();
        c.min_confidence = f64::NAN;
        c.sanitise();
        assert!(c.min_confidence.is_finite(), "NaN must be replaced");
        assert!((0.0..=1.0).contains(&c.min_confidence));
    }

    #[test]
    fn sanitise_replaces_infinite_entropy_threshold() {
        let mut c = baseline_config();
        c.entropy_threshold = f64::INFINITY;
        c.sanitise();
        assert!(c.entropy_threshold.is_finite());
        assert!(c.entropy_threshold <= 8.0);

        c.entropy_threshold = f64::NEG_INFINITY;
        c.sanitise();
        assert!(c.entropy_threshold.is_finite());
        assert!(c.entropy_threshold >= 0.0);
    }

    #[test]
    fn sanitise_caps_pathological_max_decode_depth() {
        let mut c = baseline_config();
        c.max_decode_depth = 9999;
        c.sanitise();
        assert_eq!(
            c.max_decode_depth,
            keyhog_core::testing::CoreTestApi::max_decode_depth_limit(
                &keyhog_core::testing::TestApi,
            ),
            "scanner sanitise must use the same decode-depth ceiling as CLI/TOML"
        );
    }

    #[test]
    fn sanitise_caps_pathological_max_matches_per_chunk() {
        let mut c = baseline_config();
        c.max_matches_per_chunk = 1_000_000_000;
        c.sanitise();
        assert!(c.max_matches_per_chunk <= 1_000_000);

        c.max_matches_per_chunk = 0;
        c.sanitise();
        assert!(
            c.max_matches_per_chunk > 0,
            "zero would silently disable all matching"
        );
    }

    #[test]
    fn sanitise_is_idempotent_on_sane_config() {
        let original = baseline_config();
        let mut c = baseline_config();
        c.sanitise();
        assert_eq!(c.min_confidence, original.min_confidence);
        assert_eq!(c.ml_weight, original.ml_weight);
        assert_eq!(c.entropy_threshold, original.entropy_threshold);
        assert_eq!(c.max_decode_depth, original.max_decode_depth);
        assert_eq!(c.max_matches_per_chunk, original.max_matches_per_chunk);
    }
}
