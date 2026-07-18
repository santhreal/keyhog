//! SPEED/som-window (backlog 4786) lever-ceiling gate. Answers, with a concrete
//! count over the embedded detector corpus, whether localizing the whole-chunk
//! confirmed extract to AC trigger positions (the way `ConfirmedAnchorIndex`
//! already localizes prefix patterns) has a non-trivial addressable set of
//! PREFIXLESS patterns.
//!
//! The confirmed `ac_map` partitions into three buckets:
//!   - `prefix_anchored`: a required leading literal; ALREADY localized today
//!     by `ConfirmedAnchorIndex`.
//!   - `prefixless_internal_literal`: no leading literal but a required
//!     internal literal run; the 4786 internal-literal-AC extension COULD
//!     localize these. (HS `SOM_LEFTMOST` is NOT viable for them, it errors
//!     "Pattern too large" on exactly these complex regexes; see
//!     `simd/backend.rs`, so the feasible lever is an internal-literal AC, not
//!     HS-SOM.)
//!   - `whole_chunk_residue`: no required literal at all; irreducibly
//!     whole-chunk, loudly counted.
//!
//! This is a standalone binary (NOT the `unit/root_facade/confirmed_pattern_profile.rs`
//! shard) because it depends ONLY on the public `keyhog_scanner::testing`
//! facade, whereas that file's `_mirror` measurement calls the crate-private
//! `confirmed_profile_dump` and so cannot link outside the lib.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScannerConfig};

#[test]
fn som_window_localization_ceiling_over_embedded_corpus() {
    let (prefix_anchored, prefixless_internal_literal, whole_chunk_residue) =
        keyhog_scanner::testing::confirmed_pattern_localization_distribution();
    let total = prefix_anchored + prefixless_internal_literal + whole_chunk_residue;
    eprintln!(
        "SPEED/som-window 4786 ceiling, confirmed ac_map localization: \
         prefix_anchored={prefix_anchored} \
         prefixless_internal_literal={prefixless_internal_literal} \
         whole_chunk_residue={whole_chunk_residue} total={total}"
    );
    assert!(
        total > 0,
        "the embedded detector corpus must produce confirmed ac_map patterns"
    );
    // The 4786 internal-literal-AC lever addresses `prefixless_internal_literal`.
    // Lock that it is NON-MOOT: there must exist prefixless confirmed patterns
    // that carry a required internal literal (otherwise the whole lever buys
    // nothing beyond the existing prefix localizer). Loose, drift-proof floor.
    assert!(
        prefixless_internal_literal > 0,
        "4786 internal-literal localization must have addressable prefixless patterns; \
         got prefix_anchored={prefix_anchored} prefixless_internal_literal={prefixless_internal_literal} \
         whole_chunk_residue={whole_chunk_residue}"
    );
}

#[test]
fn optional_api_header_shape_is_localized_without_changing_findings() {
    let detector_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../detectors");
    let detectors = keyhog_core::load_detectors(&detector_dir).expect("detectors load");
    let target_ids = [
        "opensea-api-key",
        "omnisend-api-key",
        "moosend-api-key",
        "skyscanner-api-key",
        "8x8-api-credentials",
        "x2y2-api-key",
    ];
    for detector_id in target_ids {
        let detector = detectors
            .iter()
            .find(|detector| detector.id == detector_id)
            .unwrap_or_else(|| panic!("missing detector {detector_id}"));
        let reverse = detector
            .patterns
            .iter()
            .filter(|pattern| {
                pattern
                    .description
                    .as_deref()
                    .is_some_and(|description| description.contains("preceding"))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            reverse.len(),
            1,
            "{detector_id} must have one coherent reverse-order header pattern"
        );
        let prefixes =
            keyhog_scanner::testing::confirmed_required_prefix_literals(&reverse[0].regex)
                .unwrap_or_else(|| panic!("{detector_id} reverse header is not localizable"));
        assert_eq!(
            prefixes.len(),
            7,
            "{detector_id} must retain the seven finite header-prefix spellings"
        );
    }

    let mut config = ScannerConfig::default();
    config.ml_enabled = false;
    config.min_confidence = 0.0;
    let opensea = detectors
        .into_iter()
        .find(|detector| detector.id == "opensea-api-key")
        .expect("OpenSea detector exists");
    let scanner = CompiledScanner::compile(vec![opensea])
        .expect("provider header scanner compiles")
        .with_config(config);

    let credential = "0123456789abcdef0123456789abcdef";
    for header in [
        "x-api-key",
        "x_api_key",
        "x api key",
        "x-api_key",
        "xapikey",
        "x\napi-key",
        "x\u{b}api-key",
        "x\u{c}api-key",
        "x\u{a0}api-key",
    ] {
        let text = format!("{header}: {credential}\nhttps://api.opensea.io/v1");
        let findings = scanner.scan(&Chunk {
            data: text.into(),
            metadata: ChunkMetadata {
                source_type: "confirmed-anchor-localization".into(),
                path: Some("opensea.env".into()),
                ..ChunkMetadata::default()
            },
        });
        assert_eq!(
            findings.len(),
            1,
            "accepted `{header}` spelling must produce one exact finding: {findings:?}"
        );
        assert_eq!(findings[0].detector_id.as_ref(), "opensea-api-key");
        assert_eq!(
            findings[0].credential.as_ref(),
            credential,
            "localized extraction changed the credential for `{header}`"
        );
    }
}
