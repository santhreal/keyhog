//! SPEED/som-window (backlog 4786) lever-ceiling gate. Answers, with a concrete
//! count over the embedded detector corpus, whether localizing the whole-chunk
//! confirmed extract to AC trigger positions (the way `ConfirmedAnchorIndex`
//! already localizes prefix patterns) has a non-trivial addressable set of
//! PREFIXLESS patterns.
//!
//! The confirmed `ac_map` partitions into three buckets:
//!   - `prefix_anchored` — a required leading literal; ALREADY localized today
//!     by `ConfirmedAnchorIndex`.
//!   - `prefixless_internal_literal` — no leading literal but a required
//!     internal literal run; the 4786 internal-literal-AC extension COULD
//!     localize these. (HS `SOM_LEFTMOST` is NOT viable for them — it errors
//!     "Pattern too large" on exactly these complex regexes; see
//!     `simd/backend.rs`, so the feasible lever is an internal-literal AC, not
//!     HS-SOM.)
//!   - `whole_chunk_residue` — no required literal at all; irreducibly
//!     whole-chunk, loudly counted.
//!
//! This is a standalone binary (NOT the `unit/root_facade/confirmed_pattern_profile.rs`
//! shard) because it depends ONLY on the public `keyhog_scanner::testing`
//! facade, whereas that file's `_mirror` measurement calls the crate-private
//! `confirmed_profile_dump` and so cannot link outside the lib.

#[test]
fn som_window_localization_ceiling_over_embedded_corpus() {
    let (prefix_anchored, prefixless_internal_literal, whole_chunk_residue) =
        keyhog_scanner::testing::confirmed_pattern_localization_distribution();
    let total = prefix_anchored + prefixless_internal_literal + whole_chunk_residue;
    eprintln!(
        "SPEED/som-window 4786 ceiling — confirmed ac_map localization: \
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
