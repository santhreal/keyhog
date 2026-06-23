//! Known-example suppression for entropy fallback candidates.

use crate::adjudicate::EntropyShapeStage;
use keyhog_core::Chunk;

/// The entropy-fallback known-example / placeholder gate, lift-aware.
///
/// Off the lift (`canonical_lift == false`) this routes through the standard
/// typed known-example suppression context with entropy attached. The lift path
/// only diverges for a candidate the generation lift just produced under a
/// strong credential anchor — a canonical hash/UUID/serial shape — and only
/// releases the two SHAPE arms that would HARD-DROP it before the MoE scores it:
///   * the bare-hash-digest arm (hex32/40/64/128 — the `hex64` AES-256-key miss
///     class), released via the existing `allow_canonical_hex_key` exemption
///     threaded into `suppression_stage_inner`; and
///   * the UUID-v4 shape arm (the `UUID` miss class), which
///     [`suppress_known_example_credential`] gates only on `!bypass_shape_gates` and never
///     exempts — so for an EXACT-UUID lifted value we bypass that decision-tree
///     entry entirely and apply the CONTENT gates ourselves (doc/placeholder
///     markers + repetitive-run + decoded-placeholder), keeping a
///     `00000000-0000-0000-0000-000000000000` / `EXAMPLE`-bearing UUID dropped.
///
/// Every CONTENT gate stays live on both paths; only the recall-load-bearing
/// SHAPE arms are released, and only for the model-arbitrated lift surface.
pub(super) fn entropy_fallback_example_suppression_stage(
    entropy_match: &crate::entropy::EntropyMatch,
    chunk: &Chunk,
    canonical_lift: bool,
) -> Option<EntropyShapeStage> {
    let value = entropy_match.value.as_str();
    let path = chunk.metadata.path.as_deref();
    let source = Some(chunk.metadata.source_type.as_str());

    if !canonical_lift {
        let isolated_bare_token =
            entropy_match.keyword == crate::entropy::ISOLATED_BARE_ENTROPY_LABEL;
        let example_ctx = crate::suppression::api::KnownExampleSuppressionCtx::with_entropy(
            path,
            crate::context::CodeContext::Unknown,
            source,
            entropy_match.entropy,
            false,
            isolated_bare_token,
            false,
        );
        return crate::suppression::api::suppress_known_example_credential_stage(
            value,
            example_ctx,
        )
        .map(|stage_id| EntropyShapeStage::SuppressionStage(stage_id.as_str()));
    }

    // Lift path. ALL lifted canonical shapes (UUID, hex digest, serial) first
    // pass the crate-visible CONTENT gate — `is_known_example_credential`
    // (EXAMPLE suffix, x/X masking filler, monotonic/repetitive hex bodies,
    // empty-input MD5/SHA hashes) + `contains_placeholder_word`
    // (`changeme`/`yourkey`/…) + the run-of-identical check (all-zero /
    // `deadbeef`-style). These are the SAME content markers the strict path
    // applies; only the shape arm is what the lift releases, so a documentation
    // placeholder of ANY canonical shape stays dropped.
    if crate::context::is_known_example_credential(value) {
        return Some(EntropyShapeStage::SuppressionStage(
            "algorithmic_placeholder",
        ));
    }
    if crate::confidence::contains_placeholder_word(value) {
        return Some(EntropyShapeStage::SuppressionStage("placeholder_word"));
    }
    if crate::suppression::shape::has_three_or_more_consecutive_identical(value) {
        return Some(EntropyShapeStage::SuppressionStage("repetitive_run"));
    }

    // An EXACT-UUID value cannot be exempted inside `suppression_stage_inner` (its
    // UUID arm always fires regardless of `allow_canonical_hex_key`), so for a
    // clean UUID the content gate above is the whole verdict — let it through to
    // the model.
    if crate::suppression::shape::is_uuid_v4_shape(value) {
        return None;
    }

    // Non-UUID lifted value (canonical hex / serial). The entropy-aware variant
    // with `allow_canonical_hex_key = true` releases ONLY the bare-hash-digest
    // arm; every other CONTENT gate inside the decision tree (markers,
    // placeholders, license serials, npm-integrity, prefixed digests) still
    // fires, so `AKIAEXAMPLE…`-class and labelled-digest values stay dropped.
    let example_ctx = crate::suppression::api::KnownExampleSuppressionCtx::with_entropy(
        path,
        crate::context::CodeContext::Unknown,
        source,
        entropy_match.entropy,
        true,
        false,
        false,
    );
    crate::suppression::api::suppress_known_example_credential_stage(value, example_ctx)
        .map(|stage_id| EntropyShapeStage::SuppressionStage(stage_id.as_str()))
}
