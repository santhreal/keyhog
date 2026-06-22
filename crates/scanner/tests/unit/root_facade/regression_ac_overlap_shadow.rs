//! Regression: phase-1 AC triggers use OVERLAPPING matching so a detector whose
//! base literal is a substring of a longer matched literal is still AC-confirmed,
//! not left to the always-active homoglyph variant.
//!
//! `client_secret="…"` nests the literal `secret` (generic-password pattern 4's
//! trigger) inside `client_secret` (pattern 5's quoted-JSON literal). A
//! non-overlapping sweep reports `client_secret`, skips past it, and SHADOWS
//! `secret`, so generic-password pattern 4 was never AC-confirmed — only the
//! always-active homoglyph variant caught it on ASCII. That blocked the homoglyph
//! ASCII-skip (skipping the variant dropped the finding). Overlapping triggers
//! reproduce it via the AC/confirmed path, so the skip is recall-safe and now
//! defaults ON. On the mirror corpus this also clears the overlap-suppression
//! cascade that mislabelled `MAILGUN_API_KEY=key-…` as a Webhook-Signing-Key.

use super::support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn chunk(body: &str) -> Chunk {
    Chunk {
        data: body.to_string().into(),
        metadata: ChunkMetadata {
            source_type: "ac-overlap-shadow".into(),
            path: Some("fixture.env".into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

#[test]
fn shadowed_inner_literal_is_ac_confirmed_with_variant_skipped() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let detectors: Vec<_> = detectors
        .into_iter()
        .filter(|detector| detector.id == "generic-password")
        .collect();
    assert_eq!(detectors.len(), 1, "fixture requires generic-password");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    let c = chunk("client_secret=\"0123456789abcdefABCDEFxyz\"\n");

    // Skip the always-active homoglyph variant on ASCII AND force the legacy HS
    // prefilter off, so the pure AC trigger sweep is the ONLY thing that can
    // confirm generic-password — isolating the overlapping-trigger fix. Before it,
    // the `secret` literal was shadowed by `client_secret` and this dropped to
    // zero generic-password matches.
    keyhog_scanner::testing::set_phase2_hs(&scanner, Some(false));
    keyhog_scanner::testing::set_homoglyph_ascii_skip(&scanner, Some(true));
    scanner.clear_fragment_cache();
    let matches: Vec<_> = scanner
        .scan_chunks_with_backend(std::slice::from_ref(&c), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .collect();
    keyhog_scanner::testing::set_homoglyph_ascii_skip(&scanner, None);
    keyhog_scanner::testing::set_phase2_hs(&scanner, None);

    let gp = matches
        .iter()
        .find(|m| m.detector_id.to_string() == "generic-password");
    assert!(
        gp.is_some(),
        "generic-password must be AC-confirmed on `client_secret=\"…\"` even with the \
         homoglyph variant skipped (overlapping-trigger fix); got detectors: {:?}",
        matches
            .iter()
            .map(|m| m.detector_id.to_string())
            .collect::<Vec<_>>()
    );
    assert!(
        gp.unwrap().credential.contains("0123456789abcdefABCDEFxyz"),
        "generic-password must extract the secret value, got {:?}",
        gp.unwrap().credential.to_string()
    );
    // NOTE: the downstream precision win this fix also delivers — `MAILGUN_API_KEY=
    // key-…` classifying as mailgun-api-key (CRITICAL) instead of the mislabelled
    // mailgun-webhook-signing-key (HIGH) — is an EMERGENT full-pipeline property
    // (SimdCpu trigger + cross-detector dedup + report finalize), verified against
    // the mirror ground-truth manifest by the corpus differential, not reproducible
    // from a single-line `scanner.scan`, so it is intentionally not asserted here.
}
