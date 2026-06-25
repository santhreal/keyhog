//! Regression: two leading-construct shapes that previously defeated literal
//! prefix extraction must now route through their real prefixes.
//!
//!   * A leading zero-width assertion (`\bser\.[a-zA-Z0-9]{40,}`, flagsmith):
//!     the `\b` broke extraction at the first byte, so the detector carried no
//!     AC trigger / literal-prefix anchor and the bare `ser.<40>` positive
//!     dropped below the confidence floor (contracts_runner: flagsmith MISSED).
//!     Leading `\b`/`\B`/`\A`/`^` are now stripped and `ser.` is the prefix.
//!
//!   * A leading alternation of SHORT literals extended by a trailing literal
//!     (`(?:pk|sk)\.[a-f0-9]{32,}`, locationiq): `pk`/`sk` are below the 3-char
//!     floor on their own, so the per-branch path declined and the detector
//!     carried no prefix anchor (contracts_runner: locationiq MISSED). The
//!     post-group `\.` is now carried onto every branch yielding `pk.`/`sk.`.
//!
//! Each positive is paired with a precision twin proving the recovered prefix
//! did not widen the detector: a word-internal `ser.` (no `\b`) and a too-short
//! locationiq body must NOT be claimed.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::OnceLock;

fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
        CompiledScanner::compile(detectors).expect("compile scanner")
    })
}

fn matches_for(body: &str) -> Vec<(String, String)> {
    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata {
            source_type: "leading-construct-prefix-regression".into(),
            path: Some("notes/leading-construct-probe.txt".into()),
            ..Default::default()
        },
    };
    scanner().clear_fragment_cache();
    scanner()
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}

#[test]
fn flagsmith_word_boundary_prefixed_token_surfaces() {
    // `ser.` + 41 alnum (>= the detector's {40,} body).
    let token = "ser.7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7";
    let matches = matches_for(&format!("FLAGSMITH_KEY={token}"));
    assert!(
        matches
            .iter()
            .any(|(id, found)| id == "flagsmith-api-key" && found == token),
        "flagsmith ser. token must surface past the leading \\b; matches={matches:?}"
    );
}

#[test]
fn flagsmith_word_internal_ser_is_not_claimed() {
    // `user.` embeds `ser.` but has no word boundary before `ser`, so the `\b`
    // anchor must keep the detector from firing — the strip recovered the
    // prefix, it did not drop the boundary semantics.
    let matches = matches_for("myuser.7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d3a5e9f1b7more");
    assert!(
        !matches.iter().any(|(id, _)| id == "flagsmith-api-key"),
        "word-internal ser. must not be claimed by flagsmith; matches={matches:?}"
    );
}

#[test]
fn locationiq_pk_alternation_token_surfaces() {
    // `pk.` + 60 hex (>= the detector's {32,} body).
    let token = "pk.b02a70db24b788f217af47231d91e27e96c388b92f008b39c24addc0706";
    let matches = matches_for(&format!("LOCATIONIQ_API_KEY={token}"));
    assert!(
        matches
            .iter()
            .any(|(id, found)| id == "locationiq-api-token" && found == token),
        "locationiq pk. token must surface via the alternation-tail prefix; matches={matches:?}"
    );
}

#[test]
fn locationiq_short_body_is_not_claimed() {
    // `pk.` + only 8 hex is below the {32,} body floor, so the detector must
    // not fire — the recovered `pk.`/`sk.` prefixes route candidates, the full
    // regex still gates on body length.
    let matches = matches_for("LOCATIONIQ_API_KEY=pk.b02a70db");
    assert!(
        !matches.iter().any(|(id, _)| id == "locationiq-api-token"),
        "short locationiq body must not be claimed; matches={matches:?}"
    );
}
