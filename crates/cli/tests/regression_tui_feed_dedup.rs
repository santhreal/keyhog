//! Regression: the `keyhog tui` live feed must surface the SAME finding set the
//! `keyhog scan` reporter does, not raw per-chunk hits.
//!
//! Dogfood defect (fixed in `fix(tui): … deduped feed`): the worker streamed
//! every `scanner.scan` hit straight to the UI, so a single `ghp_…`/`sk_live_…`
//! line showed up multiple times — once per detector that fired on it (the
//! specific detector plus the entropy-token / generic-secret overlays) — and the
//! stats `findings` count disagreed with the reporter. The fix routes each chunk
//! through `dedup_file_findings`, the same severity-sort + `dedup_matches`
//! (credential scope) + `dedup_cross_detector` pipeline the reporter applies.
//!
//! Two layers of coverage:
//!   1. behavioural — drive `dedup_file_findings` on a chunk that genuinely
//!      exercises the overlap (raw scan repeats a credential) and assert the
//!      result carries each credential at most once, with the structured
//!      high-value secrets surviving exactly once.
//!   2. wiring — pin the worker to actually call the pipeline before it
//!      counts/streams, so a revert to raw emit fails here rather than only in a
//!      manual tmux dogfood.
#![cfg(feature = "tui")]

use keyhog::subcommands::tui::dedup_file_findings;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::engine::CompiledScanner;

/// Compile the real embedded detector corpus, exactly as `keyhog tui` does at
/// startup — the dedup overlap we are guarding only exists with the production
/// detector set (entropy / generic-secret overlays layered on the structured
/// provider detectors).
fn embedded_scanner() -> CompiledScanner {
    let mut detectors = Vec::new();
    for (_path, toml_str) in keyhog_core::embedded_detector_tomls() {
        if let Ok(mut ds) = keyhog_core::load_detectors_from_str(toml_str) {
            detectors.append(&mut ds);
        }
    }
    assert!(
        !detectors.is_empty(),
        "embedded detector corpus must be non-empty"
    );
    CompiledScanner::compile(detectors).expect("compile embedded scanner")
}

fn chunk_of(body: &str) -> Chunk {
    Chunk {
        data: body.to_string().into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("fixture.env".to_string()),
            ..Default::default()
        },
    }
}

#[test]
fn tui_feed_dedups_to_reporter_finding_set() {
    let scanner = embedded_scanner();

    // One chunk holding several distinct, real-shape secrets. The structured
    // tokens (Stripe `sk_live_`, GitHub `ghp_`) carry valid checksums so they
    // are actually detected — and they also trip the entropy/generic overlays,
    // which is the over-surfacing the dedup folds.
    let body = "\
STRIPE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH
token: \"ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ab\"
password = \"S3cr3tP@ssw0rd_hunter2_xyzzy\"
api_secret = aGVsbG93b3JsZHNlY3JldGtleTEyMzQ1Njc4OTBhYmM
";
    let chunk = chunk_of(body);

    let raw = scanner.scan(&chunk);
    let deduped = dedup_file_findings(&scanner, &chunk);

    // The fixture must genuinely exercise the dedup: the raw per-chunk scan
    // repeats at least one credential (specific detector + overlay on the same
    // token). If this ever stops holding, the test is no longer guarding the
    // real over-surfacing and must be strengthened — fail loudly.
    let mut raw_creds: Vec<String> = raw.iter().map(|m| m.credential.to_string()).collect();
    raw_creds.sort();
    let raw_unique = {
        let mut c = raw_creds.clone();
        c.dedup();
        c
    };
    assert!(
        raw_creds.len() > raw_unique.len(),
        "fixture should exercise the dedup: raw scan must repeat a credential \
         (raw={} unique={}) — raw creds: {raw_creds:?}",
        raw_creds.len(),
        raw_unique.len()
    );

    // Dedup never invents findings.
    assert!(
        deduped.len() <= raw.len(),
        "dedup produced MORE findings ({}) than raw scan ({})",
        deduped.len(),
        raw.len()
    );

    // Load-bearing invariant: the live feed must not show the same secret twice.
    let mut creds: Vec<String> = deduped.iter().map(|m| m.credential.to_string()).collect();
    creds.sort();
    let unique = {
        let mut c = creds.clone();
        c.dedup();
        c
    };
    assert_eq!(
        creds, unique,
        "TUI feed surfaced the same credential more than once: {creds:?}"
    );

    // The structured high-value secrets survive dedup exactly once each — not
    // dropped, not duplicated by their overlays.
    let count_containing = |needle: &str| -> usize {
        deduped
            .iter()
            .filter(|m| m.credential.contains(needle))
            .count()
    };
    assert_eq!(
        count_containing("sk_live_4eC39HqLyjWDarjtT1zdp7dc"),
        1,
        "Stripe secret key must surface exactly once; deduped: {:?}",
        deduped
            .iter()
            .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        count_containing("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ab"),
        1,
        "GitHub PAT must surface exactly once; deduped: {:?}",
        deduped
            .iter()
            .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn tui_worker_routes_every_chunk_through_dedup_before_emit() {
    // Wiring guard: the behavioural test above proves the pipeline is correct;
    // this pins the worker to actually use it. A revert to streaming raw
    // `scanner.scan` hits (the original defect) must fail here, not only under a
    // manual tmux dogfood.
    let worker_src = include_str!("../src/subcommands/tui/worker.rs");
    assert!(
        worker_src.contains("dedup_file_findings(&scanner, &chunk)"),
        "tui worker must dedup each chunk via dedup_file_findings before emitting"
    );
    assert!(
        worker_src.contains("for m in &deduped"),
        "tui worker must stream the DEDUPED set, not raw per-chunk matches"
    );
    assert!(
        !worker_src.contains("for m in &matches"),
        "tui worker must not stream raw per-chunk `matches` to the feed"
    );
}
