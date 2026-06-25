//! Regression: a detector whose regex opens with a literal run interrupted by
//! a SMALL, fully-enumerable character class (`dd[npc]_[a-f0-9]{64}`) must
//! route through the expanded per-member prefixes (`ddn_`, `ddp_`, `ddc_`) so
//! the bare token earns its literal-prefix anchor and clears the confidence
//! floor.
//!
//! `extract_literal_prefix` stops at the `[` with only `dd` (below the 3-char
//! floor), so before the fix `deno-kv-credentials` carried NO prefix anchor:
//! the plain `ddn_<64hex>` positive scored below `min_confidence` and dropped
//! as `below_min_confidence` (contracts_runner: deno-kv MISSED). The plural
//! extractor now enumerates the class into one concrete literal prefix per
//! member — the exact analogue of expanding a `(n|p|c)` alternation.
//!
//! The precision twin pins that the expansion is FAITHFUL to the class: a token
//! whose third char is NOT a class member (`ddz_…`, z ∉ [npc]) must not be
//! claimed by the detector. The expansion adds triggers for the real members
//! only; it does not widen the detector to any `dd?_` shape.

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
            source_type: "charclass-prefix-expansion-regression".into(),
            path: Some("notes/charclass-probe.txt".into()),
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

const HEX64: &str = "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d";

#[test]
fn deno_kv_ddn_member_surfaces_via_expanded_prefix() {
    let token = format!("ddn_{HEX64}");
    let matches = matches_for(&token);
    assert!(
        matches
            .iter()
            .any(|(id, found)| id == "deno-kv-credentials" && found == &token),
        "ddn_ Deno KV token must surface through the expanded literal prefix; matches={matches:?}"
    );
}

#[test]
fn deno_kv_ddc_member_surfaces_via_expanded_prefix() {
    // A different class member proves the expansion covers EVERY branch, not
    // just the first.
    let token = format!("ddc_{HEX64}");
    let matches = matches_for(&token);
    assert!(
        matches
            .iter()
            .any(|(id, found)| id == "deno-kv-credentials" && found == &token),
        "ddc_ Deno KV token must surface through the expanded literal prefix; matches={matches:?}"
    );
}

#[test]
fn non_member_third_char_is_not_claimed() {
    // `z` is not in the `[npc]` class, so the regex cannot match and the
    // detector must not fire — the expansion added triggers for the real
    // members only, it did not widen the shape to any `dd?_<64hex>`.
    let token = format!("ddz_{HEX64}");
    let matches = matches_for(&token);
    assert!(
        !matches.iter().any(|(id, _)| id == "deno-kv-credentials"),
        "a non-member third char must not be claimed by deno-kv; matches={matches:?}"
    );
}
