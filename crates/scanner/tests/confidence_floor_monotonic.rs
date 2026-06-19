//! DET-08 regression: the `min_confidence` floor is MONOTONIC in the finding
//! set.
//!
//! The detection backlog (DET-08) reported FP swinging 173 → 37 → 306 as the
//! floor rose 0.30 → 0.40 → 0.50 — a non-monotonic floor, which a clean cutoff
//! can never produce. That evidence was a measurement artifact of two *other*
//! bugs, both since fixed:
//!   * DET-10 — the `--decode-*` flag path resolved a different config than the
//!     baked defaults (FP 312 vs 41 for the SAME nominal values); the floor was
//!     swept via that broken flag path. Now there is one applied config
//!     (`orchestrator/mod.rs`: `.with_config(effective_config.scanner)`).
//!   * DET-11 — the default GPU auto-route scored the MoE on a shader whose
//!     activation diverged from the CPU rational sigmoid by ~0.05, flipping
//!     ±15 findings run-to-run near the floor. Now the shader uses the CPU
//!     sigmoid (`gpu_shader_sigmoid_contract.rs`) and the bench pins the CPU
//!     path.
//!
//! The floor itself was always monotonic *by construction*: the confidence a
//! match carries is computed with no reference to `min_confidence` (the value
//! never enters `confidence::apply_post_ml_penalties`, the entropy/length
//! boosts, or the checksum policy), and both gates that consult it
//! (`engine/phase2_generic.rs` scan-time, `orchestrator/postprocess.rs`
//! post-scan) are pure `confidence < floor` comparisons. Raising a threshold
//! that does not feed back into the value it thresholds can only remove
//! matches, never add them.
//!
//! This test proves that property end-to-end on the real scanner + the real
//! detector corpus: scan one fixed corpus at a rising floor sweep and assert
//! the finding set at each higher floor is a strict-subset-or-equal of every
//! lower floor (nesting), the count never rises, and the floor actually bites
//! (the 0.0 set is strictly larger than the 1.0 set) so the test cannot pass
//! vacuously. Deterministic CPU path (no GPU dependency) so it is a stable CI
//! gate on every host.

mod support;
use support::contracts::test_chunk as make_chunk;
use support::paths::detector_dir;

use keyhog_core::RawMatch;
use keyhog_scanner::{CompiledScanner, ScannerConfig};
use std::collections::BTreeSet;

type FindingKey = (String, String, usize);

fn collect_keys(results: &[Vec<RawMatch>]) -> BTreeSet<FindingKey> {
    results
        .iter()
        .flat_map(|chunk| chunk.iter())
        .map(|m| {
            (
                m.detector_id.as_ref().to_string(),
                m.credential.as_ref().to_string(),
                m.location.offset,
            )
        })
        .collect()
}

/// A fixed corpus that produces findings across a spread of confidences:
/// high-confidence named tokens (well above any floor), and several
/// generic-secret `KEY = value` assignments whose entropy/length give them
/// intermediate confidences so the floor sweep actually removes some of them at
/// different steps. The values are random-shaped (not placeholders) so they are
/// not suppressed as examples.
fn corpus() -> Vec<keyhog_core::Chunk> {
    vec![
        // Named, checksum/prefix-anchored — high confidence, survive most floors.
        make_chunk(
            "const AWS_KEY = \"AKIAQYLPMN5HFIQR7XYA\";\n",
            "fixtures/a.rs",
        ),
        make_chunk(
            "PAT=ghp_aBcD1234EFgh5678ijklMNop9012qrSTuvWX\n",
            "fixtures/b.env",
        ),
        // Generic key=value assignments with credential-ish keywords and
        // varied entropy/length → varied generic-secret confidence.
        make_chunk(
            "API_SECRET=Zx9Qw3Er7Ty1Up5Io2As6Df0Gh4Jk8\n",
            "config/c.env",
        ),
        make_chunk(
            "DATABASE_PASSWORD=p4ssw0rd-with-some-entropy-9182\n",
            "config/d.env",
        ),
        make_chunk(
            "auth_token: \"q1W2e3R4t5Y6u7I8o9P0a1S2d3F4g5H6\"\n",
            "config/e.yml",
        ),
        make_chunk(
            "SESSION_KEY=aGVsbG8td29ybGQtc2Vzc2lvbi1rZXktMTIz\n",
            "config/f.env",
        ),
        make_chunk("secret = \"shortish-1234567890abcd\"\n", "config/g.toml"),
    ]
}

fn scan_at_floor(detectors: &[keyhog_core::DetectorSpec], floor: f64) -> BTreeSet<FindingKey> {
    let config = ScannerConfig::default().min_confidence(floor);
    let scanner = CompiledScanner::compile(detectors.to_vec())
        .expect("scanner compile")
        .with_config(config);
    collect_keys(&scanner.scan_coalesced(&corpus()))
}

#[test]
fn finding_set_is_nested_and_non_increasing_as_floor_rises() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors directory unavailable: {e}");
            return;
        }
    };

    // Fine-grained sweep across the whole [0.0, 1.0] range so many thresholds
    // are exercised, including the 0.30 / 0.40 / 0.50 band DET-08 measured.
    let floors: Vec<f64> = (0..=20).map(|i| i as f64 * 0.05).collect();
    let sets: Vec<(f64, BTreeSet<FindingKey>)> = floors
        .iter()
        .map(|&f| (f, scan_at_floor(&detectors, f)))
        .collect();

    // Nesting + non-increasing count for every adjacent pair (low < high).
    for pair in sets.windows(2) {
        let (lo_floor, lo) = &pair[0];
        let (hi_floor, hi) = &pair[1];
        assert!(
            hi.is_subset(lo),
            "floor {hi_floor} produced findings absent at the lower floor {lo_floor} \
             (non-monotonic — raising the floor must only remove findings): \
             only-at-higher-floor = {:?}",
            hi.difference(lo).take(5).collect::<Vec<_>>(),
        );
        assert!(
            hi.len() <= lo.len(),
            "floor {hi_floor} count {} exceeds lower floor {lo_floor} count {} (non-monotonic)",
            hi.len(),
            lo.len(),
        );
    }

    // Non-vacuous: the floor must actually bite somewhere, otherwise the nesting
    // assertions above would pass on a constant set and prove nothing.
    let widest = &sets.first().expect("at least one floor").1;
    let tightest = &sets.last().expect("at least one floor").1;
    assert!(
        widest.len() > tightest.len(),
        "the floor sweep removed nothing (0.0 set len {} == 1.0 set len {}); the corpus \
         must yield at least one floor-gated finding for this test to mean anything",
        widest.len(),
        tightest.len(),
    );

    // And the widest floor must find the high-confidence named tokens at all,
    // proving the corpus is live (not an empty-scan false pass).
    assert!(
        widest
            .iter()
            .any(|(id, _, _)| id == "aws-access-key" || id == "hot-aws_key"),
        "expected the planted AKIA token in the unfiltered (floor 0.0) finding set; got {widest:?}",
    );
}
