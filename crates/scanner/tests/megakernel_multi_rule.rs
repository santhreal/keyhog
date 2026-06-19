#![cfg(feature = "gpu")]
//! Megakernel fallback port — slice 3: multi-rule, multi-file dispatch + the
//! rule→detector decode mapping.
//!
//! This is the core the live `scan_phase2_patterns` replacement uses: many
//! detector DFAs as one resident rule catalog, a batch of files, one GPU
//! dispatch, and `HitRecord{file_idx, rule_idx, match_offset}` decoded back to
//! (which file, which DETECTOR, where). Proves the mapping is correct — every
//! secret-bearing file fires its detector's rule and only that rule; clean files
//! fire nothing. (`docs/EXECUTION_PLAN.md` step 5.)
//!
//! Run: cargo test -p keyhog-scanner --features gpu --test megakernel_multi_rule -- --ignored --nocapture

use std::time::Duration;

use vyre_driver_wgpu::megakernel::{
    BatchDispatchConfig, BatchDispatcher, BatchFile, FileBatch, HitRecord,
};
use vyre_driver_wgpu::WgpuBackend;
use vyre_libs::scan::build_regex_dfa_unanchored;
use vyre_runtime::megakernel::BatchRuleProgram;

const WORKER_GROUPS: u32 = 8;
const HIT_CAPACITY: u32 = 8192;
const MAX_MATCHES: u32 = 100_000;
const MAX_DFA_STATES: usize = 16_384;

/// (detector name, regex, a length-valid sample secret) for a few real keyhog
/// detector shapes. rule_idx = index in this table.
///
/// These are deliberately **overlap-free**: the prefix-delimiter char (`_` / `-`)
/// is NOT in the body charclass, so the unanchored `.*PATTERN` DFA stays small.
/// Patterns whose prefix chars ARE in the body class (AWS `AKIA[A-Z0-9]{16}`,
/// `AIza[A-Za-z0-9_-]{35}`, `sk_live_…`) explode the unanchored DFA under the
/// `.*` self-loop (overlap ambiguity) and do NOT belong on the unanchored-DFA
/// lane at all — they route to the GpuLiteralSet literal-core prefilter
/// (AC finds the literal, anchored DFA verifies the body; task #4). This test
/// proves the unanchored-DFA rule→detector mapping, so it covers only that lane.
const DETECTORS: &[(&str, &str, &str)] = &[
    (
        "github-pat",
        "ghp_[A-Za-z0-9]{36}",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    ),
    (
        "github-app",
        "ghs_[A-Za-z0-9]{36}",
        "ghs_abcdefghijklmnopqrstuvwxyz0123456789",
    ),
    (
        "slack-token",
        "xox[baprs]-[A-Za-z0-9-]{10,48}",
        "xoxb-1234567890-abcdefghij",
    ),
];

#[test]
#[ignore = "live GPU; run with --ignored --nocapture"]
fn megakernel_multi_rule_maps_hits_to_detectors() {
    let backend =
        WgpuBackend::new().expect("Fix: live GPU required (missing GPU is a configuration bug)");

    // Build the resident rule catalog: one unanchored DFA rule per detector.
    let rules: Vec<BatchRuleProgram> = DETECTORS
        .iter()
        .enumerate()
        .map(|(idx, (_name, regex, _sample))| {
            let pipe = build_regex_dfa_unanchored(&[regex], MAX_MATCHES, MAX_DFA_STATES)
                .unwrap_or_else(|e| panic!("detector {idx} regex {regex:?} must compile: {e:?}"));
            BatchRuleProgram::new(
                idx as u32,
                pipe.dfa.transitions,
                pipe.dfa.accept,
                pipe.dfa.state_count,
            )
            .expect("rule must be valid")
        })
        .collect();

    // Files: one per detector (secret embedded at a non-zero offset), plus a
    // clean file. file_idx == position in this Vec.
    let mut files: Vec<BatchFile> = DETECTORS
        .iter()
        .enumerate()
        .map(|(i, (_n, _re, secret))| {
            BatchFile::new(
                i as u64,
                0,
                format!("config:\n  key = \"{secret}\"\n").into_bytes(),
            )
        })
        .collect();
    let clean_idx = files.len();
    files.push(BatchFile::new(
        999,
        0,
        b"// just ordinary code, no credentials here\n".to_vec(),
    ));

    let batch = FileBatch::upload(backend.device_queue(), &files, WORKER_GROUPS, HIT_CAPACITY)
        .expect("FileBatch upload");
    let config = BatchDispatchConfig {
        workgroup_size_x: 64,
        worker_groups: WORKER_GROUPS,
        hit_capacity: HIT_CAPACITY,
        timeout: Duration::from_secs(20),
        ..Default::default()
    };
    let mut dispatcher =
        BatchDispatcher::new(backend.clone(), config).expect("BatchDispatcher must compile");

    let mut hits: Vec<HitRecord> = Vec::with_capacity(256);
    let result = dispatcher
        .dispatch_into(&batch, &rules, &mut hits)
        .expect("megakernel dispatch must complete");

    eprintln!(
        "multi-rule dispatch: items_processed={}, hits={}",
        result.items_processed,
        hits.len()
    );
    for h in &hits {
        let detector = DETECTORS
            .get(h.rule_idx as usize)
            .map(|(n, _, _)| *n)
            .unwrap_or("<oob>");
        eprintln!(
            "  file_idx={} rule_idx={} ({detector}) offset={}",
            h.file_idx, h.rule_idx, h.match_offset
        );
    }

    // RECALL CONTRACT: file i (i < DETECTORS.len()) must fire exactly rule i and
    // no other; the clean file must fire nothing.
    for (i, (name, _re, _secret)) in DETECTORS.iter().enumerate() {
        let file_hits: Vec<&HitRecord> = hits.iter().filter(|h| h.file_idx as usize == i).collect();
        assert!(
            file_hits.iter().any(|h| h.rule_idx as usize == i),
            "file {i} ({name}) must fire its own detector rule {i}; got {file_hits:?}"
        );
        assert!(
            file_hits.iter().all(|h| h.rule_idx as usize == i),
            "file {i} ({name}) fired a foreign detector rule (false positive); got {file_hits:?}"
        );
    }
    let clean_hits: Vec<&HitRecord> = hits
        .iter()
        .filter(|h| h.file_idx as usize == clean_idx)
        .collect();
    assert!(
        clean_hits.is_empty(),
        "clean file must fire no detector; got {clean_hits:?}"
    );
}
