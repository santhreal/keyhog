#![cfg(feature = "gpu")]
//! Megakernel fallback port — slice 2: end-to-end GPU scan.
//!
//! Dispatches a keyhog detector regex (compiled to a megakernel DFA rule) over a
//! batch of files on the GPU via the persistent batch megakernel, and asserts
//! the `HitRecord`s correctly identify (file, rule=detector, byte offset).
//! Proves the existing vyre engine scans keyhog patterns end-to-end on hardware
//! — the foundation the fallback/confirmed passes wire onto
//! (`docs/EXECUTION_PLAN.md` step 5). Modeled on
//! vyre `vyre-driver-wgpu/tests/megakernel_telemetry_contracts.rs`.
//!
//! Run: cargo test -p keyhog-scanner --features gpu --test megakernel_gpu_scan -- --ignored --nocapture

use std::time::Duration;

use vyre_driver_wgpu::megakernel::{
    BatchDispatchConfig, BatchDispatcher, BatchFile, FileBatch, HitRecord,
};
use vyre_driver_wgpu::WgpuBackend;
use vyre_libs::scan::build_regex_dfa_unanchored;
use vyre_runtime::megakernel::BatchRuleProgram;

const WORKER_GROUPS: u32 = 4;
const HIT_CAPACITY: u32 = 4096;
const MAX_MATCHES: u32 = 100_000;
const MAX_DFA_STATES: usize = 4096;

#[test]
#[ignore = "live GPU; run with --ignored --nocapture"]
fn megakernel_scans_a_keyhog_pattern_end_to_end() {
    let backend = WgpuBackend::new()
        .expect("Fix: live GPU required for megakernel scan (missing GPU is a configuration bug)");

    // One real keyhog-shaped detector regex → a single megakernel DFA rule.
    // GitHub classic PAT: ghp_ + 36 alphanumerics (regex-level; checksum is a
    // keyhog post-process, not the DFA's job).
    // Unanchored (find-anywhere) via the NFA-table start-self-loop transform —
    // the keyhog fallback contract (secrets occur anywhere in a chunk, not at
    // byte 0). Bare pattern; the helper does the unanchoring (no `(?s).*?` text
    // hack, which OOMs at scale).
    let pipe = build_regex_dfa_unanchored(&["ghp_[A-Za-z0-9]{36}"], MAX_MATCHES, MAX_DFA_STATES)
        .expect("github PAT regex must compile to an unanchored dense DFA");
    let rule = BatchRuleProgram::new(
        0,
        pipe.dfa.transitions.clone(),
        pipe.dfa.accept.clone(),
        pipe.dfa.state_count,
    )
    .expect("DFA must form a valid BatchRuleProgram");
    let accepting = pipe.dfa.accept.iter().filter(|&&a| a != 0).count();
    eprintln!(
        "DFA: state_count={} accepting_states={} transitions_len={}",
        pipe.dfa.state_count,
        accepting,
        pipe.dfa.transitions.len()
    );
    let rules = vec![rule];

    // Two files: one carrying a (length-valid) PAT, one clean.
    let secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"; // ghp_ + 36 chars
    assert_eq!(secret.len(), 4 + 36);
    // Secret at offset 9 (after `token = "`) — the real find-anywhere case the
    // unanchored DFA must handle.
    let files = vec![
        BatchFile::new(
            0xF11E_0001,
            0,
            format!("token = \"{secret}\"\n").into_bytes(),
        ),
        BatchFile::new(
            0xF11E_0002,
            0,
            b"// nothing to see here, just code\n".to_vec(),
        ),
    ];
    let secret_byte_off = "token = \"".len() as u32; // 9

    let batch = FileBatch::upload(backend.device_queue(), &files, WORKER_GROUPS, HIT_CAPACITY)
        .expect("FileBatch upload");

    let config = BatchDispatchConfig {
        workgroup_size_x: 64,
        worker_groups: WORKER_GROUPS,
        hit_capacity: HIT_CAPACITY,
        timeout: Duration::from_secs(15),
        ..Default::default()
    };
    let mut dispatcher =
        BatchDispatcher::new(backend.clone(), config).expect("BatchDispatcher must compile");

    let mut hits: Vec<HitRecord> = Vec::with_capacity(64);
    let result = dispatcher
        .dispatch_into(&batch, &rules, &mut hits)
        .expect("megakernel dispatch must complete");

    eprintln!(
        "megakernel GPU scan: items_processed={}, hits={}",
        result.items_processed,
        hits.len()
    );
    for h in &hits {
        eprintln!(
            "  hit: file_idx={} rule_idx={} layer={} offset={}",
            h.file_idx, h.rule_idx, h.layer_idx, h.match_offset
        );
    }

    // File 0 (index 0) must produce a hit for rule 0 at the secret offset; file 1
    // (clean) must not. This is the recall contract the fallback port inherits.
    let file0_hits: Vec<&HitRecord> = hits.iter().filter(|h| h.file_idx == 0).collect();
    let file1_hits: Vec<&HitRecord> = hits.iter().filter(|h| h.file_idx == 1).collect();
    assert!(
        file0_hits.iter().any(|h| h.rule_idx == 0),
        "secret-bearing file must produce a rule-0 hit; got {file0_hits:?}"
    );
    assert!(
        file1_hits.is_empty(),
        "clean file must produce no hits; got {file1_hits:?}"
    );
    // The match offset should land at (or before, for AC-style end-of-match) the
    // secret position — assert it is within the file and near the token.
    assert!(
        file0_hits.iter().any(|h| h.match_offset >= secret_byte_off
            && (h.match_offset as usize) <= files[0].bytes.len()),
        "hit offset must fall within the secret region (expected ~{secret_byte_off}); got {file0_hits:?}"
    );
}
