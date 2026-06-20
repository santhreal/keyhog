#![cfg(feature = "gpu")]
//! Smoke coverage for Vyre's retired per-rule megakernel primitive.
//!
//! This is deliberately not a keyhog engine test. Production scanning routes
//! through region-presence plus GPU regex-DFA admission, and the live-route
//! contracts live under `gpu_*` tests. This file only proves the vendored Vyre
//! primitive still links, packs a small rule catalog, and can dispatch on a
//! live adapter when explicitly requested.

use std::time::Duration;

use vyre_driver_wgpu::megakernel::{
    BatchDispatchConfig, BatchDispatcher, BatchFile, FileBatch, HitRecord,
};
use vyre_driver_wgpu::WgpuBackend;
use vyre_libs::scan::build_regex_dfa_unanchored;
use vyre_runtime::megakernel::rule_catalog::pack_rule_catalog;
use vyre_runtime::megakernel::BatchRuleProgram;

const HIT_CAPACITY: u32 = 4096;
const MAX_MATCHES: u32 = 100_000;
const MAX_DFA_STATES: usize = 16_384;

const CASES: &[(&str, &str, &str)] = &[
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
        "slack-bot",
        "xoxb-[A-Za-z0-9-]{10,48}",
        "xoxb-1234567890-abcdefghij",
    ),
];

fn build_rule(idx: usize, regex: &str) -> BatchRuleProgram {
    let pipe = build_regex_dfa_unanchored(&[regex], MAX_MATCHES, MAX_DFA_STATES)
        .unwrap_or_else(|err| panic!("Vyre DFA build failed for {regex:?}: {err:?}"));
    BatchRuleProgram::new(
        idx as u32,
        pipe.dfa.transitions,
        pipe.dfa.accept,
        pipe.dfa.state_count,
    )
    .unwrap_or_else(|err| panic!("Vyre BatchRuleProgram build failed for {regex:?}: {err:?}"))
}

fn smoke_rules() -> Vec<BatchRuleProgram> {
    CASES
        .iter()
        .enumerate()
        .map(|(idx, (_name, regex, _sample))| build_rule(idx, regex))
        .collect()
}

#[test]
fn vyre_megakernel_rule_catalog_packs_smoke_patterns() {
    let rules = smoke_rules();
    let packed = pack_rule_catalog(&rules).expect("Vyre megakernel catalog must pack");

    assert_eq!(
        rules.len(),
        CASES.len(),
        "one smoke rule must be built per case"
    );
    assert!(
        !packed.transitions.is_empty() && !packed.accept.is_empty(),
        "packed catalog must carry DFA transition and accept tables"
    );
    assert!(
        packed.rejected_rules.is_empty(),
        "smoke rules must fit the Vyre primitive catalog"
    );
}

#[test]
#[ignore = "live-adapter Vyre primitive smoke; production GPU route is tested elsewhere"]
fn vyre_megakernel_dispatches_smoke_patterns_on_live_adapter() {
    let backend = WgpuBackend::new().expect("live WGPU adapter required for Vyre primitive smoke");
    let rules = smoke_rules();

    let mut files: Vec<BatchFile> = CASES
        .iter()
        .enumerate()
        .map(|(idx, (_name, _regex, sample))| {
            BatchFile::new(
                idx as u64,
                0,
                format!("config_{idx} = \"{sample}\"\n").into_bytes(),
            )
        })
        .collect();
    let clean_idx = files.len();
    files.push(BatchFile::new(
        clean_idx as u64,
        0,
        b"ordinary text without credential-shaped tokens\n".to_vec(),
    ));

    let batch = FileBatch::upload(
        backend.device_queue(),
        &files,
        rules.len() as u32,
        HIT_CAPACITY,
    )
    .expect("Vyre FileBatch upload must succeed");
    let config = BatchDispatchConfig {
        workgroup_size_x: 64,
        worker_groups: 8,
        hit_capacity: HIT_CAPACITY,
        timeout: Duration::from_secs(20),
        ..Default::default()
    };
    let mut dispatcher =
        BatchDispatcher::new(backend, config).expect("Vyre BatchDispatcher must compile");

    let mut hits: Vec<HitRecord> = Vec::with_capacity(256);
    let report = dispatcher
        .dispatch_into(&batch, &rules, &mut hits)
        .expect("Vyre megakernel dispatch must complete");

    assert!(
        report.items_processed > 0,
        "dispatch must process at least one file/rule item"
    );
    for (idx, (name, _regex, _sample)) in CASES.iter().enumerate() {
        assert!(
            hits.iter()
                .any(|hit| hit.file_idx as usize == idx && hit.rule_idx as usize == idx),
            "{name} sample must fire its own smoke rule; hits={hits:?}"
        );
    }
    assert!(
        hits.iter().all(|hit| hit.file_idx as usize != clean_idx),
        "clean file must not fire any smoke rule; hits={hits:?}"
    );
}
