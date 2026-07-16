//! GPU region-presence bit partition contracts.
//!
//! Runtime GPU presence rows contain only phase-1 detector literals, phase-2
//! keyword literals, and always-active anchor literals. Positioned confirmed
//! anchors and generic keywords live in a separate GPU matcher and must remain
//! out of this bitmap.

use crate::engine::CompiledScanner;
use crate::GpuInitPolicy;
use keyhog_core::{DetectorSpec, PatternSpec, Severity};

fn scanner_with_detector_and_phase2_keyword_and_anchor() -> CompiledScanner {
    CompiledScanner::compile_with_gpu_policy(
        vec![
            DetectorSpec {
                tests: Vec::new(),
                id: "gpu-presence-split".into(),
                name: "GPU Presence Split".into(),
                service: "test".into(),
                severity: Severity::High,
                patterns: vec![
                    PatternSpec {
                        regex: "abc[0-9]+".into(),
                        description: None,
                        group: None,
                        client_safe: false,
                        weak_anchor: false,
                    },
                    PatternSpec {
                        regex: "[a-z]{4}[0-9]{4}".into(),
                        description: None,
                        group: None,
                        client_safe: false,
                        weak_anchor: false,
                    },
                ],
                companions: Vec::new(),
                verify: None,
                keywords: vec!["phasekw".into()],
                min_confidence: None,
                ..Default::default()
            },
            DetectorSpec {
                tests: Vec::new(),
                id: "gpu-presence-always-anchor".into(),
                name: "GPU Presence Always Anchor".into(),
                service: "test".into(),
                severity: Severity::High,
                patterns: vec![PatternSpec {
                    regex: "[Aa][Nn][Cc][Hh][Oo][Rr][Kk][Ee][Yy][0-9]{4}".into(),
                    description: None,
                    group: None,
                    client_safe: false,
                    weak_anchor: false,
                }],
                companions: Vec::new(),
                verify: None,
                keywords: Vec::new(),
                min_confidence: None,
                ..Default::default()
            },
        ],
        GpuInitPolicy::ForceDisabled,
    )
    .expect("scanner compile")
}

#[test]
fn appended_gpu_presence_bits_become_phase2_keyword_hints_only() {
    let scanner = scanner_with_detector_and_phase2_keyword_and_anchor();
    assert_eq!(
        scanner.ac_map.len(),
        1,
        "fixture needs one detector literal"
    );
    assert_eq!(
        scanner.phase2_keyword_count, 1,
        "fixture needs one phase2 keyword"
    );
    assert!(
        scanner.phase2_always_anchor_literal_count > 0,
        "fixture needs at least one always-active anchor literal"
    );

    let mut row = vec![0u32; scanner.gpu_presence_literal_count().div_ceil(32).max(1)];
    let phase2_literal_idx = scanner.ac_map.len();
    row[phase2_literal_idx / 32] |= 1u32 << (phase2_literal_idx % 32);

    assert_eq!(
        scanner.phase2_keyword_hints_from_gpu_presence(&row),
        vec![0]
    );
    assert!(scanner.gpu_presence_stray_tail_bits(&row).is_none());
    assert!(
        scanner
            .triggered_patterns_from_gpu_presence(&row)
            .iter()
            .all(|&word| word == 0),
        "phase2 keyword bits must not set confirmed detector trigger bits"
    );
    assert!(
        !scanner.phase2_always_anchor_present_from_gpu_presence(&row),
        "phase2 keyword bits must not mark always-active anchor presence"
    );
}

#[test]
fn appended_gpu_presence_anchor_bits_are_absence_proofs_only() {
    let scanner = scanner_with_detector_and_phase2_keyword_and_anchor();
    let mut row = vec![0u32; scanner.gpu_presence_literal_count().div_ceil(32).max(1)];
    let anchor_literal_idx = scanner.ac_map.len() + scanner.phase2_keyword_count;
    row[anchor_literal_idx / 32] |= 1u32 << (anchor_literal_idx % 32);

    assert!(scanner
        .phase2_keyword_hints_from_gpu_presence(&row)
        .is_empty());
    assert!(scanner.phase2_always_anchor_present_from_gpu_presence(&row));
    assert!(scanner.gpu_presence_stray_tail_bits(&row).is_none());
    assert!(
        scanner
            .triggered_patterns_from_gpu_presence(&row)
            .iter()
            .all(|&word| word == 0),
        "always-active anchor bits must not set confirmed detector trigger bits"
    );
}

#[test]
fn positioned_confirmed_anchor_bits_are_not_presence_bits() {
    let scanner = scanner_with_detector_and_phase2_keyword_and_anchor();
    assert_eq!(
        scanner.gpu_presence_literal_count(),
        scanner.ac_map.len()
            + scanner.phase2_keyword_count
            + scanner.phase2_always_anchor_literal_count
    );
    let mut row = vec![0u32; scanner.gpu_presence_literal_count().div_ceil(32).max(1)];
    let confirmed_anchor_literal_idx = scanner.gpu_presence_literal_count();
    row[confirmed_anchor_literal_idx / 32] |= 1u32 << (confirmed_anchor_literal_idx % 32);

    assert!(scanner
        .phase2_keyword_hints_from_gpu_presence(&row)
        .is_empty());
    assert!(!scanner.phase2_always_anchor_present_from_gpu_presence(&row));
    assert!(scanner.gpu_presence_stray_tail_bits(&row).is_some());
    assert!(
        scanner
            .triggered_patterns_from_gpu_presence(&row)
            .iter()
            .all(|&word| word == 0),
        "positioned confirmed-anchor bits must not set detector trigger bits"
    );
}

#[test]
fn positioned_generic_keyword_bits_are_not_presence_bits() {
    let scanner = scanner_with_detector_and_phase2_keyword_and_anchor();
    assert_eq!(
        scanner.gpu_presence_literal_count(),
        scanner.ac_map.len()
            + scanner.phase2_keyword_count
            + scanner.phase2_always_anchor_literal_count
    );
    let mut row = vec![0u32; scanner.gpu_presence_literal_count().div_ceil(32).max(1)];
    let generic_keyword_literal_idx = scanner.gpu_presence_literal_count();
    row[generic_keyword_literal_idx / 32] |= 1u32 << (generic_keyword_literal_idx % 32);

    assert!(scanner
        .phase2_keyword_hints_from_gpu_presence(&row)
        .is_empty());
    assert!(!scanner.phase2_always_anchor_present_from_gpu_presence(&row));
    assert!(scanner.gpu_presence_stray_tail_bits(&row).is_some());
    assert!(
        scanner
            .triggered_patterns_from_gpu_presence(&row)
            .iter()
            .all(|&word| word == 0),
        "positioned generic keyword bits must not set detector trigger bits"
    );
}
