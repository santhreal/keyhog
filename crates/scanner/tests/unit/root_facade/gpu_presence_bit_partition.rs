//! GPU region-presence bit partition contracts.
//!
//! Runtime fused GPU rows contain phase-1 detector literals, phase-2 keyword
//! and anchor literals, then positioned confirmed anchors and generic stems.
//! Only the owning segment may affect each derived evidence type.

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
                        required_literals: Vec::new(),
                        client_safe: false,
                        weak_anchor: false,
                    },
                    PatternSpec {
                        regex: "([a-z]{4}[0-9]{4})".into(),
                        description: None,
                        group: Some(1),
                        required_literals: Vec::new(),
                        client_safe: false,
                        weak_anchor: false,
                    },
                ],
                companions: Vec::new(),
                verify: None,
                keywords: vec!["phasekw".into()],
                min_confidence: None,
                ..keyhog_scanner::testing::named_detector_fixture_defaults()
            },
            DetectorSpec {
                tests: Vec::new(),
                id: "gpu-presence-always-anchor".into(),
                name: "GPU Presence Always Anchor".into(),
                service: "test".into(),
                severity: Severity::High,
                patterns: vec![PatternSpec {
                    regex: "([Aa][Nn][Cc][Hh][Oo][Rr][Kk][Ee][Yy][0-9]{4})".into(),
                    description: None,
                    group: Some(1),
                    required_literals: Vec::new(),
                    client_safe: false,
                    weak_anchor: false,
                }],
                companions: Vec::new(),
                verify: None,
                keywords: Vec::new(),
                min_confidence: None,
                ..keyhog_scanner::testing::named_detector_fixture_defaults()
            },
        ],
        GpuInitPolicy::ForceDisabled,
    )
    .expect("scanner compile")
}

#[test]
fn fused_always_anchor_literal_positions_expand_like_the_host_index() {
    let scanner = scanner_with_detector_and_phase2_keyword_and_anchor();
    let index = scanner
        .phase2_anchor_index
        .as_ref()
        .expect("phase-two anchor index");
    let text = "prefix ANCHORKEY1234 suffix";
    let mut host = Vec::new();
    index.collect_always_active_candidates(text, |_| true, &mut host);
    assert!(
        !host.is_empty(),
        "fixture must exercise an always-active anchor"
    );

    let folded = text.to_ascii_lowercase();
    let literal_matches = index
        .always_anchor_literals()
        .iter()
        .enumerate()
        .filter_map(|(literal_id, literal)| {
            folded
                .find(&literal.to_ascii_lowercase())
                .map(|offset| (literal_id as u32, offset as u32))
        })
        .collect::<Vec<_>>();
    let mut fused = Vec::new();
    index.collect_always_active_candidates_from_literal_matches(
        &literal_matches,
        |_| true,
        &mut fused,
    );

    assert_eq!(fused, host);
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

    let mut row = vec![0u32; scanner.gpu_literal_count().div_ceil(32).max(1)];
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
fn appended_gpu_presence_anchor_bits_admit_phase_two_without_triggering_detectors() {
    let scanner = scanner_with_detector_and_phase2_keyword_and_anchor();
    let mut row = vec![0u32; scanner.gpu_literal_count().div_ceil(32).max(1)];
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
