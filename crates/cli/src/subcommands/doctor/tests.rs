//! Unit tests for `crate::subcommands::doctor` PATH-membership normalization.
//! Housed in a sibling `tests.rs` module (rather than an inline
//! `#[cfg(test)] mod {}` block) so the KH-GAP-004 `no_inline_tests_in_src` gate
//! stays green while still reaching the parent module's private
//! `dir_is_on_path` via `super::`.

use super::{bloom_operator_diagnostic, dir_is_on_path, load_bloom_evidence, BloomEvidenceSummary};
use keyhog_scanner::{BigramPrefilterState, BigramPrefilterStatus};
use std::ffi::OsString;

/// A PATH entry with a TRAILING SLASH still matches the install dir: the old
/// raw `d == dir` compare returned a false "on PATH: no" for `~/.local/bin/`.
#[test]
fn trailing_slash_path_entry_still_matches() {
    let dir = tempfile::tempdir().expect("tempdir");
    let install = dir.path().join("bin");
    std::fs::create_dir(&install).expect("mkdir bin");

    // PATH holds the same dir WITH a trailing separator, plus an unrelated dir.
    let mut with_slash = install.clone().into_os_string();
    with_slash.push(std::path::MAIN_SEPARATOR.to_string());
    let pathvar =
        std::env::join_paths([OsString::from("/nonexistent/x"), with_slash]).expect("join_paths");

    assert!(
        dir_is_on_path(&install, &pathvar),
        "a trailing-slash PATH entry must canonicalize-match the install dir"
    );
}

/// A dir genuinely absent from PATH reports false (no over-matching).
#[test]
fn dir_absent_from_path_reports_false() {
    let dir = tempfile::tempdir().expect("tempdir");
    let install = dir.path().join("bin");
    std::fs::create_dir(&install).expect("mkdir bin");
    let other = dir.path().join("other");
    std::fs::create_dir(&other).expect("mkdir other");

    let pathvar = std::env::join_paths([other.into_os_string()]).expect("join_paths");
    assert!(
        !dir_is_on_path(&install, &pathvar),
        "an install dir not present in PATH must report false"
    );
}

fn bloom_status(state: BigramPrefilterState) -> BigramPrefilterStatus {
    BigramPrefilterStatus {
        populated_slots: 257,
        total_slots: 65_536,
        saturation_threshold_slots: 39_322,
        density_basis_points: 39,
        state,
    }
}

fn corpus_evidence(rejected_input_count: u64) -> BloomEvidenceSummary {
    BloomEvidenceSummary {
        corpus_name: "samsung-creddata-fx-record-spans-v1".to_string(),
        corpus_revision: "f1de3f85dbdf42bf7b3467c0d273a4dfe44d56ee".to_string(),
        input_count: 3,
        eligible_input_count: 3,
        rejected_input_count,
        rejection_basis_points: if rejected_input_count == 2 { 6_666 } else { 0 },
        unavailable_reason_counts: std::collections::BTreeMap::from([(
            "source-file-missing".to_string(),
            4,
        )]),
        finding_count: 7,
        findings_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
    }
}

#[test]
fn missing_bloom_evidence_is_an_explicit_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("missing-bloom-evidence.json");
    let detector_sha = "a".repeat(64);
    let error = load_bloom_evidence(
        &path,
        bloom_status(BigramPrefilterState::Healthy),
        &detector_sha,
        0,
    )
    .expect_err("missing evidence must fail visibly");
    assert_eq!(
        error.to_string(),
        format!("read Bloom evidence {}", path.display())
    );
}

/// KH-1237 regression: doctor previously had no operator-visible bloom values,
/// leaving ordinary density and effectiveness trapped in a scanner test.
/// Pin the exact uncolored values that the command renders.
#[test]
fn ordinary_bloom_status_has_exact_operator_values() {
    let evidence = corpus_evidence(2);
    let diagnostic =
        bloom_operator_diagnostic(bloom_status(BigramPrefilterState::Healthy), Some(&evidence));
    assert_eq!(
        diagnostic.density,
        "0.39% (257/65536 slots; saturates at 39322)"
    );
    assert_eq!(
        diagnostic.corpus_rejection,
        "66.66% (2/3 inputs; 3 bloom-eligible; samsung-creddata-fx-record-spans-v1@f1de3f85dbdf42bf7b3467c0d273a4dfe44d56ee; unavailable source-file-missing=4)"
    );
    assert_eq!(
        diagnostic.finding_parity,
        "IDENTICAL (7 findings; sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)"
    );
    assert_eq!(diagnostic.state, "HEALTHY / CORPUS-PROVEN");
    assert_eq!(diagnostic.action, None);
    assert!(!diagnostic.warned);
    assert!(!diagnostic.unhealthy);
}

/// KH-1237 regression: saturation must never be colored or labeled healthy.
/// The operator text must state fail-open recall behavior and a concrete repair.
#[test]
fn saturated_bloom_status_is_actionable_and_not_healthy() {
    let diagnostic = bloom_operator_diagnostic(bloom_status(BigramPrefilterState::Saturated), None);
    assert_eq!(diagnostic.state, "SATURATED / FAIL-OPEN");
    assert!(diagnostic.warned);
    assert!(!diagnostic.unhealthy);
    assert!(diagnostic
        .action
        .is_some_and(|action| action.contains("downstream scanning remains enabled")));
    assert!(diagnostic
        .action
        .is_some_and(|action| action.contains("enlarge the table")));
}

/// KH-1237 regression: invalid state must be a doctor health failure, not a
/// warning or an apparently healthy zero-density filter, while explicitly
/// telling operators that downstream recall remains enabled.
#[test]
fn invalid_bloom_status_is_unhealthy_and_actionable() {
    let diagnostic = bloom_operator_diagnostic(bloom_status(BigramPrefilterState::Invalid), None);
    assert_eq!(diagnostic.state, "INVALID / FAIL-OPEN");
    assert!(!diagnostic.warned);
    assert!(diagnostic.unhealthy);
    assert!(diagnostic
        .action
        .is_some_and(|action| action.contains("repair or rebuild")));
}

/// KH-1237 regression: a technically non-saturated filter that rejects none of
/// the named production benchmark must not appear fully effective or omit an
/// operator action.
#[test]
fn zero_rejection_healthy_filter_is_visible_as_ineffective() {
    let evidence = corpus_evidence(0);
    let diagnostic =
        bloom_operator_diagnostic(bloom_status(BigramPrefilterState::Healthy), Some(&evidence));
    assert_eq!(diagnostic.state, "HEALTHY / NO CORPUS REJECTION");
    assert!(diagnostic.warned);
    assert!(!diagnostic.unhealthy);
    assert!(diagnostic
        .action
        .is_some_and(|action| action.contains("measured corpus was rejected at 0%")));
}
