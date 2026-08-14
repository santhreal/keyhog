//! Per-pattern positive and hard-negative evidence gates.
//!
//! Every shipped pattern receives an exact synthetic positive witness. Each
//! enforcement-capable policy also owns a named direct negative and rejects a
//! generated sibling-prefix mutation.

use std::collections::BTreeSet;

use keyhog_core::{
    validate_detector, Chunk, ChunkMetadata, DetectorHardNegativeClass, DetectorSpec, PatternSpec,
};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use regex::{Regex, RegexBuilder};
use regex_syntax::hir::{Class, Hir, HirKind};
use regex_syntax::ParserBuilder;

const MAX_GENERATED_WITNESS_BYTES: usize = 64 * 1024;
const MAX_GENERATED_WITNESSES: usize = 64;

#[derive(Clone)]
struct PositiveWitness {
    text: String,
    path: String,
    source_type: String,
}

fn detector_regex(pattern: &str) -> Regex {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .crlf(true)
        .build()
        .expect("detector regex must compile with production flags")
}

fn detector_fires(scanner: &CompiledScanner, detector_id: &str, witness: &PositiveWitness) -> bool {
    let chunk = Chunk {
        data: witness.text.as_str().into(),
        metadata: ChunkMetadata {
            source_type: witness.source_type.as_str().into(),
            path: Some(witness.path.as_str().into()),
            ..Default::default()
        },
    };
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .expect("per-pattern evidence scan must complete")
        .iter()
        .flat_map(|matches| matches.iter())
        .any(|matched| matched.detector_id.as_ref() == detector_id)
}

fn append_bounded(left: &[u8], right: &[u8]) -> Option<Vec<u8>> {
    let next_len = left.len().checked_add(right.len())?;
    if next_len > MAX_GENERATED_WITNESS_BYTES {
        return None;
    }
    let mut joined = Vec::with_capacity(next_len);
    joined.extend_from_slice(left);
    joined.extend_from_slice(right);
    Some(joined)
}

fn combine_witnesses(left: Vec<Vec<u8>>, right: &[Vec<u8>]) -> Vec<Vec<u8>> {
    if left.is_empty() || right.is_empty() {
        return Vec::new();
    }
    let mut combined = Vec::new();
    for diagonal in 0..left.len() + right.len() - 1 {
        let first_left = diagonal.saturating_sub(right.len() - 1);
        let last_left = diagonal.min(left.len() - 1);
        for left_index in first_left..=last_left {
            let right_index = diagonal - left_index;
            if let Some(joined) = append_bounded(&left[left_index], &right[right_index]) {
                combined.push(joined);
                if combined.len() == MAX_GENERATED_WITNESSES {
                    return combined;
                }
            }
        }
    }
    combined
}

fn character_category(character: char) -> u8 {
    if character == '\n' || character == '\r' {
        0
    } else if character.is_whitespace() {
        1
    } else if character.is_alphanumeric() || character == '_' {
        2
    } else {
        3
    }
}

fn unicode_class_witnesses(class: &regex_syntax::hir::ClassUnicode) -> Vec<Vec<u8>> {
    let mut candidates = Vec::new();
    let mut categories = BTreeSet::new();
    if let Some(candidate) = ['A', 'a', '0', '_'].into_iter().find(|candidate| {
        class
            .iter()
            .any(|range| range.start() <= *candidate && *candidate <= range.end())
    }) {
        categories.insert(character_category(candidate));
        candidates.push(candidate.to_string().into_bytes());
    }
    for range in class.iter() {
        let candidate = range.start();
        if categories.insert(character_category(candidate)) {
            let mut encoded = [0; 4];
            candidates.push(candidate.encode_utf8(&mut encoded).as_bytes().to_vec());
        }
    }
    candidates
}

fn byte_class_witnesses(class: &regex_syntax::hir::ClassBytes) -> Vec<Vec<u8>> {
    let mut candidates = Vec::new();
    let mut categories = BTreeSet::new();
    if let Some(candidate) = [b'A', b'a', b'0', b'_'].into_iter().find(|candidate| {
        class
            .iter()
            .any(|range| range.start() <= *candidate && *candidate <= range.end())
    }) {
        categories.insert(character_category(char::from(candidate)));
        candidates.push(vec![candidate]);
    }
    for range in class.iter() {
        let candidate = range.start();
        if categories.insert(character_category(char::from(candidate))) {
            candidates.push(vec![candidate]);
        }
    }
    candidates
}

fn hir_witnesses(hir: &Hir) -> Vec<Vec<u8>> {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => vec![Vec::new()],
        HirKind::Literal(literal) => (literal.0.len() <= MAX_GENERATED_WITNESS_BYTES)
            .then(|| vec![literal.0.to_vec()])
            .unwrap_or_default(),
        HirKind::Class(Class::Unicode(class)) => unicode_class_witnesses(class),
        HirKind::Class(Class::Bytes(class)) => byte_class_witnesses(class),
        HirKind::Repetition(repetition) => {
            let repeated = hir_witnesses(&repetition.sub);
            let mut witnesses = vec![Vec::new()];
            for _ in 0..repetition.min {
                witnesses = combine_witnesses(witnesses, &repeated);
                if witnesses.is_empty() {
                    break;
                }
            }
            witnesses
        }
        HirKind::Capture(capture) => hir_witnesses(&capture.sub),
        HirKind::Concat(parts) => {
            let mut witnesses = vec![Vec::new()];
            for part in parts {
                let part_witnesses = hir_witnesses(part);
                witnesses = combine_witnesses(witnesses, &part_witnesses);
                if witnesses.is_empty() {
                    break;
                }
            }
            witnesses
        }
        HirKind::Alternation(parts) => {
            let alternatives = parts.iter().map(hir_witnesses).collect::<Vec<_>>();
            let mut witnesses = Vec::new();
            for witness_index in 0..MAX_GENERATED_WITNESSES {
                let mut added = false;
                for alternative in &alternatives {
                    if let Some(witness) = alternative.get(witness_index) {
                        witnesses.push(witness.clone());
                        added = true;
                        if witnesses.len() == MAX_GENERATED_WITNESSES {
                            return witnesses;
                        }
                    }
                }
                if !added {
                    break;
                }
            }
            witnesses
        }
    }
}

fn exact_regex_witnesses(pattern: &str) -> Vec<String> {
    let mut builder = ParserBuilder::new();
    builder.case_insensitive(true).crlf(true);
    let Ok(hir) = builder.build().parse(pattern) else {
        return Vec::new();
    };
    hir_witnesses(&hir)
        .into_iter()
        .filter_map(|bytes| String::from_utf8(bytes).ok())
        .collect()
}

fn positive_witnesses(detector: &DetectorSpec, pattern_index: usize) -> Vec<PositiveWitness> {
    let mut witnesses = Vec::new();
    let pattern_index_u32 = u32::try_from(pattern_index).expect("pattern index fits u32");
    let default_path = detector
        .tests
        .iter()
        .find_map(|test| test.test_path.clone())
        .or_else(|| {
            detector
                .source_admission
                .file_extensions
                .first()
                .map(|extension| format!("application.{}", extension.trim_start_matches('.')))
        })
        .unwrap_or_else(|| "application.conf".to_owned());
    let source_type = detector
        .source_admission
        .source_types
        .first()
        .cloned()
        .unwrap_or_else(|| "filesystem".to_owned());

    for test in detector.tests.iter().filter(|test| {
        test.pattern_index == Some(pattern_index_u32) || test.pattern_index.is_none()
    }) {
        if let Some(positive) = test.test_positive.as_deref() {
            witnesses.push(PositiveWitness {
                text: positive.to_owned(),
                path: test
                    .test_path
                    .clone()
                    .unwrap_or_else(|| default_path.clone()),
                source_type: source_type.clone(),
            });
        }
    }

    witnesses.extend(
        exact_regex_witnesses(&detector.patterns[pattern_index].regex)
            .into_iter()
            .map(|text| PositiveWitness {
                text,
                path: default_path.clone(),
                source_type: source_type.clone(),
            }),
    );

    let mut seen = BTreeSet::new();
    witnesses.retain(|witness| {
        seen.insert((
            witness.text.clone(),
            witness.path.clone(),
            witness.source_type.clone(),
        ))
    });
    witnesses
}

fn find_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

fn generated_sibling_negative(
    pattern: &PatternSpec,
    matcher: &Regex,
    positive: &str,
) -> Option<String> {
    let mut anchors = pattern.required_literals.clone();
    anchors.extend(keyhog_scanner::testing::pattern_literal_prefixes(
        &pattern.regex,
    ));
    anchors.sort();
    anchors.dedup();

    for anchor in anchors {
        let Some(start) = find_ascii_case_insensitive(positive.as_bytes(), anchor.as_bytes())
        else {
            continue;
        };
        for offset in 0..anchor.len() {
            if !anchor.as_bytes()[offset].is_ascii_alphanumeric() {
                continue;
            }
            let mut mutated = positive.as_bytes().to_vec();
            mutated[start + offset] = b'~';
            let Ok(mutated) = String::from_utf8(mutated) else {
                continue;
            };
            if !matcher.is_match(&mutated) {
                return Some(mutated);
            }
        }
    }
    None
}

fn named_mutations(
    pattern: &PatternSpec,
    positive: &str,
) -> Vec<(DetectorHardNegativeClass, String)> {
    let matcher = detector_regex(&pattern.regex);
    let identifier = positive
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();
    let mut mutations = vec![
        (DetectorHardNegativeClass::Boundary, format!("A{positive}Z")),
        (
            DetectorHardNegativeClass::Identifier,
            format!("{identifier}Type"),
        ),
        (
            DetectorHardNegativeClass::Prose,
            format!("synthetic documentation example containing {positive}"),
        ),
        (
            DetectorHardNegativeClass::RegexLiteral,
            format!("scanner_rule = {:?}", pattern.regex),
        ),
    ];
    if let Some(sibling) = generated_sibling_negative(pattern, &matcher, positive) {
        mutations.push((DetectorHardNegativeClass::SiblingPrefix, sibling));
    }
    mutations
}

/// WHY: one prolific early regex alternative must not consume the bounded
/// witness budget and hide every later provider-specific branch.
#[test]
fn hard_negative_witness_generation_keeps_late_alternatives() {
    let pattern = r"(?:(?:A|-){6}x|late_)(?:A|-){6}";
    let matcher = detector_regex(pattern);
    assert!(exact_regex_witnesses(pattern).iter().any(|witness| {
        witness.to_ascii_lowercase().starts_with("late_") && matcher.is_match(witness)
    }));
}

/// WHY: a detector-level positive can hide one unsupported sibling pattern.
/// Enumerate the registry and every pattern ordinal so each new or changed
/// regex must produce an exact synthetic or detector-owned witness. The
/// separate corpus coverage ratchet keeps one production scan proof per ID.
#[test]
fn hard_negative_every_pattern_has_direct_positive_coverage() {
    let detectors = keyhog_core::embedded_detector_specs().to_vec();
    let mut failures = Vec::new();
    let mut checked = 0usize;

    for detector in &detectors {
        for (pattern_index, pattern) in detector.patterns.iter().enumerate() {
            let matcher = detector_regex(&pattern.regex);
            let covered = positive_witnesses(detector, pattern_index)
                .into_iter()
                .any(|witness| matcher.is_match(&witness.text));
            if !covered {
                failures.push(format!("{}[{pattern_index}]", detector.id));
            }
            checked += 1;
        }
    }

    assert!(
        checked >= 1_700,
        "expected the complete pattern corpus, found {checked}"
    );
    assert!(
        failures.is_empty(),
        "{} patterns lack an exact direct positive witness: {}",
        failures.len(),
        failures.join(", ")
    );
}

/// WHY: semantic enforcement without both authored and generated negatives can
/// turn one observed false positive into a detector-wide recall workaround.
/// Every capable pattern must own a named direct negative and reject a mutation
/// of the production-derived literal anchor.
#[test]
fn enforcement_capable_patterns_have_direct_and_generated_hard_negatives() {
    let detectors = keyhog_core::embedded_detector_specs().to_vec();
    let capable = detectors
        .iter()
        .filter(|detector| detector.semantic_policy().is_enforcement_capable())
        .collect::<Vec<_>>();
    if capable.is_empty() {
        return;
    }
    let scanner = CompiledScanner::compile(detectors.clone()).expect("embedded corpus compiles");
    let mut failures = Vec::new();

    for detector in capable {
        let validation = validate_detector(detector);
        for issue in validation {
            let keyhog_core::QualityIssue::Error(message) = issue else {
                continue;
            };
            if message.contains("direct positive") || message.contains("direct hard negative") {
                failures.push(format!("{}: {message}", detector.id));
            }
        }

        for (pattern_index, pattern) in detector.patterns.iter().enumerate() {
            let matcher = detector_regex(&pattern.regex);
            let positive = positive_witnesses(detector, pattern_index)
                .into_iter()
                .find(|witness| matcher.is_match(&witness.text));
            let Some(positive) = positive else {
                failures.push(format!(
                    "{}[{pattern_index}]: no positive witness",
                    detector.id
                ));
                continue;
            };
            let Some(sibling) = generated_sibling_negative(pattern, &matcher, &positive.text)
            else {
                failures.push(format!(
                    "{}[{pattern_index}]: no generated sibling-prefix negative",
                    detector.id
                ));
                continue;
            };
            let sibling = PositiveWitness {
                text: sibling,
                path: positive.path,
                source_type: positive.source_type,
            };
            if detector_fires(&scanner, &detector.id, &sibling) {
                failures.push(format!(
                    "{}[{pattern_index}]: generated sibling-prefix negative fired",
                    detector.id
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "hard-negative support gate failed:\n  - {}",
        failures.join("\n  - ")
    );
}

/// WHY: the corpus starts in compatibility mode, so a synthetic capable
/// detector keeps the generated sibling-negative path non-vacuous.
#[test]
fn hard_negative_capable_fixture_rejects_generated_sibling() {
    let pattern = PatternSpec {
        regex: "demo_[A-Z0-9]{8}".to_owned(),
        required_literals: vec!["demo_".to_owned()],
        ..Default::default()
    };
    let detector = DetectorSpec {
        id: "hard-negative-fixture".into(),
        name: "Hard negative fixture".into(),
        service: "test".into(),
        severity: keyhog_core::Severity::High,
        patterns: vec![pattern.clone()],
        keywords: vec!["demo_".into()],
        capture_role: keyhog_core::CaptureSemanticRole::AssignmentValue,
        anchor_role: keyhog_core::AnchorSemanticRole::DistinctivePrefix,
        allowed_source_roles: vec![keyhog_core::SemanticSourceRole::StandaloneToken],
        tests: vec![keyhog_core::DetectorTestSpec {
            test_positive: Some("demo_ABC12345".into()),
            test_negative: Some("dema_ABC12345".into()),
            pattern_index: Some(0),
            negative_class: Some(DetectorHardNegativeClass::SiblingPrefix),
            test_path: Some("application.conf".into()),
        }],
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    assert!(!validate_detector(&detector).iter().any(
        |issue| matches!(issue, keyhog_core::QualityIssue::Error(message)
                if message.contains("direct positive") || message.contains("direct hard negative"))
    ));

    let matcher = detector_regex(&pattern.regex);
    let sibling = generated_sibling_negative(&pattern, &matcher, "demo_ABC12345")
        .expect("literal prefix yields a sibling mutation");
    assert!(
        Regex::new(".{4}_[A-Z0-9]{8}")
            .expect("weakened fixture regex compiles")
            .is_match(&sibling),
        "weakening the literal anchor must admit the generated hard negative"
    );
    let scanner = CompiledScanner::compile(vec![detector]).expect("fixture detector compiles");
    let positive = PositiveWitness {
        text: "demo_ABC12345".into(),
        path: "application.conf".into(),
        source_type: "filesystem".into(),
    };
    assert!(detector_fires(&scanner, "hard-negative-fixture", &positive));
    assert!(!detector_fires(
        &scanner,
        "hard-negative-fixture",
        &PositiveWitness {
            text: sibling,
            ..positive
        }
    ));
}

/// WHY: the generator registry is exhaustive. Adding a negative class must make
/// this assertion fail until that class receives deterministic synthetic data.
#[test]
fn named_hard_negative_classes_have_synthetic_generators() {
    let pattern = PatternSpec {
        regex: "demo_[A-Z0-9]{8}".to_owned(),
        required_literals: vec!["demo_".to_owned()],
        ..Default::default()
    };
    let generated = named_mutations(&pattern, "demo_ABC12345");
    let classes = generated
        .iter()
        .map(|(class, _)| class.as_str())
        .collect::<BTreeSet<_>>();
    let expected = DetectorHardNegativeClass::ALL
        .iter()
        .map(|class| class.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(classes, expected);
    assert!(generated
        .iter()
        .all(|(_, value)| !value.is_empty() && value != "demo_ABC12345"));
}
