//! Behavioral regression coverage for typed detector evidence relations.

use keyhog_core::{
    Chunk, ChunkMetadata, CompanionSpec, DetectorRelationKind, DetectorRelationSpec, DetectorSpec,
    EvidenceDirection, EvidenceRequirement, EvidenceScope, EvidenceValueRelation, PatternSpec,
    Severity,
};
use keyhog_scanner::testing::{CompiledCompanion, ScannerPreprocessedText};
use keyhog_scanner::CompiledScanner;
use std::sync::{Arc, LazyLock};

const PRIMARY: &str = "REL_7Gk2Nq9Vm4Xs8Wp3Dz6H";

fn compiled_relation(
    regex: &str,
    capture_group: Option<usize>,
    within_lines: usize,
    within_bytes: Option<usize>,
    direction: EvidenceDirection,
    scope: EvidenceScope,
    value_relation: EvidenceValueRelation,
) -> CompiledCompanion {
    CompiledCompanion {
        name: Arc::from("context"),
        regex: regex::Regex::new(regex).expect("relation regex must compile"),
        capture_group,
        within_lines,
        within_bytes,
        direction,
        scope,
        requirement: EvidenceRequirement::Reinforcing,
        value_relation,
    }
}

fn find_relation(text: &str, companion: &CompiledCompanion) -> Option<String> {
    let token_anchor = text
        .find("\"token\"")
        .or_else(|| text.find("token="))
        .expect("fixture contains a token field");
    let primary_start = token_anchor
        + text[token_anchor..]
            .find(PRIMARY)
            .expect("token field contains the primary credential");
    let preprocessed = ScannerPreprocessedText::passthrough(text);
    keyhog_scanner::testing::find_companion(
        &preprocessed,
        text[..primary_start]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1,
        primary_start,
        primary_start + PRIMARY.len(),
        PRIMARY,
        companion,
    )
}

fn scanner(requirement: EvidenceRequirement) -> CompiledScanner {
    CompiledScanner::compile(vec![DetectorSpec {
        id: format!("typed-evidence-{requirement:?}").to_ascii_lowercase(),
        name: "Typed evidence fixture".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: format!(r"\b{PRIMARY}\b"),
            required_literals: vec!["REL_".into()],
            ..Default::default()
        }],
        companions: vec![CompanionSpec {
            name: "account".into(),
            regex: r"account=([A-Za-z0-9_-]+)".into(),
            within_lines: 2,
            direction: EvidenceDirection::Before,
            requirement,
            capture_group: Some(1),
            ..Default::default()
        }],
        keywords: vec!["REL_".into()],
        min_confidence: Some(0.0),
        match_confidence: keyhog_core::detector_spec_by_id("github-classic-pat")
            .and_then(|detector| detector.match_confidence),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }])
    .expect("typed evidence fixture scanner compiles")
}

fn scan_count(scanner: &CompiledScanner, text: &str) -> usize {
    scanner
        .scan(&Chunk {
            data: text.to_string().into(),
            metadata: ChunkMetadata::default(),
        })
        .expect("typed evidence fixture scans")
        .len()
}

/// A same-object relation must accept evidence in the exact nested object that owns the secret.
#[test]
fn same_object_accepts_evidence_inside_primary_object() {
    let text = format!(
        r#"{{"first":{{"token":"{PRIMARY}","account":"{PRIMARY}"}},"second":{{"account":"other"}}}}"#
    );
    let companion = compiled_relation(
        r#""account"\s*:\s*"([^"]+)""#,
        Some(1),
        0,
        None,
        EvidenceDirection::Either,
        EvidenceScope::SameObject,
        EvidenceValueRelation::EqualsPrimary,
    );

    assert_eq!(find_relation(&text, &companion).as_deref(), Some(PRIMARY));
}

/// A sibling JSON object on the same physical line must not satisfy same-object evidence.
#[test]
fn same_object_rejects_cross_object_evidence_on_same_line() {
    let text = format!(r#"{{"first":{{"token":"{PRIMARY}"}},"second":{{"account":"{PRIMARY}"}}}}"#);
    let companion = compiled_relation(
        r#""account"\s*:\s*"([^"]+)""#,
        Some(1),
        0,
        None,
        EvidenceDirection::Either,
        EvidenceScope::SameObject,
        EvidenceValueRelation::EqualsPrimary,
    );

    assert_eq!(find_relation(&text, &companion), None);
}

/// A blank line must terminate same-record evidence even when the line radius includes both records.
#[test]
fn same_record_rejects_evidence_across_blank_line() {
    let text = format!("token={PRIMARY}\n\naccount={PRIMARY}\n");
    let companion = compiled_relation(
        r"account=(\S+)",
        Some(1),
        3,
        None,
        EvidenceDirection::Either,
        EvidenceScope::SameRecord,
        EvidenceValueRelation::EqualsPrimary,
    );

    assert_eq!(find_relation(&text, &companion), None);
}

/// Same-record evidence before the primary must survive both the structural and directional gates.
#[test]
fn same_record_accepts_preceding_evidence_in_record() {
    let text = format!("account={PRIMARY}\ntoken={PRIMARY}\n\nnext=true\n");
    let companion = compiled_relation(
        r"account=(\S+)",
        Some(1),
        2,
        None,
        EvidenceDirection::Before,
        EvidenceScope::SameRecord,
        EvidenceValueRelation::EqualsPrimary,
    );

    assert_eq!(find_relation(&text, &companion).as_deref(), Some(PRIMARY));
}

/// Directional evidence must reject an otherwise valid value on the wrong side of the primary.
#[test]
fn before_direction_rejects_following_evidence() {
    let text = format!("token={PRIMARY}\naccount={PRIMARY}\n");
    let companion = compiled_relation(
        r"account=(\S+)",
        Some(1),
        2,
        None,
        EvidenceDirection::Before,
        EvidenceScope::Window,
        EvidenceValueRelation::EqualsPrimary,
    );

    assert_eq!(find_relation(&text, &companion), None);
}

/// The byte-distance bound is inclusive, so evidence at the exact declared gap remains valid.
#[test]
fn byte_distance_accepts_exact_boundary() {
    let text = format!("context=ok___token={PRIMARY}");
    let primary_start = text.find(PRIMARY).unwrap();
    let evidence_end = text.find("ok").unwrap() + 2;
    let companion = compiled_relation(
        r"context=(ok)",
        Some(1),
        0,
        Some(primary_start - evidence_end),
        EvidenceDirection::Before,
        EvidenceScope::SameLine,
        EvidenceValueRelation::Present,
    );

    assert_eq!(find_relation(&text, &companion).as_deref(), Some("ok"));
}

/// A byte-distance bound one byte below the actual gap must reject the relation.
#[test]
fn byte_distance_rejects_value_beyond_boundary() {
    let text = format!("context=ok___token={PRIMARY}");
    let primary_start = text.find(PRIMARY).unwrap();
    let evidence_end = text.find("ok").unwrap() + 2;
    let companion = compiled_relation(
        r"context=(ok)",
        Some(1),
        0,
        Some(primary_start - evidence_end - 1),
        EvidenceDirection::Before,
        EvidenceScope::SameLine,
        EvidenceValueRelation::Present,
    );

    assert_eq!(find_relation(&text, &companion), None);
}

/// Explicit capture selection must compare and return the selected group rather than implicit group one.
#[test]
fn explicit_capture_group_selects_declared_evidence_value() {
    let text = format!("meta=wrong:{PRIMARY}\ntoken={PRIMARY}");
    let companion = compiled_relation(
        r"meta=([^:]+):(\S+)",
        Some(2),
        1,
        None,
        EvidenceDirection::Before,
        EvidenceScope::Window,
        EvidenceValueRelation::EqualsPrimary,
    );

    assert_eq!(find_relation(&text, &companion).as_deref(), Some(PRIMARY));
}

/// Required evidence must preserve a primary finding only when the relation is present.
#[test]
fn required_relation_suppresses_missing_evidence() {
    let scanner = scanner(EvidenceRequirement::Required);

    assert_eq!(
        scan_count(&scanner, &format!("account=tenant_42\ntoken={PRIMARY}")),
        1
    );
    assert_eq!(scan_count(&scanner, &format!("token={PRIMARY}")), 0);
}

/// Forbidden evidence must suppress a primary finding when the prohibited relation is present.
#[test]
fn forbidden_relation_suppresses_present_evidence() {
    let scanner = scanner(EvidenceRequirement::Forbidden);

    assert_eq!(scan_count(&scanner, &format!("token={PRIMARY}")), 1);
    assert_eq!(
        scan_count(&scanner, &format!("account=tenant_42\ntoken={PRIMARY}")),
        0
    );
}
/// Compiled-plan introspection must expose the exact relation semantics executed by the scanner.
#[test]
fn compiled_evidence_plan_reports_resolved_relation() {
    let scanner = scanner(EvidenceRequirement::Required);
    let plan = scanner
        .compiled_evidence_plan("typed-evidence-required")
        .expect("compiled detector exposes an evidence plan");

    assert_eq!(plan.detector_id, "typed-evidence-required");
    assert_eq!(plan.relations.len(), 1);
    let relation = &plan.relations[0];
    assert_eq!(relation.name, "account");
    assert_eq!(relation.regex, r"account=([A-Za-z0-9_-]+)");
    assert_eq!(relation.capture_group, Some(1));
    assert_eq!(relation.within_lines, 2);
    assert_eq!(relation.within_bytes, None);
    assert_eq!(relation.direction, EvidenceDirection::Before);
    assert_eq!(relation.scope, EvidenceScope::Window);
    assert_eq!(relation.requirement, EvidenceRequirement::Required);
    assert_eq!(relation.value_relation, EvidenceValueRelation::Present);
}

const OWNER_TOKEN: &str = "OWN_7Gk2Nq9Vm4Xs8Wp3Dz6H";
const TARGET_TOKEN: &str = "TARGET_4Qm8Za2Lc7Nv5Xk9Bp3R";
const DOMINATOR_TOKEN: &str = "DOM_9Vr2Ks7Qm4Xp8Lc5Nz1B";

fn relation_detector(
    id: &str,
    token: &str,
    detector_relations: Vec<DetectorRelationSpec>,
) -> DetectorSpec {
    DetectorSpec {
        id: id.into(),
        name: format!("{id} fixture"),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: format!(r"\b{token}\b"),
            required_literals: vec![token[..token.find('_').unwrap() + 1].into()],
            ..Default::default()
        }],
        detector_relations,
        keywords: vec![token[..token.find('_').unwrap() + 1].into()],
        min_confidence: Some(0.0),
        match_confidence: keyhog_core::detector_spec_by_id("github-classic-pat")
            .and_then(|detector| detector.match_confidence),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }
}

fn detector_relation_scanner(kind: DetectorRelationKind) -> CompiledScanner {
    let owner = relation_detector(
        "owner-detector",
        OWNER_TOKEN,
        vec![DetectorRelationSpec {
            detector_id: "target-detector".into(),
            kind,
            within_lines: 1,
            within_bytes: None,
            direction: EvidenceDirection::Before,
        }],
    );
    let target = relation_detector("target-detector", TARGET_TOKEN, Vec::new());
    CompiledScanner::compile(vec![owner, target]).expect("detector relation scanner compiles")
}

fn scan_ids(scanner: &CompiledScanner, text: &str) -> Vec<String> {
    let matches = scanner
        .scan(&Chunk {
            data: text.to_string().into(),
            metadata: ChunkMetadata::default(),
        })
        .expect("detector relation fixture scans");
    let mut ids = scanner
        .try_resolve_matches(matches)
        .expect("detector relation fixture resolves")
        .into_iter()
        .map(|matched| matched.detector_id.to_string())
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids
}

/// A requires relation must suppress its owner when the target detector is absent.
#[test]
fn detector_requires_relation_suppresses_owner_without_target() {
    let scanner = detector_relation_scanner(DetectorRelationKind::Requires);

    assert_eq!(
        scan_ids(&scanner, &format!("owner={OWNER_TOKEN}")),
        Vec::<String>::new()
    );
}

/// A requires relation must retain both independently valid findings when bounded target evidence exists.
#[test]
fn detector_requires_relation_accepts_preceding_target() {
    let scanner = detector_relation_scanner(DetectorRelationKind::Requires);
    let ids = scan_ids(
        &scanner,
        &format!("target={TARGET_TOKEN}\nowner={OWNER_TOKEN}"),
    );

    assert_eq!(ids, vec!["owner-detector", "target-detector"]);
}

/// A directional detector dependency must not accept target evidence on the wrong side.
#[test]
fn detector_requires_relation_rejects_target_in_wrong_direction() {
    let scanner = detector_relation_scanner(DetectorRelationKind::Requires);
    let ids = scan_ids(
        &scanner,
        &format!("owner={OWNER_TOKEN}\ntarget={TARGET_TOKEN}"),
    );

    assert_eq!(ids, vec!["target-detector"]);
}

/// A conflict relation must suppress only its declaring owner when the target is nearby.
#[test]
fn detector_conflict_relation_keeps_target_and_suppresses_owner() {
    let scanner = detector_relation_scanner(DetectorRelationKind::Conflicts);
    let ids = scan_ids(
        &scanner,
        &format!("target={TARGET_TOKEN}\nowner={OWNER_TOKEN}"),
    );

    assert_eq!(ids, vec!["target-detector"]);
}

/// A subsumption relation must retain the specific owner and suppress its bounded target.
#[test]
fn detector_subsumes_relation_keeps_owner_and_suppresses_target() {
    let scanner = detector_relation_scanner(DetectorRelationKind::Subsumes);
    let ids = scan_ids(
        &scanner,
        &format!("target={TARGET_TOKEN}\nowner={OWNER_TOKEN}"),
    );

    assert_eq!(ids, vec!["owner-detector"]);
}

/// Unknown detector dependencies must fail compilation instead of silently becoming inactive edges.
#[test]
fn detector_relation_unknown_target_fails_compilation() {
    let owner = relation_detector(
        "owner-detector",
        OWNER_TOKEN,
        vec![DetectorRelationSpec {
            detector_id: "missing-detector".into(),
            kind: DetectorRelationKind::Requires,
            within_lines: 1,
            within_bytes: None,
            direction: EvidenceDirection::Either,
        }],
    );

    let error = CompiledScanner::compile(vec![owner])
        .err()
        .expect("unknown detector relation target must fail compilation");
    assert!(error
        .to_string()
        .contains("relation targets unknown detector \"missing-detector\""));
}

/// Requires and subsumes cycles must fail compilation so detector order cannot affect resolution.
#[test]
fn detector_relation_cycle_fails_compilation() {
    let owner = relation_detector(
        "owner-detector",
        OWNER_TOKEN,
        vec![DetectorRelationSpec {
            detector_id: "target-detector".into(),
            kind: DetectorRelationKind::Requires,
            within_lines: 1,
            within_bytes: None,
            direction: EvidenceDirection::Either,
        }],
    );
    let target = relation_detector(
        "target-detector",
        TARGET_TOKEN,
        vec![DetectorRelationSpec {
            detector_id: "owner-detector".into(),
            kind: DetectorRelationKind::Subsumes,
            within_lines: 1,
            within_bytes: None,
            direction: EvidenceDirection::Either,
        }],
    );

    let error = CompiledScanner::compile(vec![owner, target])
        .err()
        .expect("cyclic detector relations must fail compilation");
    assert!(error
        .to_string()
        .contains("requires/subsumes relations contain a cycle"));
}
/// Compiled-plan introspection must expose cross-detector operations with resolved bounds.
#[test]
fn compiled_evidence_plan_reports_detector_relation() {
    let scanner = detector_relation_scanner(DetectorRelationKind::Requires);
    let plan = scanner
        .compiled_evidence_plan("owner-detector")
        .expect("compiled detector relation plan is visible");

    assert_eq!(plan.detector_relations.len(), 1);
    let relation = &plan.detector_relations[0];
    assert_eq!(relation.detector_id, "target-detector");
    assert_eq!(relation.kind, DetectorRelationKind::Requires);
    assert_eq!(relation.within_lines, 1);
    assert_eq!(relation.within_bytes, None);
    assert_eq!(relation.direction, EvidenceDirection::Before);
}

/// Relation resolution must re-check requirements after another relation suppresses their target.
#[test]
fn detector_relation_cascade_preserves_final_requirements() {
    let owner = relation_detector(
        "owner-detector",
        OWNER_TOKEN,
        vec![DetectorRelationSpec {
            detector_id: "target-detector".into(),
            kind: DetectorRelationKind::Requires,
            within_lines: 2,
            within_bytes: None,
            direction: EvidenceDirection::Either,
        }],
    );
    let target = relation_detector("target-detector", TARGET_TOKEN, Vec::new());
    let dominator = relation_detector(
        "dominator-detector",
        DOMINATOR_TOKEN,
        vec![DetectorRelationSpec {
            detector_id: "target-detector".into(),
            kind: DetectorRelationKind::Subsumes,
            within_lines: 2,
            within_bytes: None,
            direction: EvidenceDirection::Either,
        }],
    );
    let scanner = CompiledScanner::compile(vec![owner, target, dominator])
        .expect("acyclic relation cascade compiles");

    for text in [
        format!("{OWNER_TOKEN}\n{TARGET_TOKEN}\n{DOMINATOR_TOKEN}"),
        format!("{DOMINATOR_TOKEN}\n{TARGET_TOKEN}\n{OWNER_TOKEN}"),
    ] {
        assert_eq!(scan_ids(&scanner, &text), vec!["dominator-detector"]);
    }
}

/// Opposing conflict declarations must fail compilation instead of suppressing both findings.
#[test]
fn detector_relation_rejects_mutual_conflicts() {
    let owner = relation_detector(
        "owner-detector",
        OWNER_TOKEN,
        vec![DetectorRelationSpec {
            detector_id: "target-detector".into(),
            kind: DetectorRelationKind::Conflicts,
            within_lines: 1,
            within_bytes: None,
            direction: EvidenceDirection::Either,
        }],
    );
    let target = relation_detector(
        "target-detector",
        TARGET_TOKEN,
        vec![DetectorRelationSpec {
            detector_id: "owner-detector".into(),
            kind: DetectorRelationKind::Conflicts,
            within_lines: 1,
            within_bytes: None,
            direction: EvidenceDirection::Either,
        }],
    );

    let error = CompiledScanner::compile(vec![owner, target])
        .err()
        .expect("mutual conflict declarations must fail compilation");
    assert!(error
        .to_string()
        .contains("declare contradictory conflicts and conflicts relations"));
}

fn scan_embedded_relation_ids(text: &str, relevant: &[&str]) -> Vec<String> {
    static SCANNER: LazyLock<CompiledScanner> = LazyLock::new(|| {
        CompiledScanner::compile(
            keyhog_core::load_embedded_detectors_or_fail()
                .expect("embedded relation corpus must load"),
        )
        .expect("embedded relation corpus must compile")
    });
    scan_ids(&SCANNER, text)
        .into_iter()
        .filter(|detector_id| relevant.contains(&detector_id.as_str()))
        .collect()
}

/// The anchored Notion OAuth detector must win the exact token overlap deterministically.
#[test]
fn shipped_notion_relations_keep_only_specific_oauth_owner() {
    let ids = scan_embedded_relation_ids(
        "NOTION_CLIENT_SECRET=secret_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        &[
            "notion-api-key",
            "notion-integration-token",
            "notion-oauth-secret",
        ],
    );

    assert_eq!(ids, vec!["notion-oauth-secret"]);
}

/// A public Razorpay key ID must not survive unless the paired secret detector also fires.
#[test]
fn shipped_razorpay_dependency_requires_secret_finding() {
    let relevant = ["razorpay-key-id", "razorpay-key-secret"];
    assert_eq!(
        scan_embedded_relation_ids("RAZORPAY_KEY_ID=rzp_test_Kp4Qx7Rm2Sn5Tb", &relevant),
        Vec::<String>::new()
    );
    assert_eq!(
        scan_embedded_relation_ids(
            "RAZORPAY_KEY_ID=rzp_test_Kp4Qx7Rm2Sn5Tb\nRAZORPAY_KEY_SECRET=Vk9Bn3Lp7Qm2Rs5Tw8Vk9Bn3",
            &relevant,
        ),
        vec!["razorpay-key-id", "razorpay-key-secret"]
    );
}

/// Detector declaration order must not change relation resolution output.
#[test]
fn detector_relation_resolution_ignores_compile_order() {
    let owner = || {
        relation_detector(
            "owner-detector",
            OWNER_TOKEN,
            vec![DetectorRelationSpec {
                detector_id: "target-detector".into(),
                kind: DetectorRelationKind::Conflicts,
                within_lines: 1,
                within_bytes: None,
                direction: EvidenceDirection::Before,
            }],
        )
    };
    let target = || relation_detector("target-detector", TARGET_TOKEN, Vec::new());
    let owner_first =
        CompiledScanner::compile(vec![owner(), target()]).expect("owner-first corpus compiles");
    let target_first =
        CompiledScanner::compile(vec![target(), owner()]).expect("target-first corpus compiles");
    let text = format!("target={TARGET_TOKEN}\nowner={OWNER_TOKEN}");

    assert_eq!(
        scan_ids(&owner_first, &text),
        scan_ids(&target_first, &text)
    );
    assert_eq!(scan_ids(&owner_first, &text), vec!["target-detector"]);
}

/// A target in another file must never satisfy a requires relation, even at identical offsets.
#[test]
fn detector_relation_requires_same_file_origin() {
    let scanner = detector_relation_scanner(DetectorRelationKind::Requires);
    let mut matches = scanner
        .scan(&Chunk {
            data: format!("target={TARGET_TOKEN}").into(),
            metadata: ChunkMetadata {
                path: Some("target.env".into()),
                ..Default::default()
            },
        })
        .expect("target file scans");
    matches.extend(
        scanner
            .scan(&Chunk {
                data: format!("owner={OWNER_TOKEN}").into(),
                metadata: ChunkMetadata {
                    path: Some("owner.env".into()),
                    ..Default::default()
                },
            })
            .expect("owner file scans"),
    );
    let mut ids = scanner
        .try_resolve_matches(matches)
        .expect("cross-file findings resolve")
        .into_iter()
        .map(|matched| matched.detector_id.to_string())
        .collect::<Vec<_>>();
    ids.sort_unstable();

    assert_eq!(ids, vec!["target-detector"]);
}
