//! LANE-4 detection-truth: every detector that ships an inline `[[detector.tests]]`
//! fixture must (a) FIRE on its `test_positive` under its OWN detector id, and
//! (b) NOT fire under its own id on its `test_negative` twin, driven through
//! the REAL `CompiledScanner::scan` production path, asserting the EXACT
//! detector id (Law 6, never `!is_empty`).
//!
//! The contract corpus (`contracts_runner.rs`) drives the hand-written
//! `tests/contracts/<id>.toml` fixtures; the inline `[[detector.tests]]` block
//! is a SEPARATE, author-shipped fixture living INSIDE the detector TOML
//! (Tier-B self-test data) and was only pinned by `all_detectors_self_validate`
//! at the structural level ("has a contract OR is deferred"). This suite pins
//! the inline fixtures' SCAN BEHAVIOUR directly: the positive the author wrote
//! into the detector MUST surface that detector, and the negative MUST NOT, so
//! a regex edit that breaks the author's own example flips a named case red.
//!
//! Plus a per-detector REGISTRY-CARDINALITY lane: every one of the ~900
//! embedded detector ids must be present, exactly once, in the scanner the
//! binary actually compiles, a per-id assertion (the registry truth matrix
//! pins only aggregate counts), so a single dropped/shadowed id is caught by
//! name.
//!
//! Deterministic + host-independent (no GPU env dependency; the CPU/SIMD path
//! is exercised). The detector tree is loaded from `CARGO_MANIFEST_DIR` so the
//! suite is cwd-stable under `cargo test` / `nextest` / remote runners.

mod support;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, DetectorFile};
use keyhog_scanner::telemetry::{self, ScanTelemetry};
use keyhog_scanner::{CompiledScanner, ScanBackend};

/// One inline self-test fixture extracted from a detector TOML.
struct InlineCase {
    detector_id: String,
    toml_file: String,
    positive: Option<String>,
    negative: Option<String>,
}

/// Read every `detectors/*.toml`, returning the id + inline `[[detector.tests]]`
/// fixtures for the detectors that ship them. Fails LOUDLY on a parse error
/// a malformed detector TOML is a source bug, never a silently-skipped file
/// (Law 10).
fn load_inline_cases() -> Vec<InlineCase> {
    let dir = detector_dir();
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("detectors/ must be readable ({}): {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("toml"))
        .collect();
    files.sort();

    let mut cases = Vec::new();
    for path in &files {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let file: DetectorFile = toml::from_str(&text)
            .unwrap_or_else(|e| panic!("malformed detector TOML {}: {e}", path.display()));
        let stem = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<unknown>")
            .to_string();
        for t in &file.detector.tests {
            cases.push(InlineCase {
                detector_id: file.detector.id.clone(),
                toml_file: stem.clone(),
                positive: t.test_positive.clone(),
                negative: t.test_negative.clone(),
            });
        }
    }
    cases
}

/// The on-disk corpus, compiled into ONE scanner exactly as the binary builds
/// it. Fails loudly if the tree can't load.
fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir())
        .unwrap_or_else(|e| panic!("detectors/ must load into the scanner: {e}"));
    CompiledScanner::compile(detectors).expect("on-disk corpus must compile into one scanner")
}

fn make_chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            // Inline cases specify detector syntax, not test-file policy. A
            // `test_` basename would lower confidence and could hide both a
            // broken positive and an over-broad negative behind path scoring.
            source_type: "filesystem".into(),
            path: Some("application.conf".into()),
            ..Default::default()
        },
    }
}

/// FLOOR: the inline-test feature is actually wired, at least the known
/// authored set ships. If this collapses to 0 the per-case assertions below
/// pass vacuously, so pin a concrete floor (11 detectors ship inline tests as
/// of this writing; new ones only raise it).
#[test]
fn inline_test_fixtures_are_present() {
    let cases = load_inline_cases();
    let with_positive = cases.iter().filter(|c| c.positive.is_some()).count();
    assert!(
        with_positive >= 11,
        "expected >= 11 detectors shipping an inline test_positive, found {with_positive} \
The inline `[[detector.tests]]` self-test corpus shrank (or the loader broke)"
    );
}

/// Every shipped detector owns at least one complete truth pair in its TOML.
/// Counting fixtures globally is insufficient: two fixtures on one detector
/// must not hide a different detector with no local contract.
#[test]
fn every_detector_owns_a_complete_inline_truth_pair() {
    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("detectors/ must load while checking inline truth ownership");
    let mut missing = Vec::new();

    for detector in &detectors {
        let owns_pair = detector.tests.iter().any(|case| {
            case.test_positive
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
                && case
                    .test_negative
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
        });
        if !owns_pair {
            missing.push(detector.id.as_str());
        }
    }

    assert!(
        missing.is_empty(),
        "{} detector(s) have no complete detector-owned positive/negative truth pair: {}",
        missing.len(),
        missing.join(", ")
    );
}

/// Every inline `test_positive` MUST surface its OWN detector id through the
/// real scan path. The author wrote this example into the detector; if the
/// detector's regex no longer fires on it, the example is decoration and the
/// detector has a recall hole on its own canonical shape.
#[test]
fn every_inline_positive_fires_its_own_detector() {
    let scanner = scanner();
    let cases = load_inline_cases();
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for case in &cases {
        let Some(positive) = &case.positive else {
            continue;
        };
        // Isolate cross-file fragment-reassembly state between fixtures (the
        // scanner accumulates it across scan() calls (see contracts_runner)).
        scanner.clear_fragment_cache();
        let matches = scanner.scan(&make_chunk(positive));
        let fired = matches
            .iter()
            .any(|m| m.detector_id.as_ref() == case.detector_id);
        if !fired {
            let ids: Vec<&str> = matches.iter().map(|m| m.detector_id.as_ref()).collect();
            let trace = Arc::new(ScanTelemetry::new());
            trace.enable_dogfood();
            scanner.clear_fragment_cache();
            telemetry::with_scan_telemetry(&trace, || {
                let _ = scanner.scan(&make_chunk(positive));
            });
            let suppressions = trace.drain().dogfood_events;
            failures.push(format!(
                "{} ({}): inline test_positive {:?} did not fire detector {:?}; scanner saw {:?}; suppression trace {:?}",
                case.detector_id,
                case.toml_file,
                positive,
                case.detector_id,
                ids,
                suppressions,
            ));
        }
        checked += 1;
    }

    assert!(
        failures.is_empty(),
        "{} of {checked} inline positives failed to fire their own detector:\n  - {}",
        failures.len(),
        failures.join("\n  - ")
    );
    assert!(
        checked >= 11,
        "expected >= 11 inline positive cases, ran {checked}"
    );
}

#[test]
fn anchored_generic_service_detectors_remain_named_through_resolution() {
    let cases = load_inline_cases();
    let detectors = keyhog_core::embedded_detector_specs().to_vec();
    let scanner = CompiledScanner::compile(detectors.clone()).expect("compile embedded detectors");
    let anchored_generic_ids: std::collections::BTreeSet<&str> = detectors
        .iter()
        .filter(|detector| {
            detector.service == "generic" && detector.kind == keyhog_core::DetectorKind::Regex
        })
        .map(|detector| detector.id.as_str())
        .collect();
    assert_eq!(anchored_generic_ids.len(), 5);

    let mut checked = 0usize;
    for case in cases {
        if !anchored_generic_ids.contains(case.detector_id.as_str()) {
            continue;
        }
        let Some(positive) = &case.positive else {
            continue;
        };
        scanner.clear_fragment_cache();
        let raw = scanner.scan(&make_chunk(positive));
        let active = scanner
            .try_resolve_matches(raw.clone())
            .expect("active compiled plan must classify every finding");
        let embedded = keyhog_scanner::resolution::try_resolve_matches(raw)
            .expect("embedded plan must classify every finding");
        for (surface, resolved) in [("active", active), ("embedded", embedded)] {
            assert!(
                resolved
                    .iter()
                    .any(|matched| matched.detector_id.as_ref() == case.detector_id),
                "{surface} resolution dropped anchored generic-service detector {} for {:?}; retained {:?}",
                case.detector_id,
                positive,
                resolved
                    .iter()
                    .map(|matched| matched.detector_id.as_ref())
                    .collect::<Vec<_>>()
            );
        }
        checked += 1;
    }
    assert_eq!(
        checked, 5,
        "each anchored generic-service detector has one inline positive"
    );
}

#[test]
fn corrected_primary_role_regressions_have_exact_backend_parity() {
    let scanner = scanner();
    let acquired_gpu_backends: Vec<_> = scanner
        .gpu_backend_candidates()
        .into_iter()
        .filter(|candidate| candidate.acquired)
        .map(|candidate| candidate.backend)
        .collect();
    assert!(
        !keyhog_scanner::hw_probe::probe_hardware().gpu_available
            || !acquired_gpu_backends.is_empty(),
        "physical GPU probe succeeded but no compiled GPU peer was acquired"
    );
    let corrected: std::collections::BTreeSet<&str> = [
        "alertmanager-credentials",
        "basic-auth-credentials",
        "bearer-authorization",
        "cli-password-flag",
        "goto-connect-api-credentials",
        "rapyd-api-credentials",
        "saltstack-credentials",
        "sql-password",
        "twilio-api-key",
        "url-credentials",
    ]
    .into_iter()
    .collect();
    let mut checked = 0usize;
    for case in load_inline_cases() {
        if !corrected.contains(case.detector_id.as_str()) {
            continue;
        }
        let Some(positive) = case.positive else {
            continue;
        };
        let chunk = make_chunk(&positive);
        scanner.clear_fragment_cache();
        let mut cpu = scanner.scan_with_backend(&chunk, ScanBackend::CpuFallback);
        scanner.clear_fragment_cache();
        let mut simd = scanner.scan_with_backend(&chunk, ScanBackend::SimdCpu);
        cpu.sort();
        simd.sort();
        assert_eq!(cpu, simd, "CPU/SIMD finding drift for {}", case.detector_id);
        for backend in &acquired_gpu_backends {
            scanner.clear_fragment_cache();
            let mut gpu = scanner.scan_with_backend(&chunk, *backend);
            gpu.sort();
            assert_eq!(
                cpu,
                gpu,
                "CPU/{} finding drift for {}",
                backend.label(),
                case.detector_id
            );
        }
        let resolved = scanner
            .try_resolve_matches(cpu)
            .expect("active plan resolves corrected inline findings");
        assert!(
            resolved
                .iter()
                .any(|matched| matched.detector_id.as_ref() == case.detector_id),
            "{} lost its own positive during final resolution",
            case.detector_id
        );
        checked += 1;
    }
    assert_eq!(
        checked, 11,
        "the ten corrected detectors own eleven inline positives"
    );
}

/// Every inline `test_negative` MUST NOT fire its own detector, the author's
/// negative twin proves the regex isn't over-broad. (Another detector may fire
/// on the same text; we only assert THIS detector stays silent, mirroring the
/// contract-runner negative semantics.)
#[test]
fn every_inline_negative_does_not_fire_its_own_detector() {
    let scanner = scanner();
    let cases = load_inline_cases();
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for case in &cases {
        let Some(negative) = &case.negative else {
            continue;
        };
        scanner.clear_fragment_cache();
        let matches = scanner.scan(&make_chunk(negative));
        let wrongly_fired: Vec<&str> = matches
            .iter()
            .filter(|m| m.detector_id.as_ref() == case.detector_id)
            .map(|m| m.credential.as_ref())
            .collect();
        if !wrongly_fired.is_empty() {
            failures.push(format!(
                "{} ({}): inline test_negative {:?} WRONGLY fired detector {:?} on {:?}",
                case.detector_id, case.toml_file, negative, case.detector_id, wrongly_fired
            ));
        }
        checked += 1;
    }

    assert!(
        failures.is_empty(),
        "{} of {checked} inline negatives wrongly fired their own detector:\n  - {}",
        failures.len(),
        failures.join("\n  - ")
    );
    assert!(
        checked >= 11,
        "expected >= 11 inline negative cases, ran {checked}"
    );
}

/// Per-detector cardinality: EVERY embedded detector id appears EXACTLY ONCE in
/// the on-disk tree (a per-id assertion, not just an aggregate count). A
/// copy-paste that duplicates an id, or a stale embed that drops one, is caught
/// by name here. The registry truth matrix pins the aggregate counts; this pins
/// the SET membership per id so the offending id is named.
#[test]
fn every_embedded_id_is_present_exactly_once_on_disk() {
    let embedded = keyhog_core::load_embedded_detectors_or_fail()
        .expect("embedded corpus must parse (baked in by build.rs)");

    // Count on-disk occurrences of each id (parse every TOML).
    let dir = detector_dir();
    let mut on_disk: BTreeMap<String, usize> = BTreeMap::new();
    for entry in std::fs::read_dir(&dir)
        .expect("detectors/ readable")
        .flatten()
    {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read detector toml");
        let file: DetectorFile = toml::from_str(&text)
            .unwrap_or_else(|e| panic!("malformed detector TOML {}: {e}", path.display()));
        *on_disk.entry(file.detector.id).or_insert(0) += 1;
    }

    let mut missing: Vec<String> = Vec::new();
    let mut dup: Vec<String> = Vec::new();
    for d in &embedded {
        match on_disk.get(d.id.as_str()).copied().unwrap_or(0) {
            0 => missing.push(d.id.clone()),
            1 => {}
            n => dup.push(format!("{} (x{n})", d.id)),
        }
    }
    assert!(
        missing.is_empty(),
        "embedded id(s) absent from the on-disk detectors/ tree (stale embed): {missing:?}"
    );
    assert!(
        dup.is_empty(),
        "id(s) declared by more than one on-disk TOML (one silently shadows the other): {dup:?}"
    );
    // Exact cardinality pin: embedded set and the distinct on-disk id set are
    // the SAME size (every embedded id mapped to exactly one TOML above).
    assert_eq!(
        embedded.len(),
        on_disk.len(),
        "embedded detector count ({}) must equal the distinct on-disk id count ({})",
        embedded.len(),
        on_disk.len()
    );
    // And a population floor so a near-empty load can't pass vacuously.
    assert!(
        embedded.len() >= 800,
        "embedded detector population collapsed to {} (<800)",
        embedded.len()
    );
}
