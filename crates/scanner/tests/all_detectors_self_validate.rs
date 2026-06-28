//! Per-detector self-validation: every TOML in `detectors/` must
//! (a) load via keyhog_core, (b) compile its regex(es) via the
//! Hyperscan / regex backend, (c) declare at least one keyword
//! ≥ 4 chars (the phase-2 keyword prefilter floor), and (d) have at
//! least one canonical-shape positive that fires.
//!
//! The "canonical-shape positive" comes from the auto-generator
//! in `tools/gen_contracts.py` - we don't duplicate its synthesis
//! logic in Rust. Instead, we check that EVERY detector either
//! (i) has a contract under `tests/contracts/<id>.toml` with a
//! positive that fires, OR (ii) we mark it as deferred-no-contract
//! and that count is bounded.
//!
//! This is the bar a 890-detector engine has to clear before any
//! claim of "ships X detectors" is honest. A detector that loads
//! but never fires is decoration.

mod support;
use support::paths::detector_dir;

use std::collections::BTreeSet;
use std::path::PathBuf;

use keyhog_core::Chunk;
use keyhog_core::ChunkMetadata;
use keyhog_scanner::CompiledScanner;

fn contracts_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests");
    d.push("contracts");
    d
}

fn detector_ids_on_disk() -> BTreeSet<String> {
    std::fs::read_dir(detector_dir())
        .expect("detectors dir readable")
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) != Some("toml") {
                return None;
            }
            p.file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.to_string())
        })
        .collect()
}

fn contract_ids_on_disk() -> BTreeSet<String> {
    std::fs::read_dir(contracts_dir())
        .map(|d| {
            d.flatten()
                .filter_map(|e| {
                    let p = e.path();
                    if p.extension().and_then(|s| s.to_str()) != Some("toml") {
                        return None;
                    }
                    p.file_stem()
                        .and_then(|s| s.to_str())
                        .map(|s| s.to_string())
                })
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default()
}

/// Every detector TOML in `detectors/` must successfully load through
/// `keyhog_core::load_detectors`. A parse failure here means the TOML
/// is malformed and the embedded-detectors build would have produced a
/// dead-on-arrival entry. This is the floor - no detector ships with
/// a malformed TOML. The check is loaded-count == file-count, NOT
/// id-matches-filename (many TOMLs use a different `id` than their
/// stem, e.g. `data-gov-api.toml` declares `id = "data-gov-api-key"`).
#[test]
fn every_detector_loads() {
    let dir = detector_dir();

    let mut files = std::fs::read_dir(&dir)
        .expect("read_dir")
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) == Some("toml") {
                Some(p)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    files.sort();

    let mut failed_to_parse = 0;
    let mut failed_quality_gate = 0;

    for path in &files {
        let content = std::fs::read_to_string(path).expect("read");
        let parsed = toml::from_str::<keyhog_core::DetectorFile>(&content);
        match parsed {
            Err(e) => {
                println!("TOML Parse Error in {}: {}", path.display(), e);
                failed_to_parse += 1;
            }
            Ok(file) => {
                let issues = keyhog_core::validate_detector(&file.detector);
                let has_errors = issues
                    .iter()
                    .any(|issue| matches!(issue, keyhog_core::QualityIssue::Error(_)));
                if has_errors {
                    println!("Quality Gate Errors in {}:", path.display());
                    for issue in issues {
                        if let keyhog_core::QualityIssue::Error(err) = issue {
                            println!("  - {}", err);
                        }
                    }
                    failed_quality_gate += 1;
                }
            }
        }
    }

    println!("Total TOML files: {}", files.len());
    println!("Failed to parse: {}", failed_to_parse);
    println!("Failed quality gate: {}", failed_quality_gate);

    let detectors = keyhog_core::load_detectors(&dir)
        .unwrap_or_else(|e| panic!("load_detectors({}) failed: {e}", dir.display()));
    assert!(
        !detectors.is_empty(),
        "detectors/ contains no loadable TOML - embedded count would be 0"
    );

    let file_count = detector_ids_on_disk().len();
    let loaded_count = detectors.len();
    assert_eq!(
        loaded_count, file_count,
        "loaded detector count ({loaded_count}) ≠ on-disk TOML count ({file_count}); \
         a TOML failed to parse silently in load_detectors"
    );
}

/// Every detector must compile into the scanner's regex backend.
/// A regex that parses as TOML but fails Hyperscan / regex compilation
/// is invisible at runtime - `CompiledScanner::compile` is the gate.
#[test]
fn every_detector_compiles_into_scanner() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let _scanner = CompiledScanner::compile(detectors)
        .expect("scanner compile must succeed for every loaded detector");
}

/// Every detector must declare at least one keyword whose length is
/// >= 3 chars. Hyperscan handles 3-char prefix anchors (e.g. `hf_`,
/// `re_`, `r8_`) on its own; the phase-2 Aho-Corasick prefilter
/// drops keywords shorter than 4, but Hyperscan is the primary
/// matching path and the 4-char floor only matters when Hyperscan is
/// unavailable. Three chars is the absolute floor: a detector with
/// only 1-2 char keywords would be invisible to both paths.
#[test]
fn every_detector_has_at_least_one_keyword_geq_3() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let mut bad: Vec<String> = Vec::new();
    for d in &detectors {
        let has_long = d.keywords.iter().any(|k| k.len() >= 3);
        if !has_long {
            bad.push(format!(
                "{} (keywords: {:?})",
                d.id,
                d.keywords.iter().map(|k| k.as_str()).collect::<Vec<_>>()
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "{} detectors have NO keyword >= 3 chars (will be invisible to BOTH Hyperscan and AC):\n  - {}",
        bad.len(),
        bad.join("\n  - ")
    );
}

/// Every detector must declare a service, a severity, and at least
/// one pattern. Empty pattern arrays mean the detector loads but
/// never scans for anything.
#[test]
fn every_detector_has_metadata_and_patterns() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let mut bad: Vec<String> = Vec::new();
    for d in &detectors {
        if d.service.is_empty() {
            bad.push(format!("{}: missing service", d.id));
        }
        if d.patterns.is_empty() {
            bad.push(format!("{}: zero patterns", d.id));
        }
    }
    assert!(
        bad.is_empty(),
        "{} detectors have missing required metadata:\n  - {}",
        bad.len(),
        bad.join("\n  - ")
    );
}

/// Contract coverage bound: at least 50% of detectors must have a
/// per-rule contract under `tests/contracts/`. The aspirational
/// target is 100%; this floor catches regressions where a detector
/// gets added but no contract follows. Run `tools/gen_contracts.py
/// --write` to auto-generate stubs for the simple-shape detectors.
#[test]
fn detector_contract_coverage_meets_floor() {
    // Compare detector INTERNAL IDS (the runtime-canonical identifier the
    // scanner, findings, SARIF rule ids, and the contracts_runner all key on)
    // to the contract stems - NOT filenames. 10 detectors carry a filename
    // that drifts from their internal id (e.g. file `data-gov-api.toml` with
    // `id = "data-gov-api-key"`, file `npm-token.toml` with
    // `id = "npm-access-token"`); the contract is correctly named by the id,
    // so the old filename-based comparison falsely reported those 10 as
    // uncovered (892/902) when their by-id contract exists. By id, coverage is
    // exact.
    let detector_ids: BTreeSet<String> = keyhog_core::load_detectors(&detector_dir())
        .expect("load")
        .into_iter()
        .map(|d| d.id.to_string())
        .collect();
    let contracts = contract_ids_on_disk();
    let covered = detector_ids.intersection(&contracts).count();
    let total = detector_ids.len();
    let ratio = covered as f64 / total.max(1) as f64;
    // Floor 1.0: every detector id MUST have a contract under
    // tests/contracts/<id>.toml. This was a stale, toothless 0.38 (it predated
    // the contract backfill); a regression could silently drop hundreds of
    // contracts and stay green. Now adding a detector without a contract -
    // or renaming a detector id without renaming its contract - fails closed.
    let floor = 1.0;
    let missing: Vec<&String> = detector_ids.difference(&contracts).collect();
    assert!(
        ratio >= floor,
        "detector(id) → contract coverage {covered}/{total} = {ratio:.4} below floor {floor:.4}; \
         {} detector ids lack a tests/contracts/<id>.toml: {missing:?}",
        missing.len()
    );
}

/// Smoke: a single bench-emitted shape per category must fire SOMETHING.
/// This is the "engine produces findings" backstop - if a regression
/// silently breaks the entire scanner, this test goes red.
#[test]
fn smoke_scanner_fires_on_canonical_aws_ghp_re_examples() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // (label, text containing a canonical-shape secret). Values are
    // hand-rolled fake-but-realistic credentials, NOT the public
    // AWS/GitHub docs placeholders (which suffix `EXAMPLE` and trip
    // `is_known_example_credential`) - the smoke gate's job is to
    // catch a scanner regression, not to test the placeholder filter.
    let cases: Vec<(&str, &str)> = vec![
        (
            "aws-access-key",
            "export AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYxqfwh4qWqHJK",
        ),
        ("github-classic-pat", "GITHUB_TOKEN=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"),
        ("resend-api-key", "RESEND_API_KEY=re_aBcDefGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWx"),
        ("openai-api-key", "OPENAI_API_KEY=sk-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYz"),
    ];
    for (label, text) in cases {
        let chunk = Chunk {
            data: text.into(),
            metadata: ChunkMetadata {
                source_type: "smoke".into(),
                path: Some("smoke.env".into()),
                ..Default::default()
            },
        };
        scanner.clear_fragment_cache();
        let matches = scanner.scan(&chunk);
        assert!(
            !matches.is_empty(),
            "smoke: scanner found NO findings on {label} canonical fixture: {text:?}"
        );
    }
}
