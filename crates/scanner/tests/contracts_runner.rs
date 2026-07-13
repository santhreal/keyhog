//! Per-detector contract runner.
//!
//! Walks `tests/contracts/*.toml` and enforces every section that
//! CLAUDE.md "per-rule directory contract" mandates (positives,
//! negatives, evasions, cve_replay, perf, scale, readme_claim).
//! Adding a new TOML adds a new contract; every existing TOML must
//! stay green or the test suite fails.
//!
//! The runner is the same shape for every detector - the per-rule
//! TOML is the only thing the contributor edits. That's the
//! lego-block move: build the harness once, instantiate per
//! detector by writing data, not code.

mod support;
use support::paths::detector_dir;

use std::collections::BTreeMap;
use std::path::PathBuf;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Contract {
    #[allow(dead_code)]
    schema_version: u32,
    detector_id: String,
    #[allow(dead_code)]
    service: String,
    #[allow(dead_code)]
    severity: String,
    #[serde(default)]
    positive: Vec<Positive>,
    #[serde(default)]
    negative: Vec<Negative>,
    #[serde(default)]
    evasion: Vec<Positive>,
    #[serde(default)]
    cve_replay: Vec<Positive>,
    #[serde(default)]
    perf: Option<PerfBudget>,
    #[serde(default)]
    scale: Option<ScaleBudget>,
    #[serde(default)]
    readme_claim: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Positive {
    text: String,
    credential: String,
    #[allow(dead_code)]
    reason: String,
}

#[derive(Debug, Deserialize)]
struct Negative {
    text: String,
    #[allow(dead_code)]
    reason: String,
}

// `deny_unknown_fields`: a top-level scalar written AFTER a `[perf]`/`[scale]`
// header binds to that table in TOML, not to the Contract. A `readme_claim`
// misplaced at the bottom of a contract used to land here and be silently
// dropped, making `every_contract_readme_claim_present` vacuous. Rejecting
// unknown budget keys turns that mistake into a loud parse error.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PerfBudget {
    fixture_bytes: usize,
    max_microseconds: u64,
    #[allow(dead_code)]
    note: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScaleBudget {
    fixture_bytes: usize,
    min_findings: usize,
    max_seconds: f64,
    #[allow(dead_code)]
    note: String,
}

fn contracts_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests");
    d.push("contracts");
    d
}

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

fn load_contracts() -> Vec<(PathBuf, Contract)> {
    let dir = contracts_dir();
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) => panic!("read contracts dir {}: {e}", dir.display()),
    };
    for entry in entries {
        let entry =
            entry.unwrap_or_else(|e| panic!("read contracts dir entry {}: {e}", dir.display()));
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read contract {}: {e}", path.display()));
        let contract: Contract = match toml::from_str(&text) {
            Ok(c) => c,
            Err(e) => panic!("malformed contract {}: {e}", path.display()),
        };
        out.push((path, contract));
    }
    out
}

fn make_chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "contract".into(),
            path: Some("contract.txt".into()),
            ..Default::default()
        },
    }
}

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("detectors directory loadable from contract runner");
    CompiledScanner::compile(detectors).expect("scanner compile from contract runner")
}

fn timing_budgets_are_enforced() -> bool {
    if !cfg!(debug_assertions) {
        return true;
    }

    std::env::current_exe().is_ok_and(|path| {
        path.components().any(|component| {
            matches!(
                component.as_os_str().to_str(),
                Some("release-fast" | "release" | "bench")
            )
        })
    })
}

/// Bucket findings by their credential string so the per-fixture
/// assertions are O(1) hash lookups, not O(n) linear scans, when
/// the runner gets large.
fn finding_creds(matches: &[keyhog_core::RawMatch]) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for f in matches {
        *m.entry(f.credential.as_ref().to_string()).or_insert(0) += 1;
    }
    m
}

/// True if the expected credential substring appears in any
/// extracted credential. Used instead of strict equality because
/// keyhog's context-window extraction can over-capture trailing
/// punctuation from the surrounding text (e.g. `</token>` after a
/// PAT in an XML tag); the contract that matters is "the secret
/// is in the surfaced credential," not byte-exact equality.
fn any_credential_contains(matches: &[keyhog_core::RawMatch], expected: &str) -> bool {
    matches
        .iter()
        .any(|m| m.credential.as_ref().contains(expected))
}

#[test]
fn every_contract_passes_positives_negatives_evasions() {
    let scanner = scanner();
    let contracts = load_contracts();
    assert!(
        !contracts.is_empty(),
        "tests/contracts/ has no *.toml - at least one detector must ship a contract"
    );

    let mut failures: Vec<String> = Vec::new();
    for (path, c) in &contracts {
        let label = c.detector_id.as_str();

        for p in &c.positive {
            // CompiledScanner accumulates cross-file fragment
            // reassembly state across every scan() (see
            // engine/mod.rs:747-760). Tests that reuse one scanner
            // across independent fixtures see cross-fixture state
            // leak - e.g. braintree's `sandbox_7b3e5d8c_…` positive
            // surfacing later as a finding on blur-api-key's
            // evasion text. Clear before every scan so each fixture
            // is isolated; cache order is filesystem-dependent and
            // makes pollution a non-deterministic CI-only flake.
            scanner.clear_fragment_cache();
            let chunk = make_chunk(&p.text);
            let matches = scanner.scan(&chunk);
            if !any_credential_contains(&matches, &p.credential) {
                let creds = finding_creds(&matches);
                failures.push(format!(
                    "{}: positive MISSED - text {:?} should have surfaced credential containing {:?} ({}); \
                     scanner saw {:?}",
                    label,
                    p.text,
                    p.credential,
                    path.display(),
                    creds.keys().collect::<Vec<_>>(),
                ));
            }
        }

        for n in &c.negative {
            scanner.clear_fragment_cache();
            let chunk = make_chunk(&n.text);
            let matches = scanner.scan(&chunk);
            // We don't gate on "zero findings" - a fixture line may
            // also exercise a different detector - we gate on
            // "this detector did not fire on this text."
            let detector_fired = matches.iter().any(|m| m.detector_id.as_ref() == label);
            if detector_fired {
                let captured: Vec<&str> = matches
                    .iter()
                    .filter(|m| m.detector_id.as_ref() == label)
                    .map(|m| m.credential.as_ref())
                    .collect();
                failures.push(format!(
                    "{}: false positive on negative - text {:?} should NOT have fired \
                     ({}); scanner saw {} matches under this detector: {:?}",
                    label,
                    n.text,
                    path.display(),
                    captured.len(),
                    captured,
                ));
            }
        }

        for e in &c.evasion {
            scanner.clear_fragment_cache();
            let chunk = make_chunk(&e.text);
            let matches = scanner.scan(&chunk);
            if !any_credential_contains(&matches, &e.credential) {
                let creds = finding_creds(&matches);
                failures.push(format!(
                    "{}: evasion DROPPED - adversarial text {:?} should still surface \
                     credential containing {:?} ({}); scanner saw {:?}",
                    label,
                    e.text,
                    e.credential,
                    path.display(),
                    creds.keys().collect::<Vec<_>>(),
                ));
            }
        }

        for r in &c.cve_replay {
            scanner.clear_fragment_cache();
            let chunk = make_chunk(&r.text);
            let matches = scanner.scan(&chunk);
            if !any_credential_contains(&matches, &r.credential) {
                let creds = finding_creds(&matches);
                failures.push(format!(
                    "{}: cve_replay MISSED - leaked sample {:?} should fire on credential \
                     containing {:?} ({}); scanner saw {:?}",
                    label,
                    r.text,
                    r.credential,
                    path.display(),
                    creds.keys().collect::<Vec<_>>(),
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "per-detector contract failures:\n  - {}",
        failures.join("\n  - "),
    );
}

#[test]
fn every_contract_perf_budget_holds() {
    // Perf budgets are calibrated for optimized builds. A plain `cargo test`
    // builds the dev/debug profile, where regex matching is 10-40x slower and
    // EVERY budget blows by design - a debug-mode false alarm, not a
    // regression. `release-fast` deliberately keeps debug assertions enabled,
    // so do not use `cfg!(debug_assertions)` as the optimization proxy.
    if !timing_budgets_are_enforced() {
        eprintln!(
            "every_contract_perf_budget_holds: SKIPPED (debug build). Perf budgets \
             only hold under optimization. Enforce with:\n  \
             cargo test -p keyhog-scanner --profile release-fast --test contracts_runner"
        );
        return;
    }
    let scanner = scanner();
    // Warm regex transition caches up front: the per-detector perf budget
    // measures match THROUGHPUT (catching a regex that is catastrophically slow
    // to match), not one-time DFA/cache first-touch. Detector regexes are
    // already compiled once during scanner construction; without warming, the
    // first scan to touch each detector would fold transition-cache setup into
    // the measured μs and blow the budget - an artifact of this harness scanning
    // ~895 separate fixtures, not a real per-scan cost.
    scanner.warm();
    let contracts = load_contracts();
    let mut failures: Vec<String> = Vec::new();

    for (path, c) in &contracts {
        let Some(perf) = &c.perf else {
            continue;
        };
        // Build a fixture with one planted positive embedded in
        // benign filler; perf budget includes scanner+regex cost.
        let Some(first) = c.positive.first() else {
            continue;
        };
        let mut fixture = "x".repeat(perf.fixture_bytes.saturating_sub(first.text.len()));
        fixture.push_str(&first.text);
        let chunk = make_chunk(&fixture);

        // Warm any internal caches first; the budget gates steady-
        // state, not cold-start. Clear the fragment cache before
        // the warmup AND before each measured pass so none inherits
        // state from another contract's fixture.
        scanner.clear_fragment_cache();
        let _ = scanner.scan(&chunk);

        // Best-of-N steady-state timing. A single wall-clock sample on a shared
        // CI runner occasionally folds in a scheduler-preemption / cache-eviction
        // spike (observed: azure-blob-sas-token + jwt-token tripping a 15 ms
        // budget by 1-3% on one noisy sample while steady-state sits well under).
        // The budget gates match THROUGHPUT, so keep the best of a few passes:
        // a catastrophically slow regex blows the budget on EVERY pass (the min
        // still exceeds it and we still fail), while a one-off stall is discarded.
        // The common case, under budget on the first pass, pays for exactly one
        // scan: the loop breaks as soon as a pass comes in under budget.
        let mut micros = u64::MAX;
        for _ in 0..5 {
            scanner.clear_fragment_cache();
            let start = std::time::Instant::now();
            let _ = scanner.scan(&chunk);
            micros = micros.min(start.elapsed().as_micros() as u64);
            if micros <= perf.max_microseconds {
                break;
            }
        }
        if micros > perf.max_microseconds {
            failures.push(format!(
                "{}: perf budget exceeded ({}): {}μs > budget {}μs",
                c.detector_id,
                path.display(),
                micros,
                perf.max_microseconds,
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "per-detector perf budget failures:\n  - {}",
        failures.join("\n  - "),
    );
}

#[test]
fn every_contract_scale_gate_holds() {
    let scanner = scanner();
    // See `every_contract_perf_budget_holds`: warm so the scale budget
    // (max_seconds on a multi-MB fixture) measures scanning, not one-time
    // regex transition-cache setup for the detector under test.
    scanner.warm();
    let contracts = load_contracts();
    let mut failures: Vec<String> = Vec::new();

    for (path, c) in &contracts {
        let Some(scale) = &c.scale else {
            continue;
        };
        let Some(first) = c.positive.first() else {
            continue;
        };
        // Build a `fixture_bytes`-sized chunk with the planted
        // credential at the midpoint. Filler is a punctuation+
        // whitespace pattern: detector regexes operate on
        // alphanumeric runs, so non-alphanumeric filler can't
        // false-match AND can't extend a true match into a
        // many-MB greedy capture (e.g. stripe's
        // `sk_live_[a-zA-Z0-9]{24,}` would match the entire
        // filler if the filler were `xxx...`, blowing the
        // post-process length cap). Spaces + newlines break up
        // any partial-keyword false hits cleanly.
        let half = scale.fixture_bytes / 2;
        let cycle = b". \n";
        let filler: Vec<u8> = (0..scale.fixture_bytes - first.text.len())
            .map(|i| cycle[i % cycle.len()])
            .collect();
        let filler_a = String::from_utf8_lossy(&filler[..half.min(filler.len())]).into_owned();
        let filler_b = String::from_utf8_lossy(&filler[half.min(filler.len())..]).into_owned();
        let fixture = format!("{filler_a}{}{filler_b}", first.text);
        let chunk = make_chunk(&fixture);

        let start = std::time::Instant::now();
        let matches = scanner.scan(&chunk);
        let elapsed = start.elapsed().as_secs_f64();

        // Detector-agnostic: cross-detector dedup can relabel a
        // finding (e.g. github-classic-pat → hot-github_pat on
        // the fast-path), so the contract gates on "this
        // credential string is surfaced under SOME detector,"
        // not "the labelled detector fired." That's what the end
        // user actually cares about - the credential is in the
        // report.
        let surfaced = matches
            .iter()
            .filter(|m| m.credential.as_ref().contains(&first.credential))
            .count();
        if surfaced < scale.min_findings {
            failures.push(format!(
                "{}: scale MISSED - {} surfaced < {} required ({}); raw finding count = {}",
                c.detector_id,
                surfaced,
                scale.min_findings,
                path.display(),
                matches.len(),
            ));
        }
        // Correctness (the credential still surfaces in a multi-MB fixture) is
        // checked above in every build. The wall-clock budget, like the
        // per-detector perf budget, only holds under optimization - skip the
        // timing assertion in a plain dev/debug test so it doesn't report
        // phantom "scale budget exceeded" failures from 10-40x-slower debug
        // regex matching. CI enforces it via `--profile release-fast`.
        if timing_budgets_are_enforced() && elapsed > scale.max_seconds {
            failures.push(format!(
                "{}: scale budget exceeded - {:.3}s > budget {:.3}s ({})",
                c.detector_id,
                elapsed,
                scale.max_seconds,
                path.display(),
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "per-detector scale budget failures:\n  - {}",
        failures.join("\n  - "),
    );
}

/// README claims are pinned: a `readme_claim` in a contract MUST
/// literally appear in the repo README. Catches the case where the
/// README brags about supporting a detector but the contract for
/// that detector silently drifts out of sync.
#[test]
fn every_contract_readme_claim_present() {
    let contracts = load_contracts();
    let readme_path = repo_root().join("README.md");
    let readme = match std::fs::read_to_string(&readme_path) {
        Ok(t) => t,
        Err(e) => {
            // SKIP - running from an export without the root README.
            eprintln!("SKIP: README.md not at {}: {e}", readme_path.display());
            return;
        }
    };
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for (path, c) in &contracts {
        if let Some(claim) = &c.readme_claim {
            checked += 1;
            if !readme.contains(claim) {
                failures.push(format!(
                    "{}: README claim {:?} not present in README.md ({})",
                    c.detector_id,
                    claim,
                    path.display(),
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "README claim drift:\n  - {}",
        failures.join("\n  - "),
    );

    // Liveness floor: this gate is only meaningful if it actually checked
    // claims. A `readme_claim` placed after a `[perf]`/`[scale]` header binds
    // to the budget table, not the Contract, so it parsed as `None` and this
    // test passed vacuously for years. `deny_unknown_fields` on the budget
    // structs now makes that a loud parse error; this floor is the second
    // guard, so the gate cannot silently regress to checking nothing.
    assert!(
        checked >= 6,
        "every_contract_readme_claim_present checked only {checked} readme_claim(s). \
         expected >= 6. A claim was likely misplaced under a [table] and dropped; \
         move it to the top-level scalar position (right after `severity`).",
    );
}

/// Every contract's `detector_id` MUST resolve to a real loaded detector.
/// An orphan id is not harmless: the negative-test loop keys `detector_fired`
/// on `detector_id`, so a contract for a non-existent detector has VACUOUS
/// precision coverage (its negatives can never fire). Found `nih-pubmed-api`
/// (real id `nih-pubmed-api-key`) this way.
/// Every contract MUST ship at least one `[[evasion]]` fixture. Ratchet gate:
/// backlog must not grow above the pinned ceiling; lower the ceiling as
/// backfill lands until it reaches 0 and this becomes a hard zero-tolerance gate.
#[test]
fn every_contract_has_evasion_section() {
    /// Contracts still missing `[[evasion]]` (count from TOML scan). Lower when
    /// backfilling; target reached. 2026-07-02: 129 contracts lacked `[[evasion]]`.
    /// 2026-07-06: backfilled ALL 129 → 0. This is now a HARD ZERO-TOLERANCE GATE:
    /// every detector contract ships at least one adversarial evasion fixture, and
    /// any new detector added without one fails here. Each evasion was derived from a
    /// valid positive (anchor+value preserved), wrapped in a realistic adversarial
    /// context, and BINARY-PROBED with the shipped v0.5.40 CLI in isolation to
    /// confirm it surfaces the exact credential before landing. Subtleties handled:
    /// required companions (twilio-api-key/twilio-iot), `[\s"']`/quote-only separators
    /// (typeform/zora/x2y2), the hex-digest gate on double-quoted 40-hex, special-char
    /// values (z85/surrealdb/thales/upcloud), connection-strings (vercel/yugabytedb),
    /// and multiline JSON (vertexai). The backfill also surfaced 5 recorded detector
    /// findings (BACKLOG §4): aerisweather/x2y2 unanchored generic-header arms,
    /// google-artifact garbage-capture, turso/woocommerce duplicate patterns.
    const EVASION_BACKLOG_CEILING: usize = 0;

    let contracts = load_contracts();
    assert!(
        !contracts.is_empty(),
        "tests/contracts/ has no *.toml - at least one detector must ship a contract"
    );

    let mut missing: Vec<String> = Vec::new();
    for (path, c) in &contracts {
        if c.evasion.is_empty() {
            missing.push(format!("{} ({})", c.detector_id, path.display()));
        }
    }

    assert!(
        missing.len() <= EVASION_BACKLOG_CEILING,
        "{} contract(s) missing [[evasion]] (ceiling {EVASION_BACKLOG_CEILING}); \
         backfill or raise ceiling only with explicit approval:\n  - {}",
        missing.len(),
        missing.join("\n  - "),
    );
}

#[test]
fn every_contract_detector_id_resolves() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors loadable");
    let ids: std::collections::HashSet<&str> = detectors.iter().map(|d| d.id.as_str()).collect();

    let contracts = load_contracts();
    let mut orphans: Vec<String> = Vec::new();
    for (path, c) in &contracts {
        if !ids.contains(c.detector_id.as_str()) {
            orphans.push(format!("{} ({})", c.detector_id, path.display()));
        }
    }
    assert!(
        orphans.is_empty(),
        "contract(s) name a detector_id with no matching detector, their negative \
         tests are vacuous (the `detector_fired` check keys on detector_id):\n  - {}",
        orphans.join("\n  - "),
    );
}

#[test]
fn contracts_cover_at_least_one_detector() {
    // Hard floor: at least one detector must ship a full contract.
    // CI must require this stays >= 1 forever; raise it as more
    // contracts land.
    let contracts = load_contracts();
    assert!(
        !contracts.is_empty(),
        "contracts/ directory has no TOMLs - the per-rule contract is the legendary bar; \
         ship at least one"
    );
    // Also assert each loaded contract has *some* test material -
    // an empty TOML is a useless contract.
    for (path, c) in &contracts {
        let total = c.positive.len() + c.negative.len() + c.evasion.len() + c.cve_replay.len();
        assert!(
            total > 0,
            "contract {} has zero test fixtures across all sections",
            path.display(),
        );
    }
}

/// A secret-FREE fingerprint of a scan result: detector id, byte offset, and
/// line for each surfaced match. Never the credential bytes (CLAUDE.md: never
/// log secrets; `RawMatch`'s own `Debug` redacts the credential for the same
/// reason). Offset makes the fingerprint injective per detector, one match
/// starts at one offset, so a divergence names exactly which finding moved,
/// appeared, or vanished without revealing the plaintext.
fn scan_fingerprint(matches: &[keyhog_core::RawMatch]) -> Vec<(String, usize, Option<usize>)> {
    matches
        .iter()
        .map(|m| {
            (
                m.detector_id.as_ref().to_string(),
                m.location.offset,
                m.location.line,
            )
        })
        .collect()
}

/// Determinism / reproducibility lock over the WHOLE contract corpus.
///
/// Scanning identical bytes twice, each scan isolated by `clear_fragment_cache`
/// exactly the way every corpus runner isolates a fixture (see the cross-scan
/// fragment-state note on `every_contract_passes_positives_negatives_evasions`
/// above). MUST yield a byte-identical finding set once sorted. This guards the
/// deliberately-engineered total order and content-determined eviction in
/// `keyhog_core`'s `RawMatch: Ord`: the per-chunk match heap once evicted at its
/// cap by HashMap / rayon *insertion* order, so the surfaced set flickered
/// run-to-run on dense chunks (the fix is documented on `RawMatch::cmp`, keyed
/// down to `location.offset`/`line` precisely so eviction is reproducible). A
/// regression that reintroduces hash-set iteration order or thread-interleaving
/// nondeterminism into the surfaced set turns this red.
///
/// This is a strict superset of `backend_parity_determinism_fixed_corpus`, which
/// pins determinism on a hand-picked ten-item corpus: here EVERY positive across
/// EVERY shipped contract is a determinism case. It is a sound BEHAVIOR contract
/// (identical input ⇒ identical output), never an accuracy rate. We do NOT
/// assert warm-cache == cold-cache: the scanner accumulates cross-scan fragment
/// state by design, so a re-scan without clearing may legitimately differ; the
/// reproducibility guarantee that callers actually depend on is the
/// cache-isolated one, which is exactly what the runners rely on.
#[test]
fn every_positive_scans_deterministically_over_the_corpus() {
    let scanner = scanner();
    let contracts = load_contracts();
    assert!(
        !contracts.is_empty(),
        "tests/contracts/ has no *.toml - the determinism sweep has nothing to drive"
    );

    // Three cache-isolated re-scans of identical bytes. Two would catch a
    // deterministic divergence; a third cheaply widens the window on any
    // order/thread-interleaving flake that only sometimes reorders the set,
    // at negligible cost (fixtures are small).
    const REPEATS: usize = 3;

    let mut divergences: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    for (_path, c) in &contracts {
        for p in &c.positive {
            let chunk = make_chunk(&p.text);

            scanner.clear_fragment_cache();
            let mut first = scanner.scan(&chunk);
            first.sort();
            let baseline = scan_fingerprint(&first);
            scanned += 1;

            for run in 1..REPEATS {
                scanner.clear_fragment_cache();
                let mut again = scanner.scan(&chunk);
                again.sort();
                // Full `RawMatch` equality (every field, floats via total_cmp)
                // the strongest possible identity, not just the fingerprint.
                if first != again {
                    let other = scan_fingerprint(&again);
                    divergences.push(format!(
                        "{det}: run#{run} finding set differs from run#0 for an identical, \
                         cache-cleared re-scan\n  run#0: {baseline:?}\n  run#{run}: {other:?}",
                        det = c.detector_id,
                    ));
                    break;
                }
            }
        }
    }

    assert!(
        scanned > 0,
        "no positive fixtures were scanned - the corpus lost every positive"
    );
    assert!(
        divergences.is_empty(),
        "{} positive fixture(s) scanned NON-deterministically (identical bytes, fragment cache \
         cleared before each scan, yet a different finding set surfaced):\n{}",
        divergences.len(),
        divergences.join("\n"),
    );
}
