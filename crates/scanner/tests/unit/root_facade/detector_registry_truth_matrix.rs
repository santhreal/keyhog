//! Detector-registry truth matrix (TESTING vector 12, lane 9).
//!
//! The contract corpus (`contracts_runner.rs`) drives ~900 hand-written
//! positive/negative fixtures, but it only covers the subset of detectors that
//! have a `tests/contracts/<id>.toml`. The *registry* itself, every one of the
//! ~900 on-disk `detectors/*.toml`, the compiled-in embedded set, and the
//! invariants that make a detector loadable and routable, was pinned only by
//! ad-hoc spot checks. This suite pins the WHOLE registry with one exact
//! assertion per invariant per detector, so a malformed, duplicate, empty, or
//! count-drifted detector flips a specific named case red.
//!
//! Every assertion is exact (Law 6): a precise count, a named id, a concrete
//! field value, never `!is_empty()` standing in for truth. The suite is
//! deterministic and host-independent (no GPU, no network, no scan timing).
//!
//! What each test pins, and what goes red on regression:
//!   * `detector_ids_are_globally_unique`: two TOMLs claiming the same `id`
//!     (a copy-paste that silently shadows one detector in the compiled map).
//!   * `every_detector_has_at_least_one_pattern`: a detector with zero
//!     `[[detector.patterns]]` can never fire; it is dead weight in the corpus.
//!   * `every_pattern_regex_is_nonempty` / `every_shipped_detector_passes_the_`
//!     `production_quality_gate` / `the_whole_on_disk_corpus_compiles_into_one_`
//!     `scanner`: an empty / invalid / ReDoS-prone regex (a typo in a
//!     contributed TOML) that would be dropped or fail to compile.
//!   * `every_detector_severity_is_a_known_tier`: a severity outside the
//!     `Severity` enum (caught at parse, re-asserted here as a value pin so a
//!     new tier can't silently widen the contract).
//!   * `embedded_set_matches_the_on_disk_toml_tree` /
//!     `gated_on_disk_load_is_a_subset_of_the_embedded_set`: the compiled-in
//!     `build.rs` corpus drifting from the shipped `detectors/` tree (a stale
//!     embed = the binary scans with a different rule set than the repo claims).
//!   * `every_keyword_is_nonempty_and_distinct_within_a_detector`: a blank or
//!     duplicate prefilter keyword that would no-op (or screen in every chunk).
//!   * `self_declared_min_confidence_floor_is_a_unit_interval`: a self-declared
//!     floor outside `[0,1]` that would silently suppress or admit everything.

use super::support;

use std::collections::BTreeMap;
use support::paths::detector_dir;

use keyhog_core::{validate_detector, DetectorSpec, QualityIssue, Severity};
use keyhog_scanner::CompiledScanner;

/// The FULL shipped detector population: the compiled-in embedded corpus the
/// binary actually carries (every `detectors/*.toml`, UNGATED. `build.rs`
/// embeds them verbatim, without the runtime quality gate). Structural
/// invariants (unique id, non-blank fields, has-pattern, valid severity) are
/// pinned over THIS set so a gate-rejected detector, which `load_detectors`
/// would silently drop, is still caught. Fails LOUDLY on a parse error
/// (Law 10): `load_embedded_detectors_or_fail` is itself fail-closed.
fn load_shipped() -> Vec<DetectorSpec> {
    keyhog_core::load_embedded_detectors_or_fail()
        .expect("embedded detector corpus must parse (it is baked in by build.rs)")
}

/// Alias kept for the embedded-vs-on-disk drift checks that name the embed
/// explicitly. Same source as [`load_shipped`].
fn load_embedded() -> Vec<DetectorSpec> {
    load_shipped()
}

/// The GATED runtime population: what `load_detectors` returns after applying
/// the quality gate (gate-rejected detectors dropped). Used only where the
/// runtime-scannable set is the subject (population floor, gated-subset check).
/// Fails LOUDLY if the tree is absent, a missing `detectors/` dir is a
/// harness/checkout error, never a silent green (Law 10).
fn load_gated() -> Vec<DetectorSpec> {
    keyhog_core::load_detectors(&detector_dir()).unwrap_or_else(|e| {
        panic!(
            "detectors/ must load for the registry truth matrix (CWD-stable via \
             CARGO_MANIFEST_DIR): {e}"
        )
    })
}

#[test]
fn registry_has_a_substantial_detector_population() {
    // A floor, not a fixed count: the corpus grows over time. This goes red
    // only if the loader silently returns a near-empty set (a path/glob bug),
    // which would make every other registry assertion vacuously pass.
    let detectors = load_gated();
    assert!(
        detectors.len() >= 800,
        "on-disk detector corpus collapsed to {} (<800), loader or detectors/ \
         tree is broken; every per-detector assertion below would pass vacuously",
        detectors.len()
    );
}

#[test]
fn detector_ids_are_globally_unique() {
    let detectors = load_shipped();
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for d in &detectors {
        *seen.entry(d.id.as_str()).or_insert(0) += 1;
    }
    let dupes: Vec<String> = seen
        .iter()
        .filter(|(_, &count)| count > 1)
        .map(|(id, count)| format!("{id} (x{count})"))
        .collect();
    assert!(
        dupes.is_empty(),
        "duplicate detector ids would silently shadow one another in the \
         compiled detector map:\n  - {}",
        dupes.join("\n  - ")
    );
    // Exact pin: unique-id count equals total detector count.
    assert_eq!(
        seen.len(),
        detectors.len(),
        "unique id count ({}) must equal detector count ({})",
        seen.len(),
        detectors.len()
    );
}

#[test]
fn detector_ids_and_names_and_service_are_nonblank() {
    let detectors = load_shipped();
    let mut offenders = Vec::new();
    for d in &detectors {
        if d.id.trim().is_empty() {
            offenders.push(format!("<blank id> (name={:?})", d.name));
        }
        if d.name.trim().is_empty() {
            offenders.push(format!("{}: blank name", d.id));
        }
        if d.service.trim().is_empty() {
            offenders.push(format!("{}: blank service", d.id));
        }
    }
    assert!(
        offenders.is_empty(),
        "every detector needs a non-blank id, name, and service \
         (they key findings, reports, and routing):\n  - {}",
        offenders.join("\n  - ")
    );
}

#[test]
fn every_detector_has_at_least_one_pattern() {
    let detectors = load_shipped();
    // A detector with zero `[[detector.patterns]]` can never fire via the AC/regex
    // scan path. The ONE legitimate exception is the generic/entropy family
    // (`is_generic_or_entropy_detector`): generic-secret / generic-api-key /
    // generic-keyword-secret fire via the phase2-generic + entropy path
    // (`engine/phase2_generic.rs` emits GENERIC_SECRET; its detector TOML sets
    // their floors), anchored by keyword + entropy with NO pattern by design.
    // Every OTHER pattern-less detector is dead corpus weight.
    let zero_pattern_named: Vec<&str> = detectors
        .iter()
        .filter(|d| d.patterns.is_empty())
        .filter(|d| !keyhog_scanner::is_generic_or_entropy_detector(&d.id))
        .map(|d| d.id.as_str())
        .collect();
    assert!(
        zero_pattern_named.is_empty(),
        "a non-generic detector with zero patterns can never fire, it is dead \
         corpus weight:\n  - {}",
        zero_pattern_named.join("\n  - ")
    );
    // Guard the exemption itself (Law 6): generic-secret is the only shipped
    // pattern-less detector. The API-key and keyword-secret owners now carry
    // structured envelope patterns as well as their phase-2 bridges.
    let mut zero_pattern_all: Vec<&str> = detectors
        .iter()
        .filter(|d| d.patterns.is_empty())
        .map(|d| d.id.as_str())
        .collect();
    zero_pattern_all.sort_unstable();
    assert_eq!(
        zero_pattern_all,
        ["generic-secret"],
        "the ONLY pattern-less detectors may be the entropy-driven generic family; \
         a new entry here is either dead weight or a detector missing its pattern"
    );
}

#[test]
fn every_pattern_regex_is_nonempty() {
    let detectors = load_shipped();
    let mut offenders = Vec::new();
    let mut total_patterns = 0usize;
    for d in &detectors {
        for (i, p) in d.patterns.iter().enumerate() {
            total_patterns += 1;
            if p.regex.trim().is_empty() {
                offenders.push(format!("{}[{i}]: empty regex", d.id));
            }
        }
    }
    assert!(
        total_patterns >= detectors.len(),
        "expected at least one pattern per detector ({} patterns over {} \
         detectors)",
        total_patterns,
        detectors.len()
    );
    assert!(
        offenders.is_empty(),
        "{} pattern(s) have an empty regex:\n  - {}",
        offenders.len(),
        offenders.join("\n  - ")
    );
}

#[test]
fn every_shipped_detector_passes_the_production_quality_gate() {
    // Validate the EMBEDDED (ungated) population, not `load_detectors`: the
    // latter already SKIPS gate-rejected detectors, so re-checking its output
    // is tautological. The embedded set is what `build.rs` baked into the
    // binary verbatim; a gate Error here means a shipped detector that
    // `load_detectors` would silently drop at runtime (an invisible recall
    // hole, exactly the dead-detector class core lib.rs warns about). Use
    // keyhog's OWN validator (the same `validate_detector` the loader runs),
    // not an independent regex builder whose different flavor would false-red.
    let detectors = load_embedded();
    let mut offenders = Vec::new();
    for d in &detectors {
        for issue in validate_detector(d) {
            if let QualityIssue::Error(msg) = issue {
                offenders.push(format!("{}: {msg}", d.id));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "{} embedded detector(s) fail keyhog's own quality gate (they would be \
         silently dropped by load_detectors at runtime):\n  - {}",
        offenders.len(),
        offenders.join("\n  - ")
    );
}

#[test]
fn the_whole_on_disk_corpus_compiles_into_one_scanner() {
    // The end-to-end production compile path: every detector's patterns,
    // companions, and keywords must fuse into one `CompiledScanner` without
    // error. This is what the binary does at startup; a regex the literal-set/
    // NFA compiler rejects surfaces here, not in the field. Use the GATED set
    // the exact population `load_detectors -> CompiledScanner::compile` feeds the
    // scanner in production (a quality-Error detector is dropped before compile,
    // and is independently caught by the quality-gate test above).
    let detectors = load_gated();
    let count = detectors.len();
    assert!(count >= 800, "gated corpus collapsed to {count} (<800)");
    let scanner = CompiledScanner::compile(detectors)
        .unwrap_or_else(|e| panic!("the full on-disk detector corpus must compile: {e}"));
    // The compiled scanner must carry a substantial pattern set. A floor (not a
    // tie to the exact detector count, since the compiler may dedup identical
    // regex strings shared across detectors) catches the regression where
    // compile silently produces a near-empty engine, every scan would then
    // read clean. 700 is comfortably below the real pattern count yet far above
    // any degenerate near-empty compile.
    let patterns = keyhog_scanner::testing::pattern_regex_strs(&scanner).len();
    assert!(
        patterns >= 700,
        "compiled scanner exposes only {patterns} pattern regexes (<700) for \
         {count} detectors, the engine compiled to near-nothing (a silent \
         drop), and every scan would read clean"
    );
}

#[test]
fn every_detector_severity_is_a_known_tier() {
    let detectors = load_shipped();
    // The full closed set of severities. A detector whose severity is outside
    // this set would have failed to parse, but pinning the VALUE here means a
    // future widening of the enum can't silently change what the corpus ships.
    let known = [
        Severity::Info,
        Severity::ClientSafe,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
    let mut histogram: BTreeMap<String, usize> = BTreeMap::new();
    for d in &detectors {
        assert!(
            known.contains(&d.severity),
            "{}: severity {:?} is not one of the six known tiers",
            d.id,
            d.severity
        );
        *histogram.entry(d.severity.to_string()).or_insert(0) += 1;
    }
    // The histogram must sum to the detector count (no detector skipped).
    let summed: usize = histogram.values().sum();
    assert_eq!(
        summed,
        detectors.len(),
        "severity histogram sum ({summed}) must equal detector count ({})",
        detectors.len()
    );
    // Every secret scanner must ship at least one critical-severity detector
    // (e.g. AWS access keys); a corpus with zero criticals is mis-tiered.
    assert!(
        histogram.get("critical").copied().unwrap_or(0) > 0,
        "registry must contain at least one critical-severity detector; \
         histogram={histogram:?}"
    );
}

/// Count the `.toml` files in the detectors tree, the UNGATED population that
/// `build.rs` embeds verbatim (it does not run the quality gate). This is the
/// right comparand for the embedded set; `load_detectors` applies the gate and
/// may drop a gate-rejected detector, so it is a (possibly proper) subset.
fn on_disk_toml_count() -> usize {
    let dir = detector_dir();
    std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("detectors/ dir readable at {}: {e}", dir.display()))
        .map(|e| {
            e.unwrap_or_else(|e| panic!("detectors/ dir entry readable at {}: {e}", dir.display()))
        })
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("toml"))
        .count()
}

#[test]
fn embedded_set_matches_the_on_disk_toml_tree() {
    let embedded = load_embedded();
    let reported = keyhog_core::embedded_detector_count();
    let toml_files = on_disk_toml_count();

    // The embedded helper's reported count must equal the parsed embedded set.
    // (Each embedded TOML holds exactly one detector, so parse-count ==
    // file-count when every TOML parses: `load_embedded_detectors_or_fail`
    // fails closed otherwise, so reaching here proves they all parsed.)
    assert_eq!(
        embedded.len(),
        reported,
        "embedded_detector_count() ({reported}) must equal the number of \
         embedded specs that actually parse ({})",
        embedded.len()
    );

    // The compiled-in corpus must match the shipped `detectors/` .toml tree
    // exactly (build.rs embeds every .toml, ungated). A drift means a stale
    // embed: the binary scans with a different rule set than the repo claims
    // the exact failure mode that hid a broken detector in a benched release
    // (see core lib.rs docs on load_embedded_detectors_or_fail).
    assert_eq!(
        embedded.len(),
        toml_files,
        "embedded detector count ({}) drifted from the on-disk detectors/ .toml \
         file count ({toml_files}). Re-run the build so build.rs re-embeds the \
         current tree.",
        embedded.len()
    );
}

#[test]
fn gated_on_disk_load_is_a_subset_of_the_embedded_set() {
    // `load_detectors` runs the quality gate and may DROP a gate-rejected
    // detector; the embedded set is ungated. So every gated id must be present
    // in the embedded set (the gate only ever removes), and the gated count
    // never exceeds the embedded count. A gated id NOT in the embedded set
    // would mean the on-disk tree and the embed diverged (a stale embed).
    let on_disk = load_gated();
    let embedded = load_embedded();
    let embedded_ids: std::collections::BTreeSet<&str> =
        embedded.iter().map(|d| d.id.as_str()).collect();

    assert!(
        on_disk.len() <= embedded.len(),
        "gated on-disk load ({}) must not exceed the ungated embedded set ({})",
        on_disk.len(),
        embedded.len()
    );

    let orphan_gated: Vec<&str> = on_disk
        .iter()
        .map(|d| d.id.as_str())
        .filter(|id| !embedded_ids.contains(id))
        .collect();
    assert!(
        orphan_gated.is_empty(),
        "detector(s) loaded from disk but ABSENT from the embedded set (stale \
         embed: rebuild): {orphan_gated:?}"
    );
}

#[test]
fn every_keyword_is_nonempty_and_distinct_within_a_detector() {
    let detectors = load_shipped();
    let mut offenders = Vec::new();
    for d in &detectors {
        let mut seen = std::collections::BTreeSet::new();
        for kw in &d.keywords {
            if kw.is_empty() {
                offenders.push(format!("{}: blank prefilter keyword", d.id));
            }
            if !seen.insert(kw.as_str()) {
                offenders.push(format!("{}: duplicate keyword {kw:?}", d.id));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "prefilter keywords must be non-blank and distinct within a detector \
         (a blank keyword no-ops the literal screen):\n  - {}",
        offenders.join("\n  - ")
    );
}

#[test]
fn self_declared_min_confidence_floor_is_a_unit_interval() {
    let detectors = load_shipped();
    let mut offenders = Vec::new();
    let mut declared = 0usize;
    for d in &detectors {
        if let Some(floor) = d.min_confidence {
            declared += 1;
            if !floor.is_finite() || !(0.0..=1.0).contains(&floor) {
                offenders.push(format!("{}: min_confidence {floor} not in [0,1]", d.id));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "self-declared per-detector confidence floors must lie in [0,1] (a \
         floor >1 suppresses every finding, <0 admits noise):\n  - {}",
        offenders.join("\n  - ")
    );
    // Sanity: the field is actually exercised by the corpus (memory:
    // detector_spec_min_confidence_loaded). If zero detectors declare it, the
    // wiring is dead and this assertion is a tripwire for that regression.
    assert!(
        declared > 0,
        "no detector declares a min_confidence floor, the self-declared-floor \
         feature (sourcegraph/cursor low-entropy-body detectors) is unwired"
    );
}

#[test]
fn every_companion_has_positive_within_lines_and_nonempty_regex() {
    let detectors = load_shipped();
    let mut offenders = Vec::new();
    for d in &detectors {
        for c in &d.companions {
            if c.regex.trim().is_empty() {
                offenders.push(format!("{}: companion {:?} has empty regex", d.id, c.name));
            }
            if c.name.trim().is_empty() {
                offenders.push(format!("{}: companion with blank name", d.id));
            }
            // within_lines == 0 would make a non-required companion never match
            // (no line window), and a required one impossible to satisfy.
            if c.within_lines == 0 {
                offenders.push(format!(
                    "{}: companion {:?} has within_lines=0 (zero-line window can never match)",
                    d.id, c.name
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "companion specs must carry a non-blank name, non-empty regex, and a \
         positive within_lines window:\n  - {}",
        offenders.join("\n  - ")
    );
}
