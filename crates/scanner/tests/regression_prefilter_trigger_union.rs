//! Prefilter trigger-union recall contract: the `SimdCpu` (Hyperscan/SIMD)
//! backend's per-chunk trigger set MUST be the UNION of the AC-literal trigger
//! set and the Hyperscan confirmed-trigger set — never one or the other.
//!
//! Why this is recall-load-bearing (see `collect_triggered_patterns_simd`):
//! a subset of detectors have NO standalone AC literal that the Aho-Corasick
//! prefilter can key on; their pattern index is marked triggered ONLY when the
//! Hyperscan multi-pattern scan confirms an in-window fingerprint. `datadog-api-key`
//! is one such HS-only detector — its extractable trigger comes from the
//! `(?:DD.API.KEY|…)[…]([a-f0-9]{32})` regex, not from a short literal in the
//! AC set. If the SIMD collector ever stopped unioning the HS trigger bits into
//! the AC bitmap (regression: "AC triggers only"), datadog-api-key and its ~48
//! HS-only siblings would silently stop firing on the default backend — an
//! invisible recall cliff. This file pins:
//!   1. an HS-only detector (`datadog-api-key`) STILL fires on `SimdCpu`,
//!   2. an AC-literal detector (`aws-access-key`, keyword prefix `AKIA`) fires,
//!   3. a chunk that triggers NEITHER yields zero findings,
//!   4. SimdCpu-vs-CpuFallback parity on the union (both surface identical triples),
//! plus the boundary/negative-twin/adversarial twins and the dense
//! `trigger_bitmap` sizing primitive that backs the union.
//!
//! Host-independence (CLAUDE.md Law 10): `SimdCpu` is gated on the
//! side-effect-free `warm_backend` probe. On a build without the `simd` feature
//! (or a host whose Hyperscan DB failed to build) a forced `SimdCpu` scan
//! hard-exits by contract, so when it is unavailable we assert the concrete
//! `CpuFallback` values and report the skipped SIMD leg loudly rather than pass
//! vacuously.

mod support;
use std::collections::BTreeSet;
use support::paths::detector_dir;

use keyhog_core::{load_detectors, Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};

// ---- fixtures / shared helpers ----------------------------------------------

fn scanner() -> CompiledScanner {
    let detectors = load_detectors(&detector_dir()).expect("load on-disk detectors");
    CompiledScanner::compile(detectors).expect("compile scanner")
}

fn chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some(path.into()),
            ..Default::default()
        },
    }
}

/// Reset cross-file state, then scan on a specific backend so a reused scanner
/// never leaks fragment state between backends.
fn run(sc: &CompiledScanner, chunks: &[Chunk], backend: ScanBackend) -> Vec<Vec<RawMatch>> {
    sc.clear_fragment_cache();
    sc.scan_chunks_with_backend(chunks, backend)
}

/// `(detector_id, credential, absolute_offset)` triples — the exact parity key.
fn triples(results: &[Vec<RawMatch>]) -> BTreeSet<(String, String, usize)> {
    results
        .iter()
        .flat_map(|c| c.iter())
        .map(|m| {
            (
                m.detector_id.as_ref().to_string(),
                m.credential.as_ref().to_string(),
                m.location.offset,
            )
        })
        .collect()
}

fn count_detector(results: &[Vec<RawMatch>], id: &str) -> usize {
    results
        .iter()
        .flat_map(|c| c.iter())
        .filter(|m| m.detector_id.as_ref() == id)
        .count()
}

/// Exact set of credential strings a given detector surfaced.
fn creds_of(results: &[Vec<RawMatch>], id: &str) -> BTreeSet<String> {
    results
        .iter()
        .flat_map(|c| c.iter())
        .filter(|m| m.detector_id.as_ref() == id)
        .map(|m| m.credential.as_ref().to_string())
        .collect()
}

/// Run the SAME chunks on both CPU backends. The SIMD leg is `None` only when
/// this build/host has no usable Hyperscan prefilter — forcing `SimdCpu` there
/// would hard-exit the process, so gate on `warm_backend`.
fn both_cpu_backends(
    sc: &CompiledScanner,
    chunks: &[Chunk],
) -> (Vec<Vec<RawMatch>>, Option<Vec<Vec<RawMatch>>>) {
    let scalar = run(sc, chunks, ScanBackend::CpuFallback);
    let simd = if sc.warm_backend(ScanBackend::SimdCpu) {
        Some(run(sc, chunks, ScanBackend::SimdCpu))
    } else {
        eprintln!(
            "SKIP simd leg: ScanBackend::SimdCpu unavailable on this build/host \
             (no usable Hyperscan prefilter); asserting CpuFallback values only"
        );
        None
    };
    (scalar, simd)
}

// Concrete shipped fixtures (values mirror the on-disk contract corpora).
const AWS_KEY: &str = "AKIAQYLPMN5HFIQR7XYA"; // AC-literal detector (AKIA prefix)
const DD_BODY: &str = "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d"; // 32 lowercase hex, HS-only

// ---- HS-only detector: the union's whole reason to exist --------------------

#[test]
fn datadog_hs_only_detector_fires_on_simd_cpu() {
    let sc = scanner();
    let text = format!("DD_API_KEY={DD_BODY}\n");
    let chunks = vec![chunk(&text, "datadog.env")];
    let (scalar, simd) = both_cpu_backends(&sc, &chunks);

    // CpuFallback ground truth: exactly one datadog finding, exact body bytes.
    assert_eq!(
        count_detector(&scalar, "datadog-api-key"),
        1,
        "CpuFallback must surface exactly one datadog-api-key finding"
    );
    assert_eq!(
        creds_of(&scalar, "datadog-api-key"),
        BTreeSet::from([DD_BODY.to_string()]),
        "CpuFallback datadog credential must be exactly the 32-hex group-1 body"
    );

    if let Some(simd) = simd {
        // The load-bearing assertion: an HS-only detector STILL fires on the
        // SIMD backend — proving the Hyperscan trigger bits were unioned into
        // the AC trigger bitmap (a "AC-only" regression drops this to 0).
        assert_eq!(
            count_detector(&simd, "datadog-api-key"),
            1,
            "SimdCpu must fire the HS-only datadog-api-key (HS trigger unioned into AC bitmap)"
        );
        assert_eq!(
            creds_of(&simd, "datadog-api-key"),
            BTreeSet::from([DD_BODY.to_string()]),
            "SimdCpu datadog credential must match CpuFallback exactly"
        );
    }
}

#[test]
fn datadog_hs_only_parity_cpu_vs_simd() {
    let sc = scanner();
    let text = format!("DATADOG_API_KEY: \"{DD_BODY}\"\n");
    let chunks = vec![chunk(&text, "datadog.yml")];
    let (scalar, simd) = both_cpu_backends(&sc, &chunks);

    assert_eq!(
        count_detector(&scalar, "datadog-api-key"),
        1,
        "CpuFallback must surface exactly one datadog key from the YAML-style anchor"
    );
    assert_eq!(
        creds_of(&scalar, "datadog-api-key"),
        BTreeSet::from([DD_BODY.to_string()]),
        "CpuFallback datadog credential must be exactly the 32-hex body"
    );

    if let Some(simd) = simd {
        // Full triple parity (id, credential, absolute offset) across backends
        // proves the SIMD union reproduces the CpuFallback result byte-for-byte,
        // including the finding's location — not merely that "something" fired.
        assert_eq!(
            triples(&scalar),
            triples(&simd),
            "HS-only detector: CpuFallback vs SimdCpu triple sets must be identical (union parity)"
        );
    }
}

// ---- AC-literal detector: the other half of the union -----------------------

#[test]
fn aws_literal_detector_fires_on_simd_cpu() {
    let sc = scanner();
    let text = format!("const AWS_KEY = \"{AWS_KEY}\";\n");
    let chunks = vec![chunk(&text, "aws.rs")];
    let (scalar, simd) = both_cpu_backends(&sc, &chunks);

    assert_eq!(
        count_detector(&scalar, "aws-access-key"),
        1,
        "CpuFallback must surface exactly one aws-access-key finding"
    );
    assert_eq!(
        creds_of(&scalar, "aws-access-key"),
        BTreeSet::from([AWS_KEY.to_string()]),
        "CpuFallback aws credential must be exactly the AKIA key"
    );

    if let Some(simd) = simd {
        assert_eq!(
            count_detector(&simd, "aws-access-key"),
            1,
            "SimdCpu must fire the AC-literal aws-access-key (AC trigger half of the union)"
        );
        assert_eq!(
            creds_of(&simd, "aws-access-key"),
            BTreeSet::from([AWS_KEY.to_string()])
        );
    }
}

// ---- both halves in one chunk, plus full triple parity ----------------------

#[test]
fn ac_literal_and_hs_only_cosurface_same_chunk() {
    let sc = scanner();
    let text = format!(
        "const AWS_KEY = \"{AWS_KEY}\";\n\
         DD_API_KEY={DD_BODY}\n"
    );
    let chunks = vec![chunk(&text, "mixed.env")];
    let (scalar, simd) = both_cpu_backends(&sc, &chunks);

    // Both the AC-literal and the HS-only detector fire in the same chunk.
    assert_eq!(
        count_detector(&scalar, "aws-access-key"),
        1,
        "AC-literal aws-access-key must fire once in the mixed chunk"
    );
    assert_eq!(
        count_detector(&scalar, "datadog-api-key"),
        1,
        "HS-only datadog-api-key must fire once in the mixed chunk"
    );

    if let Some(simd) = simd {
        assert_eq!(
            count_detector(&simd, "aws-access-key"),
            1,
            "SimdCpu must also surface the AC-literal half"
        );
        assert_eq!(
            count_detector(&simd, "datadog-api-key"),
            1,
            "SimdCpu must also surface the HS-only half — the full union in one chunk"
        );
        assert_eq!(
            triples(&scalar),
            triples(&simd),
            "mixed AC-literal + HS-only chunk: CpuFallback vs SimdCpu triples must be identical"
        );
    }
}

// ---- chunk with NEITHER trigger is skipped (zero findings) ------------------

#[test]
fn chunk_with_neither_trigger_yields_zero_on_both() {
    let sc = scanner();
    let chunks = vec![chunk(
        "// pure prose with no credential shape or vendor anchor at all\n\
         fn hello() -> Result<(), Error> { Ok(()) }\n",
        "clean.rs",
    )];
    let (scalar, simd) = both_cpu_backends(&sc, &chunks);

    assert_eq!(
        triples(&scalar),
        BTreeSet::<(String, String, usize)>::new(),
        "CpuFallback must find nothing when neither AC nor HS triggers fire"
    );
    if let Some(simd) = simd {
        assert_eq!(
            triples(&simd),
            BTreeSet::<(String, String, usize)>::new(),
            "SimdCpu must also skip a chunk that triggers neither prefilter half"
        );
    }
}

// ---- negative twins for the HS-only detector --------------------------------

#[test]
fn datadog_bare_hex_without_anchor_suppressed_on_both() {
    let sc = scanner();
    // The 32-hex body ALONE, no `DD_API_KEY` vendor anchor: the HS pattern needs
    // the in-window `DD.API.KEY` prefix, so nothing should trigger datadog.
    let text = format!("session_token = {DD_BODY}\n");
    let chunks = vec![chunk(&text, "bare.env")];
    let (scalar, simd) = both_cpu_backends(&sc, &chunks);

    assert_eq!(
        count_detector(&scalar, "datadog-api-key"),
        0,
        "CpuFallback must NOT fire datadog-api-key on a bare 32-hex body with no vendor anchor"
    );
    if let Some(simd) = simd {
        assert_eq!(
            count_detector(&simd, "datadog-api-key"),
            0,
            "SimdCpu must also suppress the anchor-less bare hex (union must not over-fire)"
        );
        assert_eq!(
            triples(&scalar),
            triples(&simd),
            "negative-twin parity: both backends agree on the suppressed set"
        );
    }
}

#[test]
fn datadog_short_body_no_fire_on_both() {
    let sc = scanner();
    let chunks = vec![chunk("DD_API_KEY=short\n", "short.env")];
    let (scalar, simd) = both_cpu_backends(&sc, &chunks);

    assert_eq!(
        count_detector(&scalar, "datadog-api-key"),
        0,
        "a body below 32 hex chars must not fire datadog-api-key"
    );
    if let Some(simd) = simd {
        assert_eq!(count_detector(&simd, "datadog-api-key"), 0);
    }
}

#[test]
fn datadog_31_vs_32_hex_boundary_on_both() {
    let sc = scanner();
    // 31 hex: one short of the `{32}` quantifier — must NOT fire.
    let body31 = &DD_BODY[..31];
    assert_eq!(body31.len(), 31);
    let text31 = format!("DD_API_KEY={body31}\n");
    // 32 hex: exactly the quantifier — MUST fire, exact body.
    let text32 = format!("DD_API_KEY={DD_BODY}\n");

    let (scalar31, simd31) = both_cpu_backends(&sc, &vec![chunk(&text31, "dd31.env")]);
    let (scalar32, simd32) = both_cpu_backends(&sc, &vec![chunk(&text32, "dd32.env")]);

    assert_eq!(
        count_detector(&scalar31, "datadog-api-key"),
        0,
        "31-hex body must be one short of the {{32}} quantifier and not fire"
    );
    assert_eq!(
        count_detector(&scalar32, "datadog-api-key"),
        1,
        "32-hex body must fire exactly once"
    );
    if let Some(simd31) = simd31 {
        assert_eq!(count_detector(&simd31, "datadog-api-key"), 0);
    }
    if let Some(simd32) = simd32 {
        assert_eq!(count_detector(&simd32, "datadog-api-key"), 1);
        assert_eq!(
            creds_of(&simd32, "datadog-api-key"),
            BTreeSet::from([DD_BODY.to_string()])
        );
    }
}

// ---- adversarial: HS trigger survives an AC-literal-dominated chunk ---------

#[test]
fn hs_only_trigger_survives_ac_literal_storm() {
    let sc = scanner();
    // Hundreds of `AKIA_...` decoys (underscore breaks the [0-9A-Z]{16} body so
    // none are valid AWS keys) flood the AC prefilter, bracketing ONE real
    // datadog key. If the union dropped the HS half under AC-heavy load, the
    // datadog key would vanish. It must still surface exactly once.
    let mut s = String::with_capacity(16384);
    for i in 0..300 {
        s.push_str(&format!("noise AKIA_{i:08}_short line\n"));
    }
    s.push_str(&format!("DD_API_KEY={DD_BODY}\n"));
    for i in 0..300 {
        s.push_str(&format!("more  AKIA_{i:08}_short line\n"));
    }
    let chunks = vec![chunk(&s, "storm.env")];
    let (scalar, simd) = both_cpu_backends(&sc, &chunks);

    assert_eq!(
        count_detector(&scalar, "datadog-api-key"),
        1,
        "CpuFallback must confirm the single real datadog key amid 600 AKIA decoys"
    );
    // The decoys are invalid AWS keys — none confirm.
    assert_eq!(
        count_detector(&scalar, "aws-access-key"),
        0,
        "underscore-broken AKIA decoys must not confirm as aws-access-key"
    );

    if let Some(simd) = simd {
        assert_eq!(
            count_detector(&simd, "datadog-api-key"),
            1,
            "SimdCpu must still surface the HS-only datadog key under AC-literal storm (union intact)"
        );
        assert_eq!(
            triples(&scalar),
            triples(&simd),
            "AC-storm + HS-only key: CpuFallback vs SimdCpu triples must be identical"
        );
    }
}

// ---- evasion twin: lowercased anchor still routes through the union ---------

#[test]
fn datadog_lowercase_anchor_evasion_still_unions() {
    let sc = scanner();
    // `dd_api_key=` — the regex `DD.API.KEY` dot-class accepts the underscore
    // separator; the shipped evasion contract expects this to still surface.
    let text = format!("dd_api_key={DD_BODY}\n");
    let chunks = vec![chunk(&text, "evasion.env")];
    let (scalar, simd) = both_cpu_backends(&sc, &chunks);

    assert_eq!(
        count_detector(&scalar, "datadog-api-key"),
        1,
        "lowercase dd_api_key evasion must still fire datadog-api-key on CpuFallback"
    );
    if let Some(simd) = simd {
        assert_eq!(
            count_detector(&simd, "datadog-api-key"),
            1,
            "SimdCpu must route the lowercase-anchor evasion through the HS trigger union"
        );
        assert_eq!(triples(&scalar), triples(&simd));
    }
}

// ---- determinism of the SIMD union path -------------------------------------

#[test]
fn simd_union_determinism_run_twice_identical() {
    let sc = scanner();
    let text = format!("const K = \"{AWS_KEY}\";\nDD_API_KEY={DD_BODY}\n");
    let chunks = vec![chunk(&text, "det.env")];

    if !sc.warm_backend(ScanBackend::SimdCpu) {
        eprintln!("SKIP: SimdCpu unavailable; asserting CpuFallback determinism instead");
        let a = triples(&run(&sc, &chunks, ScanBackend::CpuFallback));
        let b = triples(&run(&sc, &chunks, ScanBackend::CpuFallback));
        assert_eq!(
            a, b,
            "CpuFallback union must be deterministic across two runs"
        );
        assert!(
            a.iter()
                .any(|(id, cred, _)| id == "datadog-api-key" && cred == DD_BODY),
            "the determinism fixture must surface the datadog key"
        );
        assert!(
            a.iter()
                .any(|(id, cred, _)| id == "aws-access-key" && cred == AWS_KEY),
            "the determinism fixture must surface the aws key"
        );
        return;
    }

    let a = triples(&run(&sc, &chunks, ScanBackend::SimdCpu));
    let b = triples(&run(&sc, &chunks, ScanBackend::SimdCpu));
    assert_eq!(
        a, b,
        "SimdCpu union must yield byte-identical findings across two runs"
    );
    assert!(
        a.iter()
            .any(|(id, cred, _)| id == "datadog-api-key" && cred == DD_BODY),
        "the SIMD determinism fixture must actually surface the HS-only datadog key"
    );
    assert!(
        a.iter()
            .any(|(id, cred, _)| id == "aws-access-key" && cred == AWS_KEY),
        "the SIMD determinism fixture must actually surface the AC-literal aws key"
    );
}

// ---- the dense bitmap primitive that backs the union ------------------------

#[test]
fn trigger_bitmap_words_for_exact_div_ceil_64() {
    use keyhog_scanner::testing::trigger_bitmap_words_for_test as words_for;
    // `words_for(n) == n.div_ceil(64)` — the single source of the bitmap's word
    // width (one bit per pattern index). Pin every boundary the union relies on.
    assert_eq!(words_for(0), 0, "zero patterns need zero words");
    assert_eq!(words_for(1), 1);
    assert_eq!(words_for(63), 1);
    assert_eq!(words_for(64), 1, "exactly one full word at 64 bits");
    assert_eq!(words_for(65), 2, "one bit past a word rolls to two words");
    assert_eq!(words_for(128), 2);
    assert_eq!(words_for(129), 3);
    assert_eq!(words_for(1000), 16); // 1000.div_ceil(64) == 16
}

#[test]
fn new_trigger_bitmap_is_zeroed_and_sized() {
    use keyhog_scanner::testing::new_trigger_bitmap_for_test as new_bitmap;
    let bm = new_bitmap(200);
    assert_eq!(bm.len(), 4, "200 pattern bits -> ceil(200/64) == 4 words");
    assert!(
        bm.iter().all(|&w| w == 0),
        "a fresh trigger bitmap must be all-zero"
    );
    // Empty pattern set -> zero-length bitmap (no phantom word).
    assert_eq!(
        new_bitmap(0).len(),
        0,
        "zero patterns -> empty bitmap, no padding word"
    );
    // Single pattern still allocates a full word.
    let one = new_bitmap(1);
    assert_eq!(one.len(), 1);
    assert_eq!(one[0], 0);
}

// ---- backend-label contract (host-independent) ------------------------------

#[test]
fn scanbackend_union_backends_labels_stable_and_distinct() {
    // The two CPU union paths this file compares must remain distinct variants
    // with the exact operator-visible labels the parity harness reports.
    assert_eq!(ScanBackend::SimdCpu.label(), "simd-regex");
    assert_eq!(ScanBackend::CpuFallback.label(), "cpu-fallback");
    assert_ne!(ScanBackend::SimdCpu, ScanBackend::CpuFallback);
    assert_eq!(ScanBackend::SimdCpu, ScanBackend::SimdCpu);
}
