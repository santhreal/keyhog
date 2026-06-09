//! RECALL/SOUNDNESS TRIPWIRE for the SimdCpu trigger path.
//!
//! ## History — PERF-simd_scan-1 was REFUTED, do not re-derive it
//! This file was originally a *perf* tripwire asserting the SimdCpu trigger pass
//! should be no slower than CpuFallback, on the theory that running the scalar
//! Aho-Corasick sweep AND the Hyperscan scan was redundant ("AC ∪ HS = AC, so HS
//! is pure overhead"). **That premise is false.** Acting on it — dropping the HS
//! union so SimdCpu ran the AC literal set alone — silently regressed
//! `contracts_runner` for ~30 detectors and, on a full sweep of every contract
//! positive, **49 detectors** were found by SimdCpu (AC ∪ HS) but MISSED by
//! CpuFallback (AC alone): twilio-auth-token, datadog-api-key,
//! africastalking-api-key, sentry-auth-token, and 45 more.
//!
//! The two prefilters are INCOMPARABLE, not nested:
//!   * AC \ HS ≠ ∅ — Hyperscan compiles some context-anchored bounded-repeat
//!     patterns (line / paloalto / tower / keystonejs / snowflake / bandwidth)
//!     without erroring yet never reports a match, so the AC literal seed is what
//!     fires them. (This is all the original soundness comment claimed.)
//!   * HS \ AC ≠ ∅ — for detectors whose extracted literal is NOT a *required*
//!     substring of every match (no fixed prefix; the credential is bare
//!     32-hex / alnum gated by a nearby keyword), the AC sweep never marks the
//!     pattern, but Hyperscan's full-regex scan does. These are the 49 above.
//!
//! Because the sets are incomparable, the union in
//! `collect_triggered_patterns_simd` (backend_triggered.rs) is **load-bearing
//! for recall** — neither half alone is a sound prefilter. SimdCpu therefore
//! legitimately does MORE work than CpuFallback (it runs both), and on a no-hit
//! chunk it is ~1% SLOWER *by design*: that ~1% buys the 49 detectors. A speed
//! assertion that SimdCpu ≤ CpuFallback would be asserting a recall regression,
//! so this file no longer makes one.
//!
//! ## What this tripwire pins instead
//! The durable, honest contract is the recall invariant the refuted "fix"
//! violated, expressed at the BACKEND-DIFFERENTIAL level so it is the exact
//! guard that fails if anyone drops the union again:
//!   1. **Load-bearing union** — for known HS\AC detectors, `SimdCpu` finds the
//!      credential and `CpuFallback` (AC-only) does NOT. If the union is removed,
//!      `SimdCpu` stops finding them and this fails immediately.
//!   2. **Superset safety** — on every chunk, `SimdCpu`'s finding set is a
//!      SUPERSET of `CpuFallback`'s: the SIMD path must never DROP a detection
//!      the scalar path makes. (Corpus-wide parity on literal-anchored fixtures
//!      lives in backend_parity_matrix.rs; this adds the context-anchored axis
//!      that corpus lacks — which is why the regression slipped past it.)
//!
//! The genuine remaining perf opportunity (run Hyperscan as the primary scan and
//! a REDUCED AC over only the ~6 HS-unsound bounded-repeat patterns, instead of
//! the full AC sweep) requires statically partitioning the pattern set by
//! HS-soundness and is tracked as a backlog rewrite — NOT a removable union.
//!
//! When the `simd` feature is compiled out (`--no-default-features` without
//! `simd`) there is no Hyperscan prefilter, `SimdCpu` falls back to the AC
//! collector, and the union/HS\AC distinction does not exist — the
//! differential assertions are skipped (documented at each site).

use keyhog_core::{load_detectors, Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn detectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detectors")
}

fn make_chunk(data: &str) -> Chunk {
    Chunk {
        data: data.to_string().into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "perf-tripwire".into(),
            path: Some("perf_simd_scan.txt".into()),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: None,
            ..Default::default()
        },
    }
}

fn finding_keys(ms: &[RawMatch]) -> BTreeSet<(String, String)> {
    ms.iter()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}

/// Verified HS\AC fixtures: each is a contract positive (copied from
/// `crates/scanner/tests/contracts/<id>.toml`) for a detector whose credential
/// has NO fixed literal prefix, so the AC literal sweep cannot trigger it — only
/// Hyperscan's full-regex scan does. Empirically, all three are found by SimdCpu
/// and missed by CpuFallback on the current detector set. The invariant the test
/// asserts ("the union is load-bearing") only needs ONE of these to remain
/// HS\AC, so it stays green even if a detector later gains a usable literal.
const HS_MINUS_AC_FIXTURES: &[(&str, &str, &str)] = &[
    (
        "datadog-api-key",
        "DD_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    ),
    (
        "twilio-auth-token",
        "TWILIO_ACCOUNT_SID=AC7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\n\
         TWILIO_AUTH_TOKEN=4c9a8f6e3b7d1a2c5e8f0b9d6a3c4e1f",
        "4c9a8f6e3b7d1a2c5e8f0b9d6a3c4e1f",
    ),
    (
        "africastalking-api-key",
        "africastalking_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    ),
];

/// The SimdCpu union must catch context-anchored detectors that the AC literal
/// set alone misses. This is the EXACT regression guard: dropping the Hyperscan
/// union (so SimdCpu = AC only) makes `simd_found` go false for these fixtures
/// and trips this test before it can reach `contracts_runner`.
#[test]
fn simd_union_is_load_bearing_for_recall() {
    if !cfg!(feature = "simd") {
        eprintln!(
            "perf_simd_scan: `simd` feature not compiled — no Hyperscan prefilter, \
             SimdCpu == CpuFallback (AC only), so the HS\\AC differential does not \
             exist; skipping the load-bearing assertion."
        );
        return;
    }

    let detectors = load_detectors(&detectors_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let mut union_load_bearing = 0usize;
    for &(detector_id, text, credential) in HS_MINUS_AC_FIXTURES {
        let chunk = make_chunk(text);
        let simd = scanner.scan_with_backend(&chunk, ScanBackend::SimdCpu);
        let cpu = scanner.scan_with_backend(&chunk, ScanBackend::CpuFallback);

        let simd_found = simd
            .iter()
            .any(|m| m.detector_id.as_ref() == detector_id && m.credential.as_ref() == credential);
        let cpu_found = cpu
            .iter()
            .any(|m| m.detector_id.as_ref() == detector_id && m.credential.as_ref() == credential);

        // Recall on the DEFAULT CI backend (SimdCpu) is non-negotiable: every
        // one of these credentials must be found by the SIMD path.
        assert!(
            simd_found,
            "SimdCpu (AC ∪ Hyperscan) FAILED to find the `{detector_id}` credential \
             `{credential}`. The Hyperscan union in collect_triggered_patterns_simd \
             (backend_triggered.rs) is the only thing that triggers this no-literal \
             detector — if it was dropped, this is the recall regression PERF-simd_scan-1 \
             caused (49 detectors lost). Restore the AC ∪ HS union."
        );

        // Superset safety per fixture: SimdCpu must never drop what CpuFallback
        // found. (CpuFallback ⊆ SimdCpu.)
        assert!(
            !cpu_found || simd_found,
            "SimdCpu dropped a `{detector_id}` finding that CpuFallback made — the SIMD \
             path must be a superset of the scalar path."
        );

        if simd_found && !cpu_found {
            union_load_bearing += 1;
            eprintln!(
                "perf_simd_scan: union load-bearing for `{detector_id}` \
                 (SimdCpu finds it, CpuFallback/AC-only misses it)."
            );
        }
    }

    assert!(
        union_load_bearing >= 1,
        "NONE of the {} known HS\\AC fixtures was missed by CpuFallback — either every \
         one gained a usable AC literal (update the fixtures) or the CpuFallback path \
         silently started using Hyperscan. The union must remain provably load-bearing.",
        HS_MINUS_AC_FIXTURES.len()
    );
}

/// On every chunk, the SimdCpu finding set must be a SUPERSET of the CpuFallback
/// finding set: the vectorized path may find MORE (the HS\AC detectors) but must
/// never find LESS than the scalar path. Checked per-fixture (each in its OWN
/// chunk — the contract fixtures share credential substrings, e.g. twilio's
/// account_sid contains datadog's hex, so a combined chunk would cross-pollute
/// the differential) plus a literal-anchored control proving the union does not
/// regress the AC fast path. The strict "SimdCpu finds MORE" direction is proven
/// per-fixture by `simd_union_is_load_bearing_for_recall`; this guards the other
/// direction — that SimdCpu never DROPS a scalar finding.
#[test]
fn simd_findings_are_a_superset_of_scalar() {
    if !cfg!(feature = "simd") {
        eprintln!(
            "perf_simd_scan: `simd` feature not compiled — SimdCpu == CpuFallback; \
             superset assertion is vacuous, skipping."
        );
        return;
    }

    let detectors = load_detectors(&detectors_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    // Literal-anchored control: a fixed-prefix secret (AKIA) is in the AC literal
    // set, so BOTH backends must find it. This proves the Hyperscan union did not
    // regress the scalar AC fast path while widening the candidate set.
    let control = make_chunk("const AWS_KEY = \"AKIAQYLPMN5HFIQR7XYA\";\n");
    let control_simd = finding_keys(&scanner.scan_with_backend(&control, ScanBackend::SimdCpu));
    let control_cpu = finding_keys(&scanner.scan_with_backend(&control, ScanBackend::CpuFallback));
    assert!(
        !control_cpu.is_empty() && control_cpu.is_subset(&control_simd),
        "literal-anchored control regressed: CpuFallback={control_cpu:?} must be non-empty \
         and a subset of SimdCpu={control_simd:?} — the union must not drop the AC fast path."
    );

    // Per-fixture superset: SimdCpu must drop NOTHING the scalar path finds, on
    // each fixture scanned in isolation (no shared-substring cross-pollution).
    for &(detector_id, text, _cred) in HS_MINUS_AC_FIXTURES {
        let chunk = make_chunk(text);
        let simd = finding_keys(&scanner.scan_with_backend(&chunk, ScanBackend::SimdCpu));
        let cpu = finding_keys(&scanner.scan_with_backend(&chunk, ScanBackend::CpuFallback));
        let dropped: Vec<_> = cpu.difference(&simd).collect();
        assert!(
            dropped.is_empty(),
            "on the `{detector_id}` fixture, SimdCpu dropped findings the scalar CpuFallback \
             path made (CpuFallback ⊄ SimdCpu): {dropped:?}. The SIMD path must be a recall \
             superset of the scalar path."
        );
    }

    eprintln!(
        "perf_simd_scan: superset OK — control (AKIA) found by both backends; SimdCpu drops \
         no scalar finding on any HS\\AC fixture. (Strictness proven by the load-bearing test.)"
    );
}
