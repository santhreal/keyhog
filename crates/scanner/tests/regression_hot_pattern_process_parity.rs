#![cfg(feature = "simdsieve")]

#[path = "support/mod.rs"]
mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};
use support::paths::detector_dir;

fn scanner() -> CompiledScanner {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("detectors directory must load");
    CompiledScanner::compile(detectors).expect("scanner compile")
}

fn scanner_without(detector_id: &str) -> CompiledScanner {
    let mut detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("detectors directory must load");
    detectors.retain(|detector| detector.id != detector_id);
    CompiledScanner::compile(detectors).expect("scanner compile")
}

fn scanner_with_cap(max_matches_per_chunk: usize) -> CompiledScanner {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("detectors directory must load");
    let mut config = ScannerConfig::default();
    config.max_matches_per_chunk = max_matches_per_chunk;
    config.entropy_enabled = false;
    CompiledScanner::compile(detectors)
        .expect("scanner compile")
        .with_config(config)
}

// Recall-correct git-LFS parity: `is_git_lfs_oid_line` suppresses ONLY a real
// oid: `oid sha256:` followed by EXACTLY 64 hex digits. A valid-shaped
// `sk-proj-` key on an `oid sha256:` line is NOT a git-LFS oid, so suppressing
// it would hide a real leaked credential (a recall loss). Both the SimdCpu hot
// path and the CpuFallback regex path must report it, proof the hot path
// delegates the SAME false-positive-context decision through process_match
// (neither over-suppresses). This replaces an earlier test that asserted the
// opposite; its premise ("the regular path suppresses this") was false, because
// the oid-line check requires 64 hex and this value is not hex. See the genuine
// suppression-parity coverage in `regression_hot_path_fp_context_parity`.
#[test]
fn hot_openai_key_on_non_hex_oid_line_is_reported_on_both_backends() {
    // sk-proj- + 40 mixed-case body (valid shape, not a sequential placeholder).
    let token = "sk-proj-aB3dE6gH9jK2mN5pQ8rS1tU4vW7xY0zA3cD6eF9h";
    let chunk = Chunk {
        data: format!(
            "version https://git-lfs.github.com/spec/v1\noid sha256:{token}\nsize 1024\n"
        )
        .into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("repo/pointer.txt".into()),
            ..Default::default()
        },
    };

    for backend in [ScanBackend::SimdCpu, ScanBackend::CpuFallback] {
        let scanner = scanner();
        scanner.clear_fragment_cache();
        let matches = scanner.scan_with_backend(&chunk, backend);
        assert!(
            matches
                .iter()
                .any(|m| m.detector_id.as_ref() == "openai-api-key"
                    && m.credential.as_ref() == token),
            "a non-hex value on an `oid sha256:` line is not a git-LFS oid; the real \
             sk-proj- key must surface on {backend:?}; matches={matches:?}"
        );
    }
}

#[test]
fn hot_openai_key_does_not_emit_when_canonical_detector_is_not_loaded() {
    let token = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD";
    let chunk = Chunk {
        data: format!("OPENAI_API_KEY={token}\n").into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("repo/.env".into()),
            ..Default::default()
        },
    };

    let matches = scanner_without("openai-api-key").scan(&chunk);
    assert!(
        matches.iter().all(
            |m| !(m.detector_id.as_ref() == "openai-api-key" && m.credential.as_ref() == token)
        ),
        "simdsieve hot path must not direct-emit a canonical detector that was not compiled; matches={matches:?}"
    );
}

#[test]
fn hot_square_key_routes_to_canonical_square_detector() {
    let token = "sq0csp-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij0123456";
    let chunk = Chunk {
        data: format!("SQUARE_OAUTH_SECRET={token}\n").into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("repo/.env".into()),
            ..Default::default()
        },
    };

    let matches = scanner().scan(&chunk);
    assert!(
        matches
            .iter()
            .any(|m| m.detector_id.as_ref() == "square-access-token"
                && m.detector_name.as_ref() == "Square Access Token"
                && m.credential.as_ref() == token),
        "simdsieve square hot path must route through the canonical Square detector; matches={matches:?}"
    );
    assert!(
        matches
            .iter()
            .all(|m| m.detector_id.as_ref() != "hot-square_secret"),
        "simdsieve square hot path must not emit legacy synthetic hot-square_secret ids; matches={matches:?}"
    );
}

#[test]
fn hot_square_key_does_not_emit_when_canonical_detector_is_not_loaded() {
    let token = "sq0csp-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij0123456";
    let chunk = Chunk {
        data: format!("SQUARE_OAUTH_SECRET={token}\n").into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("repo/.env".into()),
            ..Default::default()
        },
    };

    let matches = scanner_without("square-access-token").scan(&chunk);
    assert!(
        matches
            .iter()
            .all(|m| !(m.detector_id.as_ref() == "square-access-token"
                && m.credential.as_ref() == token)
                && m.detector_id.as_ref() != "hot-square_secret"),
        "simdsieve square hot path must not direct-emit when the canonical Square detector is not compiled; matches={matches:?}"
    );
}

#[test]
fn hot_path_duplicate_identity_does_not_consume_capped_heap_slot() {
    let square = "sq0csp-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij0123456";
    let generic = "uD7kN2pQ9sX4vB8mR1tY6zC3aW5eH0jL";
    let chunk = Chunk {
        data: format!("SQUARE_OAUTH_SECRET={square}\napp_key = \"{generic}\"\n").into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("repo/.env".into()),
            ..Default::default()
        },
    };

    let matches = scanner_with_cap(2).scan(&chunk);

    assert!(
        matches
            .iter()
            .any(|m| m.detector_id.as_ref() == "square-access-token"
                && m.credential.as_ref() == square),
        "hot Square finding must survive the capped heap; matches={matches:?}"
    );
    assert!(
        matches.iter().any(|m| m.detector_id.as_ref() == "generic-secret"
            && m.credential.as_ref() == generic),
        "a hot-path duplicate identity must not consume the second capped heap slot before the generic finding can enter; matches={matches:?}"
    );
}

/// DR-322 CONSOLIDATION GUARD, the SIMD prefilter's hot-pattern prefix bytes
/// (`ghp_`, `AKIA`, `sk_live_`, …) are a re-encoding of detection signal that
/// ALSO lives verbatim in each family's `detectors/<id>.toml` pattern. The table
/// is recall-load-bearing (see the SIMD-trigger-union invariant): a prefilter
/// prefix that silently drifts from its detector pattern is a whole detector
/// class the SIMD fast path stops triggering, an invisible recall hole no
/// output test would catch. This binds every prefix to its authoritative
/// detector so the detector TOML is the source of truth for the table. It
/// ASSERTS the existing table (detector ids are already single-owned via
/// `crate::detector_ids`) (it does not change the recall-load-bearing set).
#[test]
fn hot_pattern_prefixes_are_backed_by_their_detector() {
    let dir = detector_dir();
    let bindings = keyhog_scanner::testing::simdsieve_hot_pattern_bindings();
    assert!(
        bindings.len() >= 12,
        "expected the full SIMD hot-pattern table (>=12 prefixes); got {}",
        bindings.len()
    );
    let mut drifted: Vec<String> = Vec::new();
    for (prefix, detector_id) in bindings {
        let prefix_str = std::str::from_utf8(prefix)
            .unwrap_or_else(|_| panic!("hot-pattern prefix {prefix:?} is not UTF-8"));
        let path = dir.join(format!("{detector_id}.toml"));
        let toml = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read hot-pattern detector {}: {e}", path.display()));
        if !toml.contains(prefix_str) {
            drifted.push(format!(
                "SIMD hot-pattern prefix {prefix_str:?} is absent from its detector \
                 {detector_id}.toml, the prefilter literal drifted from the detection \
                 pattern that surfaces the credential"
            ));
        }
    }
    assert!(
        drifted.is_empty(),
        "SIMD hot-pattern prefix(es) drifted from their authoritative detector \
         (detector is the source of truth):\n  - {}",
        drifted.join("\n  - ")
    );
}
