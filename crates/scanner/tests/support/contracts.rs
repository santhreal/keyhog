//! Shared contract-corpus harness for transform-robustness runners.
//!
//! Every transform runner (multi-secret, noise, line-length, whitespace,
//! comment-embed, …) drives the SAME contract corpus (`tests/contracts/*.toml`)
//! through a transform and asks whether each positive still surfaces. This
//! module owns the one copy of:
//!   * the contract/positive TOML schema,
//!   * loading every contract from disk,
//!   * compiling the on-disk detector set into a scanner (default + custom
//!     `ScanConfig`),
//!   * the *credential-sufficiency* partition that turns a transform test into
//!     a SOUND all-or-nothing BEHAVIOR contract instead of an accuracy RATE.
//!
//! T-01 contract (see the internal design notes): these runners assert a sound
//! PROPERTY, a credential that fires on its own bytes alone cannot be removed
//! by a byte-preserving transform, never a recall/precision/F1 *rate* over a
//! corpus. Aggregate accuracy rates live ONLY in the differential bench
//! (`benchmarks/bench`), never in `cargo test`.

use std::path::PathBuf;

use keyhog_core::ScanConfig;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use serde::Deserialize;

use super::paths::detector_dir;

#[derive(Debug, Deserialize)]
pub struct Contract {
    pub schema_version: u32,
    pub detector_id: String,
    pub service: String,
    pub severity: String,
    #[serde(default)]
    pub positive: Vec<Positive>,
}

#[derive(Debug, Deserialize)]
pub struct Positive {
    pub text: String,
    pub credential: String,
    pub reason: String,
}

/// One contract's first positive, carrying the detector id so a miss names the
/// exact offending detector instead of an anonymous count.
#[derive(Debug, Clone)]
pub struct Primary {
    pub detector_id: String,
    pub text: String,
    pub credential: String,
}

pub fn contracts_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests");
    d.push("contracts");
    d
}

/// Load every `tests/contracts/*.toml`. A read or parse failure PANICS with the
/// offending path, a malformed contract is a finding, never something to skip
/// silently (CLAUDE.md Law 10: no silent fallbacks). The old per-runner loaders
/// used `let Ok(..) else { continue }`, which silently dropped a corrupt
/// contract and shrank the corpus invisibly; this is the single fail-closed
/// loader they now all share.
pub fn load_contracts() -> Vec<Contract> {
    let dir = contracts_dir();
    let mut out = Vec::new();
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read tests/contracts dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("tests/contracts dir entry readable").path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read contract {}: {e}", path.display()));
        let contract = toml::from_str::<Contract>(&text)
            .unwrap_or_else(|e| panic!("parse contract {}: {e}", path.display()));
        out.push(contract);
    }
    assert!(
        !out.is_empty(),
        "tests/contracts/ has no *.toml, the runner has nothing to drive"
    );
    out
}

/// Compile the on-disk detector set with the scanner default config.
pub fn scanner() -> CompiledScanner {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("detectors directory loadable");
    CompiledScanner::compile(detectors).expect("scanner compile")
}

/// Compile the on-disk detector set with a caller-supplied [`ScanConfig`], used
/// by config-gated behavior contracts (e.g. the `scan_comments` toggle) that
/// must compare two scanner configurations on the same corpus.
pub fn scanner_with(config: ScanConfig) -> CompiledScanner {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("detectors directory loadable");
    CompiledScanner::compile(detectors)
        .expect("scanner compile")
        .with_config(config.into())
}

pub fn make_chunk(text: &str, source_type: &str, path: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: source_type.into(),
            path: Some(path.into()),
            ..Default::default()
        },
    }
}

/// Convenience over [`make_chunk`] for the common case: a `source_type = "test"`
/// chunk where only the text and path vary. Collapses the byte-identical
/// 2-arg `make_chunk` copies that several runners (`backend_parity_matrix`,
/// `gpu_parity`, `regression_stackblitz_backend_parity`,
/// `phase2_no_hit_branch_recall`)
/// previously each defined locally.
pub fn test_chunk(text: &str, path: &str) -> Chunk {
    make_chunk(text, "test", path)
}

/// The first positive of every contract that has one, tagged with its detector
/// id. The shared unit of work for the transform runners.
pub fn primaries(contracts: &[Contract]) -> Vec<Primary> {
    contracts
        .iter()
        .filter_map(|c| {
            c.positive.first().map(|p| Primary {
                detector_id: c.detector_id.clone(),
                text: p.text.clone(),
                credential: p.credential.clone(),
            })
        })
        .collect()
}

/// True iff some surfaced match's credential contains `credential`. Clears the
/// fragment cache first so multi-scan runners never leak state between cases.
pub fn surfaces(scanner: &CompiledScanner, chunk: &Chunk, credential: &str) -> bool {
    scanner.clear_fragment_cache();
    scanner
        .scan(chunk)
        .iter()
        .any(|m| m.credential.as_ref().contains(credential))
}

/// A credential is *credential-sufficient* when it surfaces from its OWN bytes
/// alone via a detector keyed on a distinctive PREFIX/SHAPE, no companion
/// `api`/`secret`/`key` anchor needed. Only these can be gated all-or-nothing
/// across a byte-preserving transform: the transform leaves the credential bytes
/// intact, so a sufficient credential that vanishes is a real recall bug, never
/// a fixture artifact.
///
/// A standalone hit from the pure-entropy fallback (`entropy`/`entropy-*`) does
/// NOT count. Entropy detectors fire on the Shannon entropy of the matched
/// character *run*, which is intrinsically context-dependent: the SAME credential
/// bytes that form a clean high-entropy run in isolation dilute below the entropy
/// gate once embedded in a longer run (e.g. `rediss://default:<cred>@host…`,
/// `teams api key=<cred>`), where a service-anchored detector, not entropy 
/// surfaces the secret. Gating an entropy-only credential all-or-nothing would
/// therefore assert survival of a context-dependent firing the moment any
/// transform perturbs the surrounding run (whitespace injected between an anchor
/// and the token, doubled separators that break an anchor regex), which is
/// exactly the accuracy-RATE question this module delegates to the bench. Such
/// credentials fall through to the companion/informational bucket below: still
/// recorded for visibility, never gated. (A credential with a distinctive prefix
/// that *also* happens to be high-entropy stays sufficient, its named detector
/// surfaces it here regardless of the entropy fallback.)
///
/// Companion-required positives (a bare UUID, a low-entropy generic body that
/// needs a keyword anchor nearby) likewise legitimately depend on surrounding
/// context a transform may perturb; how well they survive is an accuracy RATE
/// owned by the bench, so they are recorded for visibility but never gated.
pub fn credential_sufficient(
    scanner: &CompiledScanner,
    source_type: &str,
    primary: &Primary,
) -> bool {
    let chunk = make_chunk(&primary.credential, source_type, "sufficiency-probe.txt");
    scanner.clear_fragment_cache();
    scanner.scan(&chunk).iter().any(|m| {
        m.credential.as_ref().contains(primary.credential.as_str())
            && !keyhog_scanner::is_entropy_detector(m.detector_id.as_ref())
    })
}

/// Probe every primary once and return the parallel credential-sufficiency
/// mask. Index `i` is true iff `primaries[i].credential` fires standalone.
pub fn sufficiency_mask(
    scanner: &CompiledScanner,
    source_type: &str,
    primaries: &[Primary],
) -> Vec<bool> {
    primaries
        .iter()
        .map(|p| credential_sufficient(scanner, source_type, p))
        .collect()
}
