//! Regression gate for the scan_coalesced no-hit branch fallback fix.
//!
//! Companion to fallback_wire_regression_69.rs: that test asserts the
//! wire between scan_prepared_with_triggered → scan_fallback_patterns
//! stays alive. THIS test asserts the parallel-coalesced no-hit branch
//! in scan_coalesced(chunks) ALSO routes through scan_fallback_patterns
//! when the chunk has no literal-prefix Hyperscan hits.
//!
//! Bug: kubernetes-bootstrap-token has no literal prefix; its regex
//! `\b([a-z0-9]{6}\.[a-z0-9]{16})\b` lives in self.fallback gated only
//! by keyword AC ("kubernetes", "kubeadm", "bootstrap-token", ...).
//! When a chunk contains ONLY this detector's pattern + keywords
//! (typical k8s config file with one bootstrap token), phase 1 of
//! scan_coalesced produces hits=0 - and pre-fix, the no-hit branch
//! only ran scan_generic_assignments, never scan_fallback_patterns.
//! The detector was silently dead on its own canonical input.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

fn make_chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

#[test]
fn kubernetes_bootstrap_token_fires_in_direct_scan() {
    // Sanity check - via scanner.scan(&chunk) the bootstrap detector
    // already worked pre-fix. If THIS test fails, my edits broke the
    // direct scan path; the coalesced-path tests below would be
    // diagnosing a different bug.
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let chunk = make_chunk(
        "KUBERNETES_BOOTSTRAP_TOKEN=k3m9zq.4r8w2nq3p6vt5b1z\n",
        "k8s-bootstrap.env",
    );
    let matches = scanner.scan(&chunk);
    let fired = matches
        .iter()
        .any(|m| m.detector_id.as_ref() == "kubernetes-bootstrap-token");
    assert!(
        fired,
        "direct scan must already find the bootstrap token. matches: {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref().to_string(), m.credential.to_string()))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn kubernetes_bootstrap_token_fires_in_coalesced_no_hit_branch() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Single-secret chunk: only a kubernetes bootstrap token, no other
    // detector's literal prefix (no ghp_, sk-, AKIA, etc.). The phase 1
    // literal-set walk will find ZERO hits, routing this through the
    // no-hit branch of scan_coalesced. The keyword "TOKEN" passes
    // has_generic_assignment_keyword which gates the fallback path.
    let chunk = make_chunk(
        "KUBERNETES_BOOTSTRAP_TOKEN=k3m9zq.4r8w2nq3p6vt5b1z\n",
        "k8s-bootstrap.env",
    );

    let results = scanner.scan_coalesced(std::slice::from_ref(&chunk));
    assert_eq!(results.len(), 1, "one chunk → one result vec");
    let matches = &results[0];

    let bootstrap_fired = matches
        .iter()
        .any(|m| m.detector_id.as_ref() == "kubernetes-bootstrap-token");
    assert!(
        bootstrap_fired,
        "kubernetes-bootstrap-token must fire on canonical k8s env line via scan_coalesced \
         no-hit branch (regression for prefix-less fallback detectors silently dead when \
         phase 1 produces 0 literal-prefix hits). Matches: {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref().to_string(), m.credential.to_string()))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn kubernetes_bootstrap_token_canonical_kubeadm_join_fires() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Canonical kubeadm-join command from the detector's contract.
    // No literal-prefix detector matches; only the bootstrap regex
    // can extract the token. Word "token" appears (twice) so the
    // has_generic_assignment_keyword gate passes.
    let chunk = make_chunk(
        "kubeadm join 10.0.0.1:6443 --token k3m9zq.4r8w2nq3p6vt5b1z \
         --discovery-token-ca-cert-hash sha256:abc\n",
        "kubeadm-join.sh",
    );

    let results = scanner.scan_coalesced(std::slice::from_ref(&chunk));
    let matches = &results[0];

    let bootstrap_fired = matches
        .iter()
        .any(|m| m.detector_id.as_ref() == "kubernetes-bootstrap-token");
    assert!(
        bootstrap_fired,
        "kubernetes-bootstrap-token must fire on canonical kubeadm-join command via \
         scan_coalesced no-hit branch. Matches: {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref().to_string(), m.credential.to_string()))
            .collect::<Vec<_>>(),
    );
}
