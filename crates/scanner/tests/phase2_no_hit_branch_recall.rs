//! Regression gate for the scan_coalesced no-hit branch fallback fix.
//!
//! Companion to phase2_wire_regression_69.rs: that test asserts the
//! wire between scan_prepared_with_triggered → scan_phase2_patterns
//! stays alive. THIS test asserts the parallel-coalesced no-hit branch
//! in scan_coalesced(chunks) ALSO routes through scan_phase2_patterns
//! when the chunk has no literal-prefix Hyperscan hits.
//!
//! Bug: kubernetes-bootstrap-token has no literal prefix; its regex
//! `\b([a-z0-9]{6}\.[a-z0-9]{16})\b` lives in self.phase2_patterns gated only
//! by keyword AC ("kubernetes", "kubeadm", "bootstrap-token", ...).
//! When a chunk contains ONLY this detector's pattern + keywords
//! (typical k8s config file with one bootstrap token), phase 1 of
//! scan_coalesced produces hits=0 - and pre-fix, the no-hit branch
//! only ran scan_generic_assignments, never scan_phase2_patterns.
//! The detector was silently dead on its own canonical input.

mod support;
use support::contracts::test_chunk as make_chunk;
use support::paths::detector_dir;

use keyhog_scanner::{CompiledScanner, ScannerConfig};

const BARE_ENTROPY_SECRET: &str = "qA9zM4nB7vC2xL8pR5tY1uI6oP3sD0fG9hJ2kL7mN4bV8cX1zQ6wE5rT0yU3iO";

fn compile_scanner_with_config(config: ScannerConfig) -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    CompiledScanner::compile(detectors)
        .expect("compile")
        .with_config(config)
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
    // has_generic_assignment_keyword which gates the phase-2 path.
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
         no-hit branch (regression for prefix-less phase-2 detectors silently dead when \
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

// Asserts the `entropy-generic` detector fires, which is compiled out without
// the `entropy` feature; gate the test to the feature so `--no-default-features`
// (lean / portable-without-entropy) builds stay green instead of failing on a
// detector that cannot exist in that configuration.
#[cfg(feature = "entropy")]
#[test]
fn bare_entropy_secret_file_still_enters_coalesced_no_hit_branch() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    let scanner = compile_scanner_with_config(config);
    let chunk = make_chunk(
        &format!("VALUE={BARE_ENTROPY_SECRET}\n"),
        "config/secrets.env",
    );

    let results = scanner.scan_coalesced(std::slice::from_ref(&chunk));
    let matches = &results[0];
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref() == "entropy-generic"
            && m.credential.as_ref().contains(BARE_ENTROPY_SECRET)
    });
    assert!(
        entropy_fired,
        "bare high-entropy value in a secret/config file must still be admitted \
         through the no-hit coalesced branch; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_bare_entropy_secret_enters_coalesced_no_hit_branch_on_plain_text_path() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    let scanner = compile_scanner_with_config(config);
    let secret = "KP4QX7RM2SN5TB8VW3YZ";
    let chunk = make_chunk(secret, "notes/sufficiency-probe.txt");

    let results = scanner.scan_coalesced(std::slice::from_ref(&chunk));
    let matches = &results[0];
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(secret)
    });
    assert!(
        entropy_fired,
        "an isolated full-line high-entropy token must enter the no-hit coalesced \
         entropy path even when the plain-text path is not otherwise entropy-eligible; \
         matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn bare_entropy_source_file_obeys_default_entropy_source_gate() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    let scanner = compile_scanner_with_config(config);
    let chunk = make_chunk(
        &format!("const VALUE = \"{BARE_ENTROPY_SECRET}\";\n"),
        "src/lib.rs",
    );

    let results = scanner.scan_coalesced(std::slice::from_ref(&chunk));
    let leaked = results[0]
        .iter()
        .any(|m| m.credential.as_ref().contains(BARE_ENTROPY_SECRET));
    assert!(
        !leaked,
        "source files must not emit bare entropy findings unless entropy_source_files is enabled; matches={:?}",
        results[0]
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
