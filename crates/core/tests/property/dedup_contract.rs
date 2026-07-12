//! Property tier for `keyhog_core::dedup_matches` — report-scope finding
//! deduplication. Fixed-vector coverage exists (`new_core_finding_dedup`,
//! `dedup_decoder_alias`, `gap/redaction_dedup`); this file pins the
//! output-correctness invariants over arbitrary match sets (proptest, 10k
//! cases), because dedup sits between detection and the report and a bug here
//! either DROPS a real secret (recall loss — the whole reason
//! `DEDUP_LOST_SINGLETON` exists) or FABRICATES/splits a finding:
//!
//!   * `DedupScope::None` is a 1:1 passthrough (count + credential set preserved);
//!   * `DedupScope::Credential` collapses to exactly one finding per distinct
//!     `(detector_id, credential)` — no key from the input is ever lost, and no
//!     key not in the input is ever fabricated (the recall-safety contract);
//!   * output is deterministic w.r.t. INPUT ORDER (dedup sorts internally), so a
//!     permutation of the same matches yields byte-identical grouping — the
//!     property SARIF fingerprints / baselines / CI diffs depend on;
//!   * a group's surviving confidence is the MAX over the whole group (the
//!     highest-confidence-winner rule, folded on every duplicate);
//!   * `File` scope can only SPLIT relative to `Credential` scope, never merge.
//!
//! Uses only the STABLE PUBLIC API (`dedup_matches`, `RawMatch`, `DedupScope`,
//! `MatchLocation`, `Severity`, `SensitiveString`, `CredentialHash`) + the same
//! local `RawMatch` builders as `new_core_finding_dedup.rs`.

use keyhog_core::{
    dedup_matches, CredentialHash, DedupScope, MatchLocation, RawMatch, SensitiveString, Severity,
};
use proptest::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

fn sha256(s: &str) -> CredentialHash {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    CredentialHash::from_bytes(h.finalize().into())
}

/// One generated match, drawn from SMALL universes so keys COLLIDE and dedup
/// actually has work to do: `(detector_idx, credential_idx, file_idx, line,
/// offset, confidence)`.
type MatchSpec = (u8, u8, u8, u32, u32, f64);

fn build(specs: &[MatchSpec]) -> Vec<RawMatch> {
    specs
        .iter()
        .map(|&(det, cred, file, line, offset, conf)| {
            let credential = format!("cred-{cred}");
            RawMatch {
                detector_id: Arc::from(format!("det-{det}").as_str()),
                detector_name: Arc::from("Detector"),
                service: Arc::from("svc"),
                severity: Severity::High,
                credential: SensitiveString::from(credential.as_str()),
                credential_hash: sha256(&credential),
                companions: HashMap::new(),
                location: MatchLocation {
                    source: Arc::from("filesystem"),
                    file_path: Some(Arc::from(format!("f{file}.txt").as_str())),
                    line: Some(line as usize),
                    offset: offset as usize,
                    commit: None,
                    author: None,
                    date: None,
                },
                entropy: None,
                confidence: Some(conf),
            }
        })
        .collect()
}

/// `(detector_id, credential)` key of a spec, as owned strings — the identity
/// `DedupScope::Credential` collapses on.
fn spec_key(&(det, cred, ..): &MatchSpec) -> (String, String) {
    (format!("det-{det}"), format!("cred-{cred}"))
}

/// `(detector_id, credential)` keys of a dedup result, in output order. A macro
/// (not a fn) because `dedup_matches` returns `Vec<DedupedMatch>` and
/// `DedupedMatch` lives in a private module (`mod dedup`) — its type is
/// reachable through the value (fields, methods) but cannot be NAMED in a fn
/// signature, exactly as `new_core_finding_dedup.rs` uses it inference-only.
macro_rules! out_keys {
    ($out:expr) => {
        $out.iter()
            .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
            .collect::<Vec<(String, String)>>()
    };
}

fn spec_strat() -> impl Strategy<Value = MatchSpec> {
    (0u8..3, 0u8..4, 0u8..2, 0u32..6, 0u32..200, 0.0f64..1.0)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// `None` scope is a faithful 1:1 passthrough: one output per input, and the
    /// multiset of `(detector_id, credential)` is preserved exactly (nothing
    /// dropped, nothing merged).
    #[test]
    fn prop_none_scope_is_lossless_passthrough(specs in prop::collection::vec(spec_strat(), 0..24)) {
        let out = dedup_matches(build(&specs), &DedupScope::None);
        prop_assert_eq!(out.len(), specs.len());
        let mut in_keys: Vec<_> = specs.iter().map(spec_key).collect();
        let mut got = out_keys!(out);
        in_keys.sort();
        got.sort();
        prop_assert_eq!(got, in_keys);
    }

    /// `Credential` scope: exactly one finding per distinct `(detector_id,
    /// credential)`, and the output key set EQUALS the input key set — no key
    /// lost (recall) and none fabricated. Output keys are all distinct.
    #[test]
    fn prop_credential_scope_collapses_without_loss(
        specs in prop::collection::vec(spec_strat(), 0..24)
    ) {
        let expected: HashSet<(String, String)> = specs.iter().map(spec_key).collect();
        let out = dedup_matches(build(&specs), &DedupScope::Credential);
        let got: HashSet<(String, String)> = out_keys!(out).into_iter().collect();
        prop_assert_eq!(&got, &expected); // no loss, no fabrication
        prop_assert_eq!(out.len(), expected.len()); // one per distinct key
        // Output keys are unique (a HashSet of them has the same length).
        prop_assert_eq!(out_keys!(out).len(), got.len());
    }

    /// Output is INPUT-ORDER-INDEPENDENT: permuting the matches yields the exact
    /// same ordered grouping (dedup sorts by key). Checked against the reversed
    /// and a rotated input.
    #[test]
    fn prop_credential_scope_is_order_independent(
        specs in prop::collection::vec(spec_strat(), 0..24)
    ) {
        let base = out_keys!(dedup_matches(build(&specs), &DedupScope::Credential));

        let mut rev = specs.clone();
        rev.reverse();
        prop_assert_eq!(
            out_keys!(dedup_matches(build(&rev), &DedupScope::Credential)),
            base.clone()
        );

        if !specs.is_empty() {
            let mut rot = specs.clone();
            rot.rotate_left(1);
            prop_assert_eq!(out_keys!(dedup_matches(build(&rot), &DedupScope::Credential)), base);
        }
    }

    /// Highest-confidence-winner: a surviving group's confidence is the MAX
    /// confidence over every input match with that key (folded on each merge).
    #[test]
    fn prop_credential_scope_keeps_max_confidence(
        specs in prop::collection::vec(spec_strat(), 1..24)
    ) {
        let mut expected_max: HashMap<(String, String), f64> = HashMap::new();
        for s in &specs {
            let e = expected_max.entry(spec_key(s)).or_insert(f64::MIN);
            *e = e.max(s.5);
        }
        let out = dedup_matches(build(&specs), &DedupScope::Credential);
        for m in &out {
            let key = (m.detector_id.to_string(), m.credential.to_string());
            let want = expected_max[&key];
            prop_assert_eq!(
                m.confidence,
                Some(want),
                "group {:?} confidence should be the group max {}",
                key,
                want
            );
        }
    }

    /// `File` scope partitions by `(detector_id, credential, file)`, so it can
    /// only ever produce MORE-OR-EQUAL groups than `Credential` scope — never
    /// fewer (a file split cannot merge two credential groups).
    #[test]
    fn prop_file_scope_never_merges_below_credential_scope(
        specs in prop::collection::vec(spec_strat(), 0..24)
    ) {
        let cred = dedup_matches(build(&specs), &DedupScope::Credential).len();
        let file = dedup_matches(build(&specs), &DedupScope::File).len();
        prop_assert!(
            file >= cred,
            "File scope ({file}) produced fewer groups than Credential scope ({cred})"
        );
        // With every match forced into a single file, the two scopes coincide.
        let one_file: Vec<MatchSpec> =
            specs.iter().map(|&(d, c, _, l, o, cf)| (d, c, 0u8, l, o, cf)).collect();
        let cred1 = dedup_matches(build(&one_file), &DedupScope::Credential).len();
        let file1 = dedup_matches(build(&one_file), &DedupScope::File).len();
        prop_assert_eq!(file1, cred1);
    }
}
