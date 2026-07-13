//! CAPABILITY TARGET-SPEC: decode-through depth + multiline reassembly.
//!
//! Two product claims keyhog makes that real leaks exercise constantly:
//!
//!   1. DECODE-THROUGH DEPTH. A secret base64'd (or hex'd) N layers deep, a
//!      k8s Secret value that is base64, embedded in a YAML that is itself
//!      base64'd into a ConfigMap, stuffed into a JSON blob, must still
//!      surface. The README claims multi-layer decode; this lane plants a
//!      credential-sufficient token under 1, 2, and 3 encode layers and asserts
//!      it is recovered at each depth. A miss at depth K is a decode-recursion
//!      gap (fails if the engine stops recursing before depth 3).
//!
//!   2. MULTILINE REASSEMBLY. A secret split across N source lines via string
//!      concatenation (`"AKIA" + "IOSF..." ` / a `\`-continued shell line / a
//!      Python implicit-concat block) must be reassembled and matched. This is
//!      the shape every config-as-code leak takes. A miss is a reassembly gap.
//!
//! Both lanes drive the REAL `CompiledScanner::scan` (decode + multiline are
//! default features) over credential-sufficient contract tokens, so a miss is a
//! pipeline-depth hole, never a fixture artifact. Expected partially RED: the
//! deeper the layer / the more fragments, the more detectors fall off. Each red
//! is the worklist; never weaken the depth target to pass (Law 9).

use crate::target_spec::{join_capped, load_canonicals, scan, sufficient_canonicals, surfaces};

use base64::{engine::general_purpose, Engine as _};

/// Encode `s` one layer with base64-standard. Real k8s/CI leaks are
/// overwhelmingly std-base64, so the depth lane uses it as the canonical layer.
fn b64(s: &str) -> String {
    general_purpose::STANDARD.encode(s.as_bytes())
}

/// Wrap an encoded payload in a tiny realistic carrier so the decoder has a
/// keyword/structural hint to recurse on (a bare base64 blob with no context is
/// legitimately ambiguous; real leaks carry a `data:` / `value:` label). The
/// carrier itself is then what gets encoded at the next layer.
fn carry(payload: &str, depth: usize) -> String {
    format!("apiVersion: v1\nkind: Secret\ndata:\n  layer{depth}: {payload}\n")
}

/// TARGET: a credential-sufficient token must be recovered through at least
/// THREE decode layers. The README's multi-layer-decode claim is only real if
/// the engine recurses that deep on a realistic carrier. Pinned as the target;
/// expected to fail at depth>=2 or 3 for detectors whose decoded body is too
/// short/ambiguous for the recursion heuristic.
const DECODE_TARGET_RECALL: f64 = 0.95;

/// Probe depths 1..=3. Depth 1 establishes the floor (single-layer decode is the
/// most-supported path); depths 2 and 3 are the product's headline claim.
#[test]
fn credential_sufficient_tokens_survive_three_decode_layers() {
    let all = load_canonicals();
    let sufficient = sufficient_canonicals(&all);
    assert!(
        sufficient.len() >= 150,
        "expected >= 150 credential-sufficient detectors, found {}",
        sufficient.len()
    );

    for depth in 1usize..=3 {
        let mut total = 0usize;
        let mut surfaced = 0usize;
        let mut failures: Vec<String> = Vec::new();

        for canon in &sufficient {
            // Build the nested payload: start from the canonical context line so
            // the innermost layer carries the token's own keyword anchor, then
            // wrap+encode `depth` times.
            let mut payload = canon.canonical_text.clone();
            for d in 0..depth {
                payload = b64(&carry(&payload, d));
            }
            let body = carry(&payload, depth);
            let matches = scan(&body, &format!("nested/depth{depth}/secret.yaml"));
            total += 1;
            if surfaces(&matches, &canon.credential) {
                surfaced += 1;
            } else {
                failures.push(canon.detector_id.clone());
            }
        }

        let ratio = surfaced as f64 / total.max(1) as f64;
        println!(
            "decode-depth {depth}: recovered {surfaced}/{total} = {ratio:.4}; {} lost",
            failures.len()
        );

        assert!(
            ratio >= DECODE_TARGET_RECALL,
            "decode-depth {depth}: only {surfaced}/{total} = {ratio:.4} of credential-sufficient \
             tokens were recovered through {depth} base64 layer(s); target {DECODE_TARGET_RECALL:.2}. \
             The engine is not recursing far enough on a realistic Secret carrier, each lost \
             detector is a decode-recursion gap:\n  - {}",
            join_capped(&failures, 50)
        );
    }
}

/// Pure depth-3 ladder on a SINGLE strong token (AWS-style), asserting the EXACT
/// recovery at each rung so a regression that silently caps recursion at depth 2
/// flips a named case. This is the concrete, non-statistical companion to the
/// corpus-wide lane above. Fails today if the engine stops before depth 3.
#[test]
fn single_token_decode_ladder_reaches_depth_three() {
    let all = load_canonicals();
    // Pick AWS access key as the canonical strong, credential-sufficient token.
    let aws = all
        .iter()
        .find(|c| c.detector_id == "aws-access-key")
        .expect("aws-access-key contract present");

    let mut payload = aws.canonical_text.clone();
    let mut depth_recovered = 0usize;
    for d in 0..3 {
        payload = b64(&carry(&payload, d));
        let body = carry(&payload, d + 1);
        let matches = scan(&body, &format!("ladder/depth{}.yaml", d + 1));
        if surfaces(&matches, &aws.credential) {
            depth_recovered = d + 1;
        }
    }

    assert_eq!(
        depth_recovered, 3,
        "AWS access key recovered only through depth {depth_recovered} of a 3-layer base64 \
         nest; the multi-layer decode claim requires depth 3. (credential: {})",
        aws.credential
    );
}

/// MULTILINE REASSEMBLY: a credential-sufficient token split across 2 lines via
/// string concatenation must be reassembled and surfaced. Splits the token at
/// its midpoint into a `"<head>" +\n  "<tail>"` concat, the canonical
/// config-as-code leak shape. Expected partially RED: reassembly is gated on the
/// fragments looking like a structural cluster, which not every shape triggers.
#[test]
fn credential_sufficient_tokens_reassemble_across_two_lines() {
    let all = load_canonicals();
    let sufficient = sufficient_canonicals(&all);

    let mut total = 0usize;
    let mut surfaced = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for canon in &sufficient {
        let cred = &canon.credential;
        // Only split tokens long enough that each half is meaningful (>= 16 so
        // each fragment is >= 8). Shorter tokens cannot be soundly split across
        // a concat without the halves being trivially short.
        if cred.len() < 16 {
            continue;
        }
        let mid = cred.len() / 2;
        if !cred.is_char_boundary(mid) {
            continue;
        }
        let (head, tail) = cred.split_at(mid);
        // Python/JS-style implicit + concat across two lines, with an anchoring
        // assignment so the reassembler has a key to attribute to.
        let body = format!("api_token = \"{head}\" +\n    \"{tail}\"\n");
        let matches = scan(&body, "src/build_token.py");
        total += 1;
        if surfaces(&matches, cred) {
            surfaced += 1;
        } else {
            failures.push(format!("{} (split `{head}` | `{tail}`)", canon.detector_id));
        }
    }

    let ratio = surfaced as f64 / total.max(1) as f64;
    println!(
        "multiline 2-line reassembly: {surfaced}/{total} = {ratio:.4}; {} lost",
        failures.len()
    );
    assert!(
        total >= 150,
        "expected >= 150 splittable credential-sufficient detectors, ran {total}"
    );
    assert!(
        ratio >= 0.90,
        "multiline reassembly recovered only {surfaced}/{total} = {ratio:.4} of split tokens; \
         target 0.90. A secret broken across two concatenated source lines slips past these \
         detectors: the config-as-code leak shape:\n  - {}",
        join_capped(&failures, 50)
    );
}

/// Three-line implicit concatenation (the wider reassembly claim): split the
/// token into THREE fragments across three lines. Strictly harder than two
/// lines; fails for detectors whose reassembler only clusters a 2-fragment join.
#[test]
fn credential_sufficient_tokens_reassemble_across_three_lines() {
    let all = load_canonicals();
    let sufficient = sufficient_canonicals(&all);

    let mut total = 0usize;
    let mut surfaced = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for canon in &sufficient {
        let cred = &canon.credential;
        if cred.len() < 24 {
            continue; // need 3 fragments of >= 8 each.
        }
        let third = cred.len() / 3;
        if !cred.is_char_boundary(third) || !cred.is_char_boundary(third * 2) {
            continue;
        }
        let a = &cred[..third];
        let b = &cred[third..third * 2];
        let c = &cred[third * 2..];
        let body = format!("token = (\n    \"{a}\"\n    \"{b}\"\n    \"{c}\"\n)\n");
        let matches = scan(&body, "src/three_part.py");
        total += 1;
        if surfaces(&matches, cred) {
            surfaced += 1;
        } else {
            failures.push(canon.detector_id.clone());
        }
    }

    let ratio = surfaced as f64 / total.max(1) as f64;
    println!(
        "multiline 3-line reassembly: {surfaced}/{total} = {ratio:.4}; {} lost",
        failures.len()
    );
    assert!(
        total >= 100,
        "expected >= 100 tri-splittable detectors, ran {total}"
    );
    assert!(
        ratio >= 0.85,
        "three-line reassembly recovered only {surfaced}/{total} = {ratio:.4}; target 0.85. \
         A token broken across THREE concatenated lines is not reassembled for these detectors:\n  - {}",
        join_capped(&failures, 50)
    );
}
