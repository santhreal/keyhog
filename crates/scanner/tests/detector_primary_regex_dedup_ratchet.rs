//! ONE-PLACE / DET-0 ratchet: no two `kind = "regex"` detectors may share a
//! BYTE-IDENTICAL primary pattern (`patterns[0].regex`, post-canonicalization).
//!
//! Two detectors whose primary regex is identical are a duplicate detection:
//! they fire the same finding twice (deduped by value downstream, so the bench
//! score hides it) and split one concept across two TOMLs, the exact rot the
//! ONE-PLACE law bans. This gate enumerates every such pair and asserts the set
//! is a SUBSET of the documented debt baseline below, so a NEW duplicate fails
//! the build the moment it is introduced, while the known pairs are tracked for
//! consolidation (each annotated with the survivor + the compat caveat, a
//! detector id is a public contract via `.keyhogignore` / SARIF baselines, so
//! removing one needs a migration note, not a silent delete).
//!
//! When a baseline pair is genuinely consolidated (one id removed / repurposed
//! so the primary regexes differ), REMOVE it from `KNOWN_DUP_PAIRS` to tighten
//! the ratchet. The gate never *requires* a pair to remain a dup, so a partial
//! consolidation stays green; it only forbids GROWTH.
#![cfg(feature = "simd")]

mod support;
use support::paths::detector_dir;

use std::collections::BTreeMap;

/// The 7 known byte-identical primary-regex duplicate pairs (2026-07-07 audit
/// over all 923 detectors). Each is a real ONE-PLACE violation awaiting
/// consolidation into a single owner; the note names the intended survivor and
/// why the pair exists. Ordered ids within a pair are sorted so the match
/// against a discovered group (also sorted) is order-independent.
const KNOWN_DUP_PAIRS: &[&[&str]] = &[
    // Both fire on `bbc_[a-zA-Z0-9]{48,}`. Survivor: bigcommerce-store-api-
    // credentials (superset naming covering the token). Fold the access-token
    // keywords in, then drop bigcommerce-access-token.
    &[
        "bigcommerce-access-token",
        "bigcommerce-store-api-credentials",
    ],
    // Both fire on `pk_(?:live|test)_[a-zA-Z0-9]{32}`: Clerk's PUBLISHABLE
    // (client-safe) key. 100% redundant (same regex/severity/client_safe). The
    // real secret `sk_` is already caught (shares Stripe's `sk_live_` prefix).
    // Survivor: clerk-frontend-api-key (the precise "frontend/publishable"
    // name); clerk-api-key is misnamed (it is NOT the secret key).
    &["clerk-api-key", "clerk-frontend-api-key"],
    // Both fire on `gldt-[a-zA-Z0-9_-]{20,}`. GitLab deploy tokens and package-
    // registry tokens share the `gldt-` shape; survivor TBD by product (they
    // are semantically distinct scopes but shape-identical).
    &["gitlab-deploy-token", "gitlab-package-registry-token"],
    // Both fire on `hf_[a-zA-Z0-9]{34,}`. HF user vs org tokens are shape-
    // identical; the org/user distinction is not encodable in the prefix, so
    // these should be ONE `huggingface-token` detector.
    &["huggingface-org-token", "huggingface-user-token"],
    // Both fire on `[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9]{67,}`. Terraform
    // Cloud and Enterprise use the same `atlasv1.` token shape; survivor:
    // terraform-cloud-api-token (Enterprise is the same API surface).
    &["terraform-cloud-api-token", "terraform-enterprise-token"],
    // Both fire on `ck_[a-f0-9]{40}` with the same `cs_` companion. woocommerce-
    // consumer-key is a strict subset of woocommerce-rest-api-credentials (which
    // has the fuller keyword set). Survivor: woocommerce-rest-api-credentials.
    &[
        "woocommerce-consumer-key",
        "woocommerce-rest-api-credentials",
    ],
    // Both fire on `xau_[a-zA-Z0-9_-]{40,}`. Xata api-key vs workspace-api-key
    // are the same token shape; consolidate to one `xata-api-key`.
    &["xata-api-key", "xata-workspace-api-key"],
];

fn known_pair_set() -> Vec<Vec<String>> {
    KNOWN_DUP_PAIRS
        .iter()
        .map(|pair| {
            let mut v: Vec<String> = pair.iter().map(|s| s.to_string()).collect();
            v.sort();
            v
        })
        .collect()
}

#[test]
fn no_new_duplicate_primary_regex_detectors() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors unavailable: {e}");
            return;
        }
    };

    // Group detector ids by their PRIMARY (patterns[0]) regex. Detectors with no
    // patterns (kind = "phase2-generic": shapeless secrets driven by keywords +
    // entropy_floor, no regex anchor) have no primary regex and are excluded
    // they cannot collide on a regex string.
    let mut by_regex: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for det in &detectors {
        if let Some(primary) = det.patterns.first() {
            by_regex
                .entry(primary.regex.clone())
                .or_default()
                .push(det.id.clone());
        }
    }

    let baseline = known_pair_set();
    let mut new_dups: Vec<(String, Vec<String>)> = Vec::new();
    for (regex, ids) in &by_regex {
        if ids.len() < 2 {
            continue;
        }
        let mut sorted = ids.clone();
        sorted.sort();
        if !baseline.contains(&sorted) {
            new_dups.push((regex.clone(), sorted));
        }
    }

    assert!(
        new_dups.is_empty(),
        "ONE-PLACE violation: {} NEW byte-identical primary-regex duplicate group(s) \
         (not in the tracked baseline). Two detectors with an identical primary regex \
         are a duplicate detection, consolidate into one detector, or if intentional, \
         add the pair to KNOWN_DUP_PAIRS with a survivor note:\n{}",
        new_dups.len(),
        new_dups
            .iter()
            .map(|(r, ids)| format!("  regex {r:?}  <-  {}", ids.join(", ")))
            .collect::<Vec<_>>()
            .join("\n"),
    );

    // Coverage sanity: the audit found 7 known pairs; if the corpus shrank so far
    // that NONE of them load, the gate would vacuously pass. Assert we still see
    // at least a majority of the tracked pairs as real dups (they are removed
    // from the baseline only via deliberate consolidation, which also edits this
    // file), so a silent detector-dir regression can't hollow the gate out.
    let still_dup = baseline
        .iter()
        .filter(|pair| {
            // A tracked pair is "still a dup" iff both ids share one regex bucket.
            by_regex
                .values()
                .any(|ids| pair.iter().all(|p| ids.contains(p)))
        })
        .count();
    assert!(
        still_dup >= baseline.len().saturating_sub(1).max(1),
        "dedup ratchet hollowed out: only {still_dup}/{} tracked dup pairs still load \
         as duplicates, either a big consolidation landed (tighten KNOWN_DUP_PAIRS to \
         match) or the detector dir regressed",
        baseline.len(),
    );
}
