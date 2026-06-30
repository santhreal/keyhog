//! Resolution lock: a PEM private-key block must reach the operator as EXACTLY
//! ONE finding, never a `private-key` + `ssh-private-key` double-report.
//!
//! The hazard
//! ----------
//! `private-key` (service=crypto) and `ssh-private-key` (service=ssh) BOTH match
//! the same `-----BEGIN … PRIVATE KEY … END` span for every label they share
//! (RSA / EC / DSA / OPENSSH / PKCS#8 / ENCRYPTED). At the raw
//! `CompiledScanner::scan` layer both are present — but the operator path runs
//! `resolution::resolve_matches` (wired at cli postprocess.rs + scan.rs), which
//! groups by `(file, line)` and keeps only matches within `PRIORITY_EPSILON`
//! (1e-9) of the top `match_priority`. `ssh-private-key` is service-anchored
//! (`is_private_key_fallback` is ONLY the literal `private-key`), so it earns
//! `+NAMED_DETECTOR_PRIORITY (+10)` and `+KNOWN_PREFIX_SERVICE_BONUS (+5)` plus a
//! longer id, beating the `private-key` fallback by ~16 — so `private-key` is
//! dropped and ONE finding survives.
//!
//! This suite pins that contract end-to-end through the REAL resolver so a
//! future id-length / priority-weight / classification change cannot silently
//! resurrect the double-emit (a precision regression) OR drop the block entirely
//! (a recall regression). It also pins the WINNER per label: `ssh-private-key`
//! for the shared labels, `private-key` for `PGP … BLOCK` (which `ssh-private-key`
//! does not enumerate).

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::resolution::resolve_matches;
use keyhog_scanner::CompiledScanner;

/// Detector ids classified as private-key BLOCK detectors (see
/// rules/detector-classification.toml `private_key_block`).
const BLOCK_IDS: &[&str] = &["private-key", "ssh-private-key", "github-app-private-key"];

/// A closed PEM block for `label` with a body-unique `marker`.
fn pem(label: &str, marker: &str) -> String {
    format!(
        "-----BEGIN {label}-----\n\
         MIIBVAIBADANBgkqhkiG9w0BAQEFAASC{marker}Po0kjsdfPQRSTUVWX0123456789ab\n\
         cDEFghIJklMNopQRstUVwxYZ0123456789abcDEFghIJklMNopQRstUVwxYZ0123ABCD\n\
         -----END {label}-----"
    )
}

fn scan_raw(text: &str) -> Vec<RawMatch> {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("keys.pem".into()),
            ..Default::default()
        },
    };
    scanner.scan(&chunk)
}

/// Block-detector ids present in the RESOLVED (operator-visible) match set.
fn resolved_block_ids(text: &str) -> Vec<String> {
    resolve_matches(scan_raw(text))
        .into_iter()
        .filter(|m| BLOCK_IDS.contains(&m.detector_id.as_ref()))
        .map(|m| m.detector_id.as_ref().to_string())
        .collect()
}

/// Block-detector ids present in the RAW (pre-resolution) match set.
fn raw_block_ids(text: &str) -> Vec<String> {
    scan_raw(text)
        .into_iter()
        .filter(|m| BLOCK_IDS.contains(&m.detector_id.as_ref()))
        .map(|m| m.detector_id.as_ref().to_string())
        .collect()
}

// Shared labels: both private-key and ssh-private-key match → ssh wins.
const SSH_WIN_LABELS: &[(&str, &str)] = &[
    ("RSA PRIVATE KEY", "RSARES01"),
    ("EC PRIVATE KEY", "ECRES02"),
    ("DSA PRIVATE KEY", "DSARES03"),
    ("OPENSSH PRIVATE KEY", "OSSHRES4"),
    ("PRIVATE KEY", "PKCS8RE5"),
    ("ENCRYPTED PRIVATE KEY", "ENCRES06"),
];

// ===========================================================================
// Per shared label: exactly ONE block survives, and it is ssh-private-key.
// ===========================================================================

macro_rules! ssh_wins_single_survivor {
    ($name:ident, $label:expr, $marker:expr) => {
        #[test]
        fn $name() {
            let ids = resolved_block_ids(&pem($label, $marker));
            assert_eq!(
                ids.len(),
                1,
                "exactly one block detector must survive resolution for `{}`; got {:?}",
                $label,
                ids
            );
            assert_eq!(
                ids[0], "ssh-private-key",
                "ssh-private-key (service-anchored) must win the shared `{}` span",
                $label
            );
        }
    };
}

ssh_wins_single_survivor!(rsa_resolves_to_single_ssh, "RSA PRIVATE KEY", "RSAW01");
ssh_wins_single_survivor!(ec_resolves_to_single_ssh, "EC PRIVATE KEY", "ECW02");
ssh_wins_single_survivor!(dsa_resolves_to_single_ssh, "DSA PRIVATE KEY", "DSAW03");
ssh_wins_single_survivor!(
    openssh_resolves_to_single_ssh,
    "OPENSSH PRIVATE KEY",
    "OSW04"
);
ssh_wins_single_survivor!(pkcs8_resolves_to_single_ssh, "PRIVATE KEY", "PKW05");
ssh_wins_single_survivor!(
    encrypted_resolves_to_single_ssh,
    "ENCRYPTED PRIVATE KEY",
    "ENW06"
);

// ===========================================================================
// Per shared label: the private-key fallback is DROPPED (not double-reported).
// ===========================================================================

macro_rules! private_key_dropped {
    ($name:ident, $label:expr, $marker:expr) => {
        #[test]
        fn $name() {
            let ids = resolved_block_ids(&pem($label, $marker));
            assert!(
                !ids.iter().any(|id| id == "private-key"),
                "the private-key fallback must be dropped on the shared `{}` span; got {:?}",
                $label,
                ids
            );
        }
    };
}

private_key_dropped!(rsa_drops_private_key, "RSA PRIVATE KEY", "RSAD01");
private_key_dropped!(ec_drops_private_key, "EC PRIVATE KEY", "ECD02");
private_key_dropped!(dsa_drops_private_key, "DSA PRIVATE KEY", "DSAD03");
private_key_dropped!(openssh_drops_private_key, "OPENSSH PRIVATE KEY", "OSD04");
private_key_dropped!(pkcs8_drops_private_key, "PRIVATE KEY", "PKD05");
private_key_dropped!(
    encrypted_drops_private_key,
    "ENCRYPTED PRIVATE KEY",
    "END06"
);

// ===========================================================================
// PGP: ssh-private-key does NOT enumerate it, so private-key is the sole owner.
// ===========================================================================

#[test]
fn pgp_resolves_to_single_private_key() {
    let ids = resolved_block_ids(&pem("PGP PRIVATE KEY BLOCK", "PGPRES07"));
    assert_eq!(
        ids.len(),
        1,
        "exactly one block survivor for PGP; got {ids:?}"
    );
    assert_eq!(
        ids[0], "private-key",
        "PGP is owned solely by private-key (ssh-private-key omits the PGP label)"
    );
}

#[test]
fn pgp_does_not_yield_ssh_private_key() {
    let ids = resolved_block_ids(&pem("PGP PRIVATE KEY BLOCK", "PGPNO08"));
    assert!(
        !ids.iter().any(|id| id == "ssh-private-key"),
        "ssh-private-key must not fire on a PGP block; got {ids:?}"
    );
}

// ===========================================================================
// The resolver is WHAT de-conflicts: raw shows both, resolved shows one.
// ===========================================================================

#[test]
fn raw_scan_shows_both_block_detectors_for_rsa() {
    // Pre-resolution, BOTH private-key and ssh-private-key are present — proving
    // the single-survivor outcome above is the RESOLVER's doing, not a scan-time
    // accident.
    let raw = raw_block_ids(&pem("RSA PRIVATE KEY", "RAWBOTH9"));
    assert!(
        raw.iter().any(|id| id == "private-key"),
        "raw scan must include private-key; got {raw:?}"
    );
    assert!(
        raw.iter().any(|id| id == "ssh-private-key"),
        "raw scan must include ssh-private-key; got {raw:?}"
    );
}

#[test]
fn resolution_strictly_reduces_block_detectors_for_rsa() {
    let text = pem("RSA PRIVATE KEY", "REDUCE10");
    let raw = raw_block_ids(&text);
    let resolved = resolved_block_ids(&text);
    assert!(
        raw.len() > resolved.len(),
        "resolution must strictly reduce the block-detector count (raw {raw:?} -> resolved {resolved:?})"
    );
    assert_eq!(resolved.len(), 1);
}

// ===========================================================================
// Recall preserved: the surviving capture still spans the full BEGIN/END block.
// ===========================================================================

#[test]
fn surviving_rsa_capture_spans_full_block() {
    let resolved = resolve_matches(scan_raw(&pem("RSA PRIVATE KEY", "SPAN11")));
    let survivor = resolved
        .iter()
        .find(|m| BLOCK_IDS.contains(&m.detector_id.as_ref()))
        .expect("a block survivor must remain");
    let cap = survivor.credential.as_ref();
    assert!(
        cap.contains("BEGIN RSA PRIVATE KEY"),
        "capture keeps the header"
    );
    assert!(cap.contains("SPAN11"), "capture keeps the body");
    assert!(
        cap.contains("END RSA PRIVATE KEY"),
        "capture keeps the footer"
    );
}

#[test]
fn surviving_pgp_capture_spans_full_block() {
    let resolved = resolve_matches(scan_raw(&pem("PGP PRIVATE KEY BLOCK", "SPAN12")));
    let survivor = resolved
        .iter()
        .find(|m| BLOCK_IDS.contains(&m.detector_id.as_ref()))
        .expect("a block survivor must remain");
    assert!(survivor.credential.as_ref().contains("SPAN12"));
}

// ===========================================================================
// Two distinct keys on separate lines → two independent single survivors.
// ===========================================================================

#[test]
fn two_distinct_rsa_keys_resolve_to_two_ssh_survivors() {
    let text = format!(
        "{}\n\n{}",
        pem("RSA PRIVATE KEY", "TWOKEYAA"),
        pem("RSA PRIVATE KEY", "TWOKEYBB")
    );
    let ids = resolved_block_ids(&text);
    assert_eq!(ids.len(), 2, "two keys → two block survivors; got {ids:?}");
    assert!(
        ids.iter().all(|id| id == "ssh-private-key"),
        "each distinct key resolves to ssh-private-key; got {ids:?}"
    );
}

#[test]
fn single_key_yields_single_block_group_survivor() {
    // A lone key, regardless of label, never produces more than one block
    // finding after resolution (the core no-double-report invariant).
    for (label, marker) in SSH_WIN_LABELS {
        let ids = resolved_block_ids(&pem(label, marker));
        assert_eq!(
            ids.len(),
            1,
            "label `{label}` must resolve to a single block finding; got {ids:?}"
        );
    }
}
