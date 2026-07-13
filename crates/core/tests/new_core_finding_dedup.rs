//! Standalone coverage for keyhog-core finding + dedup public API:
//! `RawMatch` (serde, Eq/Ord, Debug redaction, to_redacted, deduplication_key,
//! sanitize_floats), `MatchLocation`, `VerificationResult` serde, `RedactedFinding`,
//! `hex_encode`, and `dedup_matches` / `dedup_cross_detector` collapse behavior.
//!
//! Every assertion checks a concrete value (collapse count, primary location,
//! redacted preview, serde wire bytes, additional-location contents), never just
//! `is_ok()` / `!is_empty()`.

use keyhog_core::{
    dedup_cross_detector, dedup_matches, hex_encode, redact, CredentialHash, DedupScope,
    MatchLocation, RawMatch, Severity, VerificationResult, VerifiedFinding,
};
use std::collections::HashMap;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Construction helpers (no production code touched).
// ---------------------------------------------------------------------------

fn sha256(s: &str) -> CredentialHash {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    CredentialHash::from_bytes(h.finalize().into())
}

fn loc(file: &str, line: usize, offset: usize) -> MatchLocation {
    MatchLocation {
        source: Arc::from("filesystem"),
        file_path: Some(Arc::from(file)),
        line: Some(line),
        offset,
        commit: None,
        author: None,
        date: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn raw(
    detector_id: &str,
    detector_name: &str,
    service: &str,
    severity: Severity,
    credential: &str,
    location: MatchLocation,
    confidence: Option<f64>,
) -> RawMatch {
    RawMatch {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from(detector_name),
        service: Arc::from(service),
        severity,
        credential: keyhog_core::SensitiveString::from(credential),
        credential_hash: sha256(credential),
        companions: HashMap::new(),
        location,
        entropy: None,
        confidence,
    }
}

// ---------------------------------------------------------------------------
// RawMatch: identity, ordering, debug redaction.
// ---------------------------------------------------------------------------

#[test]
fn raw_match_deduplication_key_is_detector_and_credential() {
    let m = raw(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIAIOSFODNN7EXAMPLE",
        loc("a.env", 1, 0),
        Some(0.9),
    );
    let key = keyhog_core::testing::CoreTestApi::raw_match_deduplication_key(
        &keyhog_core::testing::TestApi,
        &m,
    );
    assert_eq!(key.detector_id, "aws-access-key");
    assert_eq!(key.credential, "AKIAIOSFODNN7EXAMPLE");
}

#[test]
fn deduped_match_serializes_companions_in_key_order() {
    let mut deduped = dedup_matches(
        vec![{
            let mut m = raw(
                "det",
                "Detector",
                "svc",
                Severity::Medium,
                "cred",
                loc("f", 1, 0),
                Some(0.7),
            );
            m.companions.insert("zeta".into(), "last".into());
            m.companions.insert("alpha".into(), "first".into());
            m.companions.insert("middle".into(), "mid".into());
            m
        }],
        &DedupScope::Credential,
    );
    let json = serde_json::to_string(&deduped.remove(0)).expect("deduped match serializes");
    let alpha = json.find(r#""alpha":"first""#).expect("alpha companion");
    let middle = json.find(r#""middle":"mid""#).expect("middle companion");
    let zeta = json.find(r#""zeta":"last""#).expect("zeta companion");

    assert!(
        alpha < middle && middle < zeta,
        "companion keys must serialize in lexical order for byte-stable reports: {json}"
    );
}

#[test]
fn raw_match_debug_redacts_credential() {
    let m = raw(
        "stripe",
        "Stripe",
        "stripe",
        Severity::Critical,
        "sk_live_supersecretkey",
        loc("a.env", 1, 0),
        Some(0.5),
    );
    let dbg = format!("{m:?}");
    assert!(
        !dbg.contains("sk_live_supersecretkey"),
        "Debug leaked plaintext: {dbg}"
    );
    assert!(dbg.contains("<redacted 22 bytes>"), "got: {dbg}");
    // The one-way hash is fine to print and is present.
    assert!(dbg.contains(&hex_encode(&m.credential_hash)));
}

#[test]
fn raw_match_eq_is_field_wise() {
    let a = raw(
        "d",
        "D",
        "s",
        Severity::Low,
        "cred",
        loc("f", 1, 0),
        Some(0.7),
    );
    let b = a.clone();
    assert_eq!(a, b);
    // A different credential makes them unequal.
    let c = raw(
        "d",
        "D",
        "s",
        Severity::Low,
        "other",
        loc("f", 1, 0),
        Some(0.7),
    );
    assert_ne!(a, c);
}

#[test]
fn raw_match_ord_higher_confidence_sorts_first() {
    let lo = raw("d", "D", "s", Severity::Low, "x", loc("f", 1, 0), Some(0.2));
    let hi = raw("d", "D", "s", Severity::Low, "y", loc("f", 1, 0), Some(0.9));
    // Ord places higher confidence first => hi < lo.
    assert!(hi < lo, "higher confidence must sort before lower");
    let mut v = vec![lo.clone(), hi.clone()];
    v.sort();
    assert_eq!(v[0].confidence, Some(0.9));
}

#[test]
fn raw_match_ord_severity_breaks_confidence_tie() {
    let crit = raw(
        "d",
        "D",
        "s",
        Severity::Critical,
        "a",
        loc("f", 1, 0),
        Some(0.5),
    );
    let info = raw(
        "d",
        "D",
        "s",
        Severity::Info,
        "b",
        loc("f", 1, 0),
        Some(0.5),
    );
    assert!(
        crit < info,
        "equal confidence => higher severity sorts first"
    );
}

#[test]
fn raw_match_ord_is_total_to_offset_then_line() {
    // The load-bearing invariant for `ScanState::push_match`: when a chunk
    // overflows `max_matches_per_chunk`, the bounded heap evicts the LOWEST by
    // this Ord. If two same-secret matches at different positions compared Equal,
    // eviction among them would fall back to insertion order (HashMap-iteration /
    // rayon-thread nondeterministic) and the kept set would flicker run-to-run
    // and depend on fallback extraction order (`fallback_order_independence`). So
    // the Ord MUST stay total down to (offset, then line); two matches identical
    // in every PRIMARY key but differing in position must NOT compare Equal.
    let same = |off, line| {
        raw(
            "d",
            "D",
            "s",
            Severity::High,
            "AKIAIOSFODNN7EXAMPLE",
            loc("f", line, off),
            Some(0.5),
        )
    };
    // Same detector+credential+confidence+severity, different OFFSET => ordered by
    // offset, never Equal.
    let a = same(0, 1);
    let b = same(64, 1);
    assert_eq!(
        a.cmp(&b),
        std::cmp::Ordering::Less,
        "lower offset must sort first (Ord total to offset)"
    );
    assert_ne!(
        a.cmp(&b),
        std::cmp::Ordering::Equal,
        "distinct offsets must never compare Equal, or heap eviction is insertion-order-dependent"
    );
    // Same offset, different LINE => the final tie-break decides; still not Equal.
    let c = same(64, 2);
    assert_eq!(
        b.cmp(&c),
        std::cmp::Ordering::Less,
        "at equal offset, lower line must sort first (final total-order key)"
    );
    assert_ne!(b.cmp(&c), std::cmp::Ordering::Equal);
}

#[test]
fn raw_match_sanitize_floats_clears_nan() {
    let mut m = raw("d", "D", "s", Severity::Low, "x", loc("f", 1, 0), None);
    m.entropy = Some(f64::NAN);
    m.confidence = Some(f64::NAN);
    let cleaned = keyhog_core::testing::CoreTestApi::raw_match_sanitize_floats(
        &keyhog_core::testing::TestApi,
        m,
    );
    assert_eq!(cleaned.entropy, None);
    assert_eq!(cleaned.confidence, None);
}

#[test]
fn raw_match_sanitize_floats_keeps_finite() {
    let mut m = raw(
        "d",
        "D",
        "s",
        Severity::Low,
        "x",
        loc("f", 1, 0),
        Some(0.42),
    );
    m.entropy = Some(3.5);
    let cleaned = keyhog_core::testing::CoreTestApi::raw_match_sanitize_floats(
        &keyhog_core::testing::TestApi,
        m,
    );
    assert_eq!(cleaned.entropy, Some(3.5));
    assert_eq!(cleaned.confidence, Some(0.42));
}

// ---------------------------------------------------------------------------
// RawMatch serde round-trip (Arc<str> + hash-hex adapters).
// ---------------------------------------------------------------------------

#[test]
fn raw_match_serde_roundtrip_preserves_fields() {
    let m = raw(
        "github-pat",
        "GitHub PAT",
        "github",
        Severity::High,
        "ghp_exampletoken1234567890",
        loc("src/main.rs", 12, 40),
        Some(0.83),
    );
    let json = serde_json::to_string(&m).unwrap();
    // Hash serializes as 64-char lowercase hex, not a byte array.
    assert!(json.contains(&hex_encode(&m.credential_hash)));
    // detector_id serializes as a bare string via serde_arc_str.
    assert!(json.contains("\"detector_id\":\"github-pat\""));
    let back: RawMatch = serde_json::from_str(&json).unwrap();
    assert_eq!(back, m);
    assert_eq!(&*back.credential, "ghp_exampletoken1234567890");
    assert_eq!(back.location.line, Some(12));
    assert_eq!(back.location.offset, 40);
}

#[test]
fn raw_match_serde_hash_hex_rejects_bad_length() {
    // A credential_hash that is not 64 hex chars must fail deserialize.
    let bad = r#"{"detector_id":"d","detector_name":"D","service":"s","severity":"low","credential":"x","credential_hash":"abcd","companions":{},"location":{"source":"fs","file_path":null,"line":null,"offset":0,"commit":null,"author":null,"date":null}}"#;
    let err = serde_json::from_str::<RawMatch>(bad);
    assert!(err.is_err(), "short hash hex must be rejected");
}

#[test]
fn match_location_serde_roundtrip_optional_fields_null() {
    let l = loc("f.txt", 3, 7);
    let json = serde_json::to_string(&l).unwrap();
    assert!(json.contains("\"file_path\":\"f.txt\""));
    assert!(json.contains("\"commit\":null"));
    let back: MatchLocation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, l);
}

// ---------------------------------------------------------------------------
// VerificationResult serde (snake_case + Error payload).
// ---------------------------------------------------------------------------

#[test]
fn verification_result_serde_unit_variants_snake_case() {
    assert_eq!(
        serde_json::to_string(&VerificationResult::Live).unwrap(),
        r#""live""#
    );
    assert_eq!(
        serde_json::to_string(&VerificationResult::Revoked).unwrap(),
        r#""revoked""#
    );
    assert_eq!(
        serde_json::to_string(&VerificationResult::Dead).unwrap(),
        r#""dead""#
    );
    assert_eq!(
        serde_json::to_string(&VerificationResult::RateLimited).unwrap(),
        r#""rate_limited""#
    );
    assert_eq!(
        serde_json::to_string(&VerificationResult::Unverifiable).unwrap(),
        r#""unverifiable""#
    );
    assert_eq!(
        serde_json::to_string(&VerificationResult::Skipped).unwrap(),
        r#""skipped""#
    );
}

#[test]
fn verification_result_serde_error_carries_payload() {
    let e = VerificationResult::Error("timeout after 5s".to_string());
    let json = serde_json::to_string(&e).unwrap();
    assert_eq!(json, r#"{"error":"timeout after 5s"}"#);
    let back: VerificationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

#[test]
fn verification_result_equality() {
    assert_eq!(VerificationResult::Live, VerificationResult::Live);
    assert_ne!(VerificationResult::Live, VerificationResult::Dead);
    assert_ne!(
        VerificationResult::Error("a".into()),
        VerificationResult::Error("b".into())
    );
}

// ---------------------------------------------------------------------------
// RawMatch::to_redacted -> RedactedFinding (disk-safe, no plaintext).
// ---------------------------------------------------------------------------

#[test]
fn to_redacted_strips_plaintext_keeps_hash_and_preview() {
    let mut m = raw(
        "slack",
        "Slack",
        "slack",
        Severity::High,
        "xoxb-1234567890-abcdefghij",
        loc("cfg.yml", 4, 8),
        Some(0.77),
    );
    m.companions
        .insert("secret".to_string(), "another_secret_value".to_string());

    let red = m.to_redacted();
    assert_eq!(&*red.detector_id, "slack");
    assert_eq!(red.severity, Severity::High);
    assert_eq!(red.credential_hash, m.credential_hash);
    // Preview is redact() of the plaintext, never the plaintext itself.
    assert_eq!(
        red.credential_redacted,
        redact("xoxb-1234567890-abcdefghij")
    );
    assert!(!red.credential_redacted.contains("1234567890"));
    // Companion values are redacted too.
    let comp = red.companions_redacted.get("secret").unwrap();
    assert_eq!(comp, &redact("another_secret_value").into_owned());
    assert!(!comp.contains("another_secret_value"));
}

#[test]
fn redacted_finding_serde_roundtrip_has_no_plaintext() {
    let m = raw(
        "gcp",
        "GCP Key",
        "gcp",
        Severity::Critical,
        "AIzaSyExamplePlaintextKeyValue00",
        loc("k.json", 1, 0),
        Some(0.95),
    );
    let red = m.to_redacted();
    let json = serde_json::to_string(&red).unwrap();
    assert!(
        !json.contains("AIzaSyExamplePlaintextKeyValue00"),
        "RedactedFinding JSON leaked plaintext: {json}"
    );
    assert!(json.contains(&hex_encode(&m.credential_hash)));
}

// ---------------------------------------------------------------------------
// dedup_matches: scope behaviors.
// ---------------------------------------------------------------------------

#[test]
fn dedup_none_keeps_every_match() {
    let matches = vec![
        raw(
            "d",
            "D",
            "s",
            Severity::Low,
            "same",
            loc("a.env", 1, 0),
            Some(0.5),
        ),
        raw(
            "d",
            "D",
            "s",
            Severity::Low,
            "same",
            loc("b.env", 2, 0),
            Some(0.5),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::None);
    assert_eq!(out.len(), 2, "None scope must not collapse anything");
    // Each carries a freshly computed hash equal to sha256(credential).
    for d in &out {
        assert_eq!(d.credential_hash, sha256("same"));
    }
}

#[test]
fn dedup_credential_collapses_same_secret_across_files() {
    let matches = vec![
        raw(
            "d",
            "D",
            "s",
            Severity::Low,
            "same",
            loc("a.env", 1, 10),
            Some(0.5),
        ),
        raw(
            "d",
            "D",
            "s",
            Severity::Low,
            "same",
            loc("b.env", 2, 20),
            Some(0.5),
        ),
        raw(
            "d",
            "D",
            "s",
            Severity::Low,
            "same",
            loc("c.env", 3, 30),
            Some(0.5),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1, "Credential scope collapses across files");
    let g = &out[0];
    // Primary is the lowest (file_path, offset) ordered location => a.env.
    assert_eq!(g.primary_location.file_path.as_deref(), Some("a.env"));
    // The other two distinct (file,line) locations are recorded.
    assert_eq!(g.additional_locations.len(), 2);
    let files: Vec<&str> = g
        .additional_locations
        .iter()
        .filter_map(|l| l.file_path.as_deref())
        .collect();
    assert!(files.contains(&"b.env"));
    assert!(files.contains(&"c.env"));
}

#[test]
fn dedup_file_keeps_one_per_file() {
    let matches = vec![
        raw(
            "d",
            "D",
            "s",
            Severity::Low,
            "same",
            loc("a.env", 1, 0),
            Some(0.5),
        ),
        raw(
            "d",
            "D",
            "s",
            Severity::Low,
            "same",
            loc("a.env", 9, 50),
            Some(0.5),
        ),
        raw(
            "d",
            "D",
            "s",
            Severity::Low,
            "same",
            loc("b.env", 1, 0),
            Some(0.5),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::File);
    // a.env collapses its two lines into one group; b.env is a second group.
    assert_eq!(out.len(), 2, "File scope: one group per file");
    let mut files: Vec<String> = out
        .iter()
        .map(|d| {
            d.primary_location
                .file_path
                .as_deref()
                .unwrap_or("")
                .to_string()
        })
        .collect();
    files.sort();
    assert_eq!(files, vec!["a.env".to_string(), "b.env".to_string()]);
}

#[test]
fn dedup_credential_same_file_line_is_not_double_counted() {
    // Two matches at the SAME (file, line) collapse with no additional location:
    // this is the synthetic-preprocessor-alias guard.
    let matches = vec![
        raw(
            "d",
            "D",
            "s",
            Severity::Low,
            "same",
            loc("a.env", 1, 0),
            Some(0.5),
        ),
        raw(
            "d",
            "D",
            "s",
            Severity::Low,
            "same",
            loc("a.env", 1, 80),
            Some(0.5),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].additional_locations.len(),
        0,
        "same (file,line) must not add an extra location"
    );
    // Primary is the smaller offset.
    assert_eq!(out[0].primary_location.offset, 0);
}

#[test]
fn dedup_credential_takes_max_confidence() {
    let matches = vec![
        raw(
            "d",
            "D",
            "s",
            Severity::Low,
            "same",
            loc("a.env", 1, 0),
            Some(0.3),
        ),
        raw(
            "d",
            "D",
            "s",
            Severity::Low,
            "same",
            loc("a.env", 2, 0),
            Some(0.91),
        ),
    ];
    let out = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].confidence,
        Some(0.91),
        "merged group keeps max confidence"
    );
}

#[test]
fn dedup_output_is_deterministic_across_input_order() {
    let mk = || {
        vec![
            raw(
                "z-det",
                "Z",
                "s",
                Severity::Low,
                "v1",
                loc("z.env", 1, 0),
                Some(0.5),
            ),
            raw(
                "a-det",
                "A",
                "s",
                Severity::Low,
                "v2",
                loc("a.env", 1, 0),
                Some(0.5),
            ),
            raw(
                "m-det",
                "M",
                "s",
                Severity::Low,
                "v3",
                loc("m.env", 1, 0),
                Some(0.5),
            ),
        ]
    };
    let mut reversed = mk();
    reversed.reverse();
    let a = dedup_matches(mk(), &DedupScope::Credential);
    let b = dedup_matches(reversed, &DedupScope::Credential);
    let ids_a: Vec<&str> = a.iter().map(|d| &*d.detector_id).collect();
    let ids_b: Vec<&str> = b.iter().map(|d| &*d.detector_id).collect();
    assert_eq!(ids_a, ids_b, "dedup output must be order-independent");
    // Sorted by key => a-det, m-det, z-det.
    assert_eq!(ids_a, vec!["a-det", "m-det", "z-det"]);
}

// ---------------------------------------------------------------------------
// dedup_cross_detector: fold alternate detectors into the winner.
// ---------------------------------------------------------------------------

#[test]
fn cross_detector_singleton_passthrough() {
    let g = dedup_matches(
        vec![raw(
            "d",
            "D",
            "s",
            Severity::Low,
            "x",
            loc("f", 1, 0),
            Some(0.5),
        )],
        &DedupScope::Credential,
    );
    let out = dedup_cross_detector(g);
    assert_eq!(
        out.len(),
        1,
        "single deduped match passes through unchanged"
    );
}

#[test]
fn cross_detector_folds_same_credential_into_winner() {
    // Two detectors fire on the SAME credential value in the SAME file. The
    // higher-confidence detector wins; the loser becomes a cross_detector
    // companion. credential_hash is identical => they group.
    let same_cred = "AIzaSyExampleSharedGoogleKey0000";
    let deduped = vec![
        {
            let mut d = dedup_matches(
                vec![raw(
                    "google-api",
                    "Google API",
                    "google",
                    Severity::High,
                    same_cred,
                    loc("k.json", 1, 0),
                    Some(0.9),
                )],
                &DedupScope::Credential,
            );
            d.remove(0)
        },
        {
            let mut d = dedup_matches(
                vec![raw(
                    "google-maps",
                    "Google Maps",
                    "google",
                    Severity::Medium,
                    same_cred,
                    loc("k.json", 1, 0),
                    Some(0.4),
                )],
                &DedupScope::Credential,
            );
            d.remove(0)
        },
    ];
    let out = dedup_cross_detector(deduped);
    assert_eq!(
        out.len(),
        1,
        "shared-credential detectors fold to one finding"
    );
    let winner = &out[0];
    assert_eq!(
        &*winner.detector_id, "google-api",
        "highest confidence wins"
    );
    // The loser is recorded as a cross_detector companion mentioning its service.
    let folded = winner
        .companions
        .values()
        .any(|v| v.contains("Google Maps"));
    assert!(
        folded,
        "loser detector must be folded as cross_detector evidence"
    );
}

#[test]
fn cross_detector_distinct_credentials_not_folded() {
    let deduped = vec![
        {
            let mut d = dedup_matches(
                vec![raw(
                    "a",
                    "A",
                    "s",
                    Severity::Low,
                    "cred-one",
                    loc("f", 1, 0),
                    Some(0.9),
                )],
                &DedupScope::Credential,
            );
            d.remove(0)
        },
        {
            let mut d = dedup_matches(
                vec![raw(
                    "b",
                    "B",
                    "s",
                    Severity::Low,
                    "cred-two",
                    loc("f", 1, 0),
                    Some(0.9),
                )],
                &DedupScope::Credential,
            );
            d.remove(0)
        },
    ];
    let out = dedup_cross_detector(deduped);
    assert_eq!(
        out.len(),
        2,
        "different credential hashes must stay separate"
    );
}

// ---------------------------------------------------------------------------
// VerifiedFinding serde (full output schema).
// ---------------------------------------------------------------------------

#[test]
fn verified_finding_serde_roundtrip() {
    let vf = VerifiedFinding {
        detector_id: Arc::from("aws-access-key"),
        detector_name: Arc::from("AWS Access Key"),
        service: Arc::from("aws"),
        severity: Severity::Critical,
        credential_redacted: redact("AKIAIOSFODNN7EXAMPLE"),
        credential_hash: sha256("AKIAIOSFODNN7EXAMPLE"),
        location: loc("creds.env", 5, 0),
        verification: VerificationResult::Live,
        metadata: {
            let mut m = HashMap::new();
            m.insert("account_id".to_string(), "123456789012".to_string());
            m
        },
        additional_locations: vec![loc("backup.env", 2, 0)],
        confidence: Some(0.99),
    };
    let json = serde_json::to_string(&vf).unwrap();
    let back: VerifiedFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(&*back.detector_id, "aws-access-key");
    assert_eq!(back.severity, Severity::Critical);
    assert_eq!(back.verification, VerificationResult::Live);
    assert_eq!(back.credential_hash, vf.credential_hash);
    assert_eq!(back.metadata.get("account_id").unwrap(), "123456789012");
    assert_eq!(back.additional_locations.len(), 1);
    assert_eq!(back.confidence, Some(0.99));
    // Redacted credential present; no plaintext.
    assert!(!json.contains("AKIAIOSFODNN7EXAMPLE"));
}

// ---------------------------------------------------------------------------
// hex_encode
// ---------------------------------------------------------------------------

#[test]
fn hex_encode_is_64_lowercase_chars() {
    let zero = hex_encode(&[0u8; 32]);
    assert_eq!(zero, "0".repeat(64));
    let mut bytes = [0u8; 32];
    bytes[0] = 0xAB;
    bytes[31] = 0xCD;
    let hex = hex_encode(&bytes);
    assert_eq!(hex.len(), 64);
    assert!(hex.starts_with("ab"));
    assert!(hex.ends_with("cd"));
    assert!(hex
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}

#[test]
fn dedup_scope_serde_roundtrip() {
    for scope in [DedupScope::None, DedupScope::File, DedupScope::Credential] {
        let json = serde_json::to_string(&scope).unwrap();
        let back: DedupScope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, scope);
    }
}
