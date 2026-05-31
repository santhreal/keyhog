//! Round 1 FP-killer regression contract: the Caesar / ROT-N decoder
//! must skip chunks whose lines already carry a `scheme://user:pass@host`
//! URL. The plaintext URL itself is the credential; the 25-shift
//! fan-out cannot reveal new information, and (worse) its high-confidence
//! decoded chunk previously out-resolved the real connection-string
//! detector on per-line grouping.
//!
//! Investigator finding (database-connection-string cause #5): the 2
//! mongo-log FNs (mirror-pos-0002325.log, -0002576.log) and the 1
//! postgres-env FN (mirror-pos-0002961.env) trace to caesar emitting a
//! synthesized generic-password finding at confidence 1.0 on the
//! ROT-13 of the URL password body. The scoring harness keys by
//! (file_path, line) and the caesar decoded finding outranked the real
//! URL detector. The fix (d60fa9d6, decode/caesar.rs) gates the
//! decoder off entirely for chunks whose lines contain `scheme://u:p@h`.
//!
//! The `line_has_credential_url` helper is `pub(crate)`, so we cannot
//! call it directly from this integration crate. Instead exercise the
//! contract end-to-end: a chunk carrying a postgres connection string
//! must surface the named postgres / generic connection-string detector
//! AND must NOT surface a generic-password / decoded-source finding
//! whose source / id includes "caesar" or "rot".
//!
//! Adversarial style: paired truth case (named URL detector must
//! surface) + negative twin (no caesar-derived finding allowed). CVE
//! replay shape: a synthesized but realistic postgres URL matching the
//! exact format of the SecretBench mirror fixtures.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScannerConfig};
use std::path::PathBuf;
use std::sync::OnceLock;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

fn shared_scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
        let mut cfg = ScannerConfig::default();
        cfg.min_confidence = 0.0;
        CompiledScanner::compile(detectors)
            .expect("compile")
            .with_config(cfg)
    })
}

fn scan_path(body: &str, path: &str) -> Vec<keyhog_core::RawMatch> {
    let chunk = Chunk {
        data: body.to_string().into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    shared_scanner().scan(&chunk)
}

/// Positive truth: a postgres connection string surfaces under a
/// connection-string-aware detector ID. Either the named
/// `postgresql-connection-string` or `postgres-connection-string`
/// detector or a generic-password / generic-secret carrying the URL
/// body is acceptable as long as the surfaced credential bytes contain
/// the password substring `lSVjMf3y`.
#[test]
fn postgres_connection_string_surfaces_on_url_line() {
    let body =
        "DATABASE_URL=postgres://prhvtsuw:lSVjMf3yTpDkVI0C@dqudscouyssx.example.org:5432/test\n";
    let matches = scan_path(body, "/repo/.env");

    let surfaced = matches.iter().any(|m| {
        let cred = m.credential.as_ref();
        cred.contains("lSVjMf3y") || cred.contains("postgres://prhvtsuw")
    });
    assert!(
        surfaced,
        "postgres URL must surface in some finding. ALL findings: {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

/// Adversarial negative twin: no Caesar / ROT-N derived finding may
/// fire on the postgres URL line. The detector_id MUST NOT contain
/// "caesar" or "rot". Before the fix, the 25-shift fan-out emitted a
/// generic-password finding whose source / id carried the "caesar"
/// tag (and which won the per-line resolution group over the real URL
/// detector).
#[test]
fn caesar_decoder_does_not_fire_on_credential_url_line() {
    let body = "log: connecting mongodb+srv://prhvtsuw:TpDkVI0CIr0lSVjMf3y@dqudscouyssx.example.org/test?retryWrites=true status=ok\n";
    let matches = scan_path(body, "/repo/logs/mongo.log");

    let caesar_offenders: Vec<_> = matches
        .iter()
        .filter(|m| {
            let id_lower = m.detector_id.as_ref().to_ascii_lowercase();
            id_lower.contains("caesar") || id_lower.contains("rot")
        })
        .collect();
    assert!(
        caesar_offenders.is_empty(),
        "no caesar/rot-tagged finding may fire on a line containing a \
         credential URL. offenders: {:?}",
        caesar_offenders
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );

    // Also assert via the synthesized-source companion: caesar's emit
    // path carries the "decoded" / "caesar" suffix in the detector_id
    // when the synthesized chunk surfaces a finding. None of those
    // suffix patterns must appear here.
    for m in &matches {
        let id = m.detector_id.as_ref();
        assert!(
            !id.ends_with(":caesar") && !id.ends_with(":rot13") && !id.contains("decoded-caesar"),
            "caesar suffix on detector_id forbidden when URL is on the \
             same line: id={} credential={:?}",
            id,
            m.credential.as_ref()
        );
    }
}

/// Defensive coverage: a chunk WITHOUT a credentialled URL must still
/// admit the wider scanner pipeline. Proves the caesar gate is
/// per-chunk (skip only when at least one line carries a credentialled
/// URL pattern), not a blanket "no findings on any non-URL chunk".
///
/// Plant a synthetic AKIA with a body that is NOT the public
/// AWS-docs-example placeholder (so the placeholder suppression does
/// not silently slam the finding). The AKIA must surface; this
/// confirms the caesar gate is not over-broad.
#[test]
fn caesar_gate_does_not_block_chunks_without_credential_urls() {
    // Synthetic AKIA body: 16 base32 chars, deterministic but not the
    // public AWS-docs placeholder. Passes the contract regex
    // `(?-i)(AKIA|ASIA)[0-9A-Z]{16}` and avoids the known-example
    // suppression that would silence "AKIAIOSFODNN7EXAMPLE".
    let synthetic_akia = "AKIA6CR0ANJCWS6ROMLZ";
    let body = format!("aws_access_key_id: {synthetic_akia}\nplain_field: value\n");
    let matches = scan_path(&body, "/repo/configs/aws.yaml");

    // The AKIA must surface; this confirms the wider pipeline is not
    // disabled by the caesar gate's negative branch.
    let akia_hit = matches
        .iter()
        .any(|m| m.credential.as_ref() == synthetic_akia);
    assert!(
        akia_hit,
        "synthetic AKIA must still surface on a non-URL chunk; the caesar \
         gate must not slam unrelated chunks. ALL findings: {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
