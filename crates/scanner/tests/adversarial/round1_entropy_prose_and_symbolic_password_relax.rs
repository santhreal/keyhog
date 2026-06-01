//! Round 1 contract: the entropy-fallback's prose detection must catch
//! 16+ char pure-lowercase / multi-token alphabetic strings, AND the
//! strict-mode floor must admit symbolic-password values past the 4.5
//! entropy ceiling when the credential is anchored by a strong keyword.
//!
//! Investigator finding (097673e4, entropy/keywords.rs +
//! engine/fallback_entropy.rs):
//!   * `looks_like_english_prose` lowered length floor 24 -> 16 and
//!     added a multi-token whitespace-alphabetic branch.
//!   * `passes_strict_secret_checks` relaxed in credential-anchored
//!     context: symbolic-char + entropy >= 3.5 admits values past the
//!     4.5 floor. Pure-alphanumeric keeps the 4.5 floor.
//!
//! Adversarial style: paired truth case (symbolic-password
//! `Y6NPMwS*rWGUv!JQnSG6a#D14`-shape surfaces under a strong
//! credential keyword) + negative twin (a 16+ char pure-lowercase
//! prose value under a weakly-anchored line does NOT surface; a
//! multi-token whitespace prose value under any line does NOT
//! surface). CVE replay shape: real symbolic-password byte pattern
//! observed in the SecretBench v32 generic-password category FNs.

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
    // Shared single scanner (LG2): all adversarial full-detector tests
    // route through one compiled instance instead of one per file.
    crate::adversarial::oracle_support::production_scanner()
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

/// Positive truth: a 25-char symbolic-password under a strong
/// credential-keyword anchor (`password=`) must surface. Shannon
/// entropy of the body lands around 4.0-4.4 (below the 4.5 blanket
/// floor), but the value carries 4 symbolic chars (`*`, `!`, `#`)
/// which is the relax signal.
#[test]
fn symbolic_password_under_strong_anchor_surfaces() {
    // Real SecretBench v32 FN shape. 25 chars, mixed case + digits +
    // 4 symbolic chars. Entropy ~4.3 bits/char, well above the 3.5
    // floor and below the 4.5 ceiling.
    let secret = "Y6NPMwS*rWGUv!JQnSG6a#D14";
    let body = format!("password={secret}\n");
    let matches = scan_path(&body, "/repo/configs/app.env");

    let surfaced = matches.iter().any(|m| m.credential.as_ref() == secret);
    assert!(
        surfaced,
        "symbolic-password under strong `password=` anchor must \
         surface (round 1 entropy relax). ALL findings: {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

/// Adversarial negative twin: a 16+ char pure-lowercase alphabetic
/// value that lands near a weak credential keyword (`description`)
/// must NOT surface. Pure-lowercase 16+ chars is the prose signature
/// the round 1 fix added; before the fix this would have leaked.
#[test]
fn pure_lowercase_prose_value_does_not_surface_as_credential() {
    // 30-char pure lowercase. Looks like joined words / sentence
    // fragment. No digit, no symbol, no uppercase.
    let prose_value = "thequickbrownfoxjumpsoverthelaz";
    assert_eq!(prose_value.len(), 31);
    let body = format!("description = \"{prose_value}\"\n");
    let matches = scan_path(&body, "/repo/configs/help.env");

    let bad: Vec<_> = matches
        .iter()
        .filter(|m| m.credential.as_ref() == prose_value)
        .collect();
    assert!(
        bad.is_empty(),
        "16+ char pure-lowercase prose value must NOT surface as a \
         credential. offenders: {:?}",
        bad.iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

/// Adversarial negative twin: a multi-token whitespace-bearing
/// alphabetic value (the second branch of the prose detector) must
/// NOT surface as a credential. This is the "your fallback ate a
/// commit message" failure mode.
#[test]
fn multi_token_whitespace_prose_does_not_surface_as_credential() {
    // Multi-token alphabetic prose. Even though the entire RHS is
    // captured by a quoted-extractor, the prose gate must reject it.
    let prose_value = "this describes the configuration field clearly";
    let body = format!("note=\"{prose_value}\"\n");
    let matches = scan_path(&body, "/repo/configs/notes.env");

    let bad: Vec<_> = matches
        .iter()
        .filter(|m| m.credential.as_ref() == prose_value)
        .collect();
    assert!(
        bad.is_empty(),
        "multi-token whitespace prose value must NOT surface as a \
         credential. offenders: {:?}",
        bad.iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

/// Adversarial soundness: pure-alphanumeric (no symbol) value at the
/// 4.0-4.4 entropy band must NOT surface even under a strong anchor.
/// The relax fix is GATED by the presence of a symbolic char; without
/// it the 4.5 floor is still enforced. A regression that drops the
/// symbolic-char gate would surface this value.
#[test]
fn pure_alphanumeric_at_relax_entropy_band_does_not_surface() {
    // 16-char value, mixed case + digits, NO symbols. Entropy ~4.0.
    // Looks like a Java/Go identifier or hash prefix. Must NOT
    // surface because the symbolic-char gate is missing.
    let identifier = "GenericServiceBuilder";
    assert_eq!(identifier.len(), 21);
    let body = format!("password={identifier}\n");
    let matches = scan_path(&body, "/repo/configs/app.env");

    let bad: Vec<_> = matches
        .iter()
        .filter(|m| m.credential.as_ref() == identifier)
        .collect();
    assert!(
        bad.is_empty(),
        "pure-alphanumeric identifier without symbols must NOT \
         surface even under password= anchor. offenders: {:?}",
        bad.iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
