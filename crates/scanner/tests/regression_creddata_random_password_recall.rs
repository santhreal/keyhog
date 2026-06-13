//! Regression (KH-L-0413): the generic keyword bridge must SURFACE a random
//! low-entropy password that is shape-identical to a code identifier (all
//! lowercase, no digit), and must keep SUPPRESSING genuine dictionary
//! identifiers under the same credential keywords.
//!
//! Root cause this locks against: the identifier/type-name shape gates
//! (`pure_identifier_no_digit`, `pure_identifier`, `type_name_shape`,
//! `word_separated_identifier`) in `generic_value_shape_rejected` dropped EVERY
//! all-letters-no-digit value — suppressing not just `password = getUserName`
//! (a code reference) but also ~1114 real CredData passwords that happen to be
//! random lowercase strings (`GRAPHITE_PASS=gjbubxsu`, `password="ufnlbbavawsdeecn"`).
//! The two classes are shape-identical, so the gate is now conditioned on an
//! English bigram-model randomness check (`suppression::token_randomness`): a
//! RANDOM token lifts the gate (recover the password); a pronounceable
//! dictionary identifier still fires it (stay suppressed).
//!
//! Measured A/B (vs the pre-change binary): CredData TP +957 / FP +71 (93%
//! marginal precision; recall 0.181→0.250, precision 0.600→0.665) and mirror
//! precision HELD 0.9954 ≥ 0.9945 — the dictionary discriminator is what makes
//! the lift sound (lifting unconditionally cost +3554 FP).

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    CompiledScanner::compile(detectors).expect("compile scanner")
}

fn credentials_for(scanner: &CompiledScanner, line: &str) -> Vec<String> {
    let chunk = Chunk {
        data: line.into(),
        metadata: ChunkMetadata::default(),
    };
    scanner.clear_fragment_cache();
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .map(|m| m.credential.to_string())
        .collect()
}

fn caught(scanner: &CompiledScanner, line: &str, value: &str) -> bool {
    credentials_for(scanner, line).iter().any(|c| c == value)
}

#[test]
fn random_lowercase_passwords_under_keyword_are_surfaced() {
    let s = scanner();
    // Real CredData passwords: all-lowercase, no digit, IMPROBABLE English
    // bigrams (gjb, kr, bx, dz) — the identifier gates dropped these before the
    // randomness discriminator. Each is keyword-anchored.
    for (line, val) in [
        ("GRAPHITE_PASS=gjbubxsu", "gjbubxsu"),
        ("JENKINS_PASS=krbykalt", "krbykalt"),
        ("password = \"ufnlbbavawsdeecn\"", "ufnlbbavawsdeecn"),
        ("self.password = \"rwwjfwpbqxzkdv\"", "rwwjfwpbqxzkdv"),
        ("SES_PASS=dzdvnffvqp", "dzdvnffvqp"),
    ] {
        assert!(
            caught(&s, line, val),
            "random lowercase password {val:?} (improbable-bigram) must surface \
             via the keyword bridge (KH-L-0413 randomness lift); line {line:?}"
        );
    }
}

#[test]
fn dictionary_identifiers_under_keyword_stay_suppressed() {
    let s = scanner();
    // Pronounceable English/code identifiers under the SAME credential keywords:
    // these are code references, NOT secrets, and must NOT bridge — the randomness
    // discriminator scores them as dictionary (high bigram probability) so the
    // identifier gate still fires. (Lifting these is the +3554-FP class the
    // unconditional lift caused.)
    for (line, val) in [
        ("password = getUserName", "getUserName"),
        ("secret = configValue", "configValue"),
        ("password = defaultPassword", "defaultPassword"),
        ("token = requestToken", "requestToken"),
        ("api_key = accessToken", "accessToken"),
        ("secret = administrator", "administrator"),
    ] {
        assert!(
            !caught(&s, line, val),
            "dictionary identifier {val:?} (pronounceable) must stay suppressed — \
             it is a code reference, not a secret; line {line:?}"
        );
    }
}
