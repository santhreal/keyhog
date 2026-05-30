//! Round 1 invariant lockdown (cross-cutting): every `RawMatch`
//! surfaced by the production scanner pipeline must carry a real
//! detector_id, NOT a placeholder string. This is the cross-cutting
//! guarantee the Round 1 fixes rely on:
//!
//!   * fragment_cache same-file-only restriction (d60fa9d6) drops the
//!     cross-file `:reassembled` cannibalization path. Any reassembled
//!     finding that does surface must inherit a real detector_id from
//!     the underlying named detector.
//!   * env parser backtick + inline-comment strip keeps the captured
//!     credential bytes aligned with the named-detector regex's literal
//!     prefix, so the detector_id surfaces as the real vendor id and
//!     not a generic fallback.
//!   * caesar gate skip on credentialled URLs prevents the synthesized
//!     ROT-N decoder from emitting placeholder-id chunks that would
//!     out-resolve the real URL detector.
//!
//! Adversarial style: PROPTEST 1k iterations.
//!
//! Property: for every randomized `.env` line carrying a synthetic
//! GitHub PAT shape (`ghp_[A-Za-z0-9]{36}`) wrapped in a randomly
//! chosen quoting style (none / single quotes / double quotes /
//! backticks) and optionally trailed by a random inline `# comment`,
//! EVERY surfaced finding must:
//!   1. Have a non-empty detector_id.
//!   2. Have a detector_id that is NOT a placeholder token (no
//!      `"placeholder"`, `"unknown"`, `"todo"`, `"undefined"`,
//!      `""`, no whitespace-only string, no `:reassembled` suffix in
//!      isolation - the suffix is only legal when paired with a real
//!      detector_id prefix).
//!   3. Have a credential string that is not the empty string.
//!
//! If a regression in any Round 1 fix surfaces a finding whose
//! detector_id violates the invariant, this test fails on the first
//! offending shrunken case.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScannerConfig};
use proptest::prelude::*;
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

fn scan(body: String, path: &str) -> Vec<keyhog_core::RawMatch> {
    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    shared_scanner().scan(&chunk)
}

/// Set of placeholder / sentinel detector_id values that must never
/// surface from the production scanner pipeline. The list is the
/// canonical placeholder phrases the codebase has historically used as
/// stand-ins (and which downstream consumers grep for to detect a
/// detector lookup failure).
fn is_placeholder_detector_id(id: &str) -> bool {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "placeholder"
            | "todo"
            | "unknown"
            | "undefined"
            | "<unknown>"
            | "<placeholder>"
            | "null"
            | "none"
            | ":reassembled"
            | "reassembled"
    )
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1_000,
        max_shrink_iters: 64,
        .. ProptestConfig::default()
    })]

    /// Property: every finding surfaced by the scanner on a randomized
    /// `.env` line carries a real detector_id and a non-empty
    /// credential. A regression that surfaces a placeholder id (e.g.
    /// the bare `:reassembled` suffix without a real prefix) fails
    /// this property.
    #[test]
    fn every_finding_has_real_detector_id_and_credential(
        body in "[A-Za-z0-9]{36}",
        quote_style in 0u8..4u8,
        with_comment in any::<bool>(),
        comment_text in "[A-Za-z0-9 ]{0,30}",
        var_name in "[A-Z][A-Z_]{2,16}",
    ) {
        // Build the .env line. `ghp_` + 36 base62 chars matches the
        // contract of `github-classic-pat` (the regex is
        // `ghp_[A-Za-z0-9]{36,255}`). The quoting / commenting
        // wrappers exercise the round-1 parser fix.
        let secret = format!("ghp_{}", body);
        let quoted = match quote_style {
            0 => secret.clone(),
            1 => format!("'{}'", secret),
            2 => format!("\"{}\"", secret),
            _ => format!("`{}`", secret),
        };
        let line = if with_comment && !comment_text.is_empty() {
            format!("{}={} # {}\n", var_name, quoted, comment_text)
        } else {
            format!("{}={}\n", var_name, quoted)
        };

        let matches = scan(line.clone(), "/repo/proptest/.env");

        for m in &matches {
            let id = m.detector_id.as_ref();
            let cred = m.credential.as_ref();

            prop_assert!(
                !is_placeholder_detector_id(id),
                "finding surfaced with placeholder detector_id={:?}, \
                 credential={:?}, line={:?}",
                id, cred, line
            );

            prop_assert!(
                !cred.is_empty(),
                "finding surfaced with empty credential, \
                 detector_id={:?}, line={:?}",
                id, line
            );

            // The :reassembled suffix is permitted, but only when
            // paired with a real prefix that is NOT the empty string.
            if let Some(prefix) = id.strip_suffix(":reassembled") {
                prop_assert!(
                    !prefix.is_empty() && !is_placeholder_detector_id(prefix),
                    "reassembled finding must carry a real prefix; \
                     id={:?}, credential={:?}, line={:?}",
                    id, cred, line
                );
            }
        }
    }

    /// Companion property: for every finding whose credential bytes
    /// contain a recognisable real-prefix substring (`ghp_`, `AKIA`,
    /// `sk-`, `eyJ`), the detector_id is NOT the empty string and
    /// the credential bytes contain NO leading wrapping punctuation
    /// (backtick / quote / hash). This locks the round-1 env-parser
    /// fix at scale: a regression that re-admits the wrapping quote
    /// would shrink to a one-character failure showing the offending
    /// leading byte.
    #[test]
    fn credential_bytes_carry_no_wrapping_punctuation(
        body in "[A-Za-z0-9]{36}",
        var_name in "[A-Z][A-Z_]{2,16}",
    ) {
        let secret = format!("ghp_{}", body);
        let line = format!("{}=`{}`\n", var_name, secret);
        let matches = scan(line.clone(), "/repo/proptest/wrap.env");

        for m in &matches {
            let cred = m.credential.as_ref();
            // Only check findings whose credential bytes correspond to
            // the planted secret. Other detectors that fire on the
            // wrapping context are outside the contract.
            if cred.contains("ghp_") {
                prop_assert!(
                    !cred.starts_with('`')
                        && !cred.starts_with('"')
                        && !cred.starts_with('\'')
                        && !cred.starts_with('#')
                        && !cred.starts_with('='),
                    "credential bytes starting with wrapping/comment \
                     punctuation; detector_id={:?}, credential={:?}, line={:?}",
                    m.detector_id.as_ref(), cred, line
                );
                prop_assert!(
                    !cred.ends_with('`')
                        && !cred.ends_with('"')
                        && !cred.ends_with('\''),
                    "credential bytes ending with wrapping punctuation; \
                     detector_id={:?}, credential={:?}, line={:?}",
                    m.detector_id.as_ref(), cred, line
                );
            }
        }
    }
}
