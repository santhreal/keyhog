//! BPE "rare-not-random" precision gate for the entropy fallback.
//!
//! The entropy detectors (`entropy-token`, `entropy-api-key`, `entropy-password`)
//! flag high-entropy tokens. Their dominant false positives on real corpora are
//! NOT random noise but WORD-LIKE structured identifiers — dotted API paths like
//! `PInvoke.User32.WindowMessage.WM_SYSCOLORCHANGE`, XML/HTML fragments, camelCase
//! symbol names. These are high-entropy (mixed case, punctuation) yet compress
//! into a handful of common subword tokens, whereas a real secret (`ghp_a8Xk…`,
//! a base64 key) has no common merges and tokenizes into many short pieces.
//!
//! tiktoken `cl100k_base` bytes-per-token measures exactly that compressibility:
//! word-like text ≈ 3–5 bytes/token, random secrets ≈ 1.1–1.5 bytes/token. This
//! is the same broad signal Betterleaks exposes as `failsTokenEfficiency` using
//! its embedded `cl100k_base` tokenizer. Betterleaks combines byte-length/token
//! thresholds with word-list and short-value branches; KeyHog deliberately uses
//! a bytes/token score whose ceiling is detector-owned TOML policy.
//! Suppressing entropy candidates ABOVE the threshold is a large CredData precision win (offline A/B
//! on a real scan, scored by the bench: F1 0.3684 → 0.4236, FP 8185 → 4260 for
//! only −55 TP at the 2.2 peak). The heuristic word-like gates that already exist
//! (English-prose, pure-identifier, word-separated) miss the dotted API-path and
//! XML classes; this principled measure catches them.
//!
//! Gated on `feature = "entropy"` (the tokenizer dep rides that feature).

use std::sync::LazyLock;

use tiktoken_rs::{cl100k_base, CoreBPE};

/// The compiled default bytes-per-token suppression bound. A candidate whose
/// `cl100k_base` bytes-per-token is STRICTLY GREATER than the ACTIVE bound is
/// treated as word-like (non-secret) and suppressed. 2.2 is the empirical
/// CredData F1 peak (see the module doc A/B); values 2.0–2.5 are all strong
/// (F1 ≈ 0.421–0.424).
///
/// The VALUE has exactly one owner, [`keyhog_core::DEFAULT_ENTROPY_BPE_MAX_BYTES_PER_TOKEN`]
/// — it lives in the lower `keyhog-core` crate so `ScanConfig` can default to it
/// without a scanner↔core cycle. This is the historical name re-bound to that one
/// owner for the gate's compiled default and the tests below; a per-scan override
/// (`ScanConfig::entropy_bpe_max_bytes_per_token`, Tier-A TOML + CLI) is threaded
/// into [`is_word_like_low_bpe`] at the two call sites, so operators trade
/// precision for recall per corpus without a code change.
#[cfg(test)]
pub(crate) const ENTROPY_BPE_MAX_BYTES_PER_TOKEN: f64 =
    keyhog_core::DEFAULT_ENTROPY_BPE_MAX_BYTES_PER_TOKEN;

/// Lazily-built cl100k_base tokenizer. The ranks are embedded in the crate, so
/// this is a pure decode with no I/O; built once on first entropy candidate that
/// survives the cheaper shape gates.
static CL100K: LazyLock<CoreBPE> =
    LazyLock::new(|| cl100k_base().expect("tiktoken cl100k_base ranks are embedded in the crate"));

/// UTF-8 bytes per BPE token for `s` under cl100k_base. Higher = more
/// compressible = more word-like. `cl100k_base` is byte-level, so using Unicode
/// scalar counts would artificially lower non-ASCII text and let ordinary
/// localized prose bypass the gate. Returns `0.0` for empty input.
pub(crate) fn bytes_per_token(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let tokens = CL100K.encode_ordinary(s).len();
    if tokens == 0 {
        return 0.0;
    }
    s.len() as f64 / tokens as f64
}

/// True iff `s` is word-like (compresses into few common subwords) under the
/// given `max_bytes_per_token` bound — i.e. a probable entropy false positive
/// that should be suppressed. The bound is the per-scan
/// `ScanConfig::entropy_bpe_max_bytes_per_token` (Tier-A), which defaults to
/// `keyhog_core::DEFAULT_ENTROPY_BPE_MAX_BYTES_PER_TOKEN`; the predicate itself owns no threshold so
/// the config value is the single runtime authority.
pub(crate) fn is_word_like_low_bpe(s: &str, max_bytes_per_token: f64) -> bool {
    bytes_per_token(s) > max_bytes_per_token
}

/// Resolve the token-efficiency ceiling for one detector. Detector TOML owns
/// detector-specific policy over the compiled fallback, while an explicitly
/// configured Tier-A scan value has final precedence. The explicit value is an
/// `Option` rather than a magic comparison with the compiled default, so an
/// operator explicitly choosing the default value still overrides a tuned
/// detector. Resolution happens once before tokenization and contains no hidden
/// detector-id table.
#[inline]
pub(crate) fn max_bytes_per_token_for_detector(
    detector: Option<&keyhog_core::DetectorSpec>,
    scan_fallback: f64,
    scan_override: Option<f64>,
) -> f64 {
    scan_override.unwrap_or_else(|| {
        detector
            .and_then(|spec| spec.bpe_max_bytes_per_token)
            .unwrap_or(scan_fallback)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The full word-like FALSE-POSITIVE taxonomy the entropy/generic detectors
    /// flood on real CredData + source trees: dotted .NET P/Invoke, Java/Go, and
    /// namespace paths, XML namespace declarations, English prose, long
    /// camelCase symbol names, snake_case config identifiers, and REST URLs.
    /// Every one compresses into a handful of common cl100k_base subwords → high
    /// bytes/token → must be suppressed. The heuristic word-like gates
    /// (pure-identifier, word-separated) miss the dotted-path/XML/URL classes;
    /// this BPE measure is their principled superset. ONE owner for the list.
    const WORD_LIKE_FP: &[&str] = &[
        "PInvoke.User32.WindowMessage.WM_SYSCOLORCHANGE",
        "PInvoke.Kernel32.CreationDisposition.TRUNCATE_EXISTING",
        "PInvoke.Win32ErrorCode.NERR_DfsChildOrParentInDfs",
        "System.Runtime.InteropServices.Marshal.GetLastWin32Error",
        "com.google.protobuf.GeneratedMessageV3.parseUnknownField",
        "org.apache.commons.lang3.builder.ReflectionToStringBuilder",
        "<ContentPagexmlns=\"http://xamarin.com/schemas/2014/forms\">",
        "the quick brown fox jumps over the lazy dog again today",
        "getUserAccountConfigurationManagerFactoryProviderInstance",
        "aws_secret_access_key_configuration_environment_variable",
        "https://management.azure.com/subscriptions/resourceGroups",
    ];

    /// The genuine SECRET taxonomy that MUST survive the gate: vendor-prefixed
    /// tokens (GitHub ghp_/gho_, GitLab glpat-, Slack xoxb-, Stripe sk_live_,
    /// Google AIza), an AWS access-key id, a secret-access-key, and bare hex
    /// digests. All are high-entropy with NO common merges → bytes/token ~1.0-1.5
    /// → never suppressed. Bodies are random (NOT the sequential / `EXAMPLE`
    /// shapes that would tokenize atypically or collide with example-suppression).
    /// ONE owner for the list.
    const REAL_SECRETS: &[&str] = &[
        "ghp_a8Xk9mQ2pL5vR7tN3wErtY1zAbCdEf0GhIj",
        "gho_1B4c6D8e0F2g4H6i8J0k2L4m6N8o0P2q4R6s",
        "glpat-3Fx7Kp9Qz2Rv5Tw8Yb1Lc4",
        "AKIAZ3XK9QM2PL5VR7TN",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYz9Qk8vHsPq",
        "AIzaSyD8kL3mNp9Qr2Xw7Vz1Bc4Yt6Uh0Jf5",
        "xoxb-2Fj8Kp1Qz5Rv9Tw3Yb7Lc0Nd4Mf6Hg2",
        "sk_live_51Hq8xKp3Nz9Rv2Tw7Yb4Lc6Md8",
        "c7f3a1e9b2d84051a6f8c3e9f1b2d4a6c8e0f1a2",
        "3d5b7f9a1c2e4068a0c2e4f6b8d0f2a4",
        "Y2FsaWNvLW9uLWt1YmUtYXV0aC1rZXk=",
    ];

    #[test]
    fn every_word_like_fp_class_is_suppressed() {
        for &fp in WORD_LIKE_FP {
            let cpt = bytes_per_token(fp);
            assert!(
                cpt > ENTROPY_BPE_MAX_BYTES_PER_TOKEN,
                "word-like FP {fp:?} should exceed threshold, got {cpt:.3} bytes/token"
            );
            assert!(
                is_word_like_low_bpe(fp, ENTROPY_BPE_MAX_BYTES_PER_TOKEN),
                "{fp:?} (cpt {cpt:.3}) must be suppressed"
            );
        }
    }

    #[test]
    fn every_real_secret_class_survives() {
        for &secret in REAL_SECRETS {
            let cpt = bytes_per_token(secret);
            assert!(
                cpt <= ENTROPY_BPE_MAX_BYTES_PER_TOKEN,
                "real secret {secret:?} must stay below threshold, got {cpt:.3} bytes/token"
            );
            assert!(
                !is_word_like_low_bpe(secret, ENTROPY_BPE_MAX_BYTES_PER_TOKEN),
                "{secret:?} (cpt {cpt:.3}) must NOT be suppressed"
            );
        }
    }

    /// The discrimination is not marginal: the LEAST word-like FP sits far above
    /// the MOST word-like secret, so the 2.2 bound falls in a wide empty gap.
    /// This gap is what makes the gate a precision win at ~zero recall cost — if
    /// it ever collapses (the classes crowd the bound), the threshold is
    /// mis-set. Differential proof, not a per-example shape check.
    #[test]
    fn fp_and_secret_classes_do_not_overlap_the_bound() {
        let min_fp = WORD_LIKE_FP
            .iter()
            .map(|s| bytes_per_token(s))
            .fold(f64::INFINITY, f64::min);
        let max_secret = REAL_SECRETS
            .iter()
            .map(|s| bytes_per_token(s))
            .fold(0.0_f64, f64::max);
        assert!(
            max_secret <= ENTROPY_BPE_MAX_BYTES_PER_TOKEN,
            "most word-like secret cpt {max_secret:.3} must not exceed bound {ENTROPY_BPE_MAX_BYTES_PER_TOKEN}"
        );
        assert!(
            min_fp > ENTROPY_BPE_MAX_BYTES_PER_TOKEN,
            "least word-like FP cpt {min_fp:.3} must exceed bound {ENTROPY_BPE_MAX_BYTES_PER_TOKEN}"
        );
        assert!(
            min_fp > max_secret + 1.0,
            "FP class (min {min_fp:.3}) must sit >1.0 bytes/token above secret class (max {max_secret:.3})"
        );
    }

    /// `is_word_like_low_bpe` must be exactly `cpt > bound` (STRICTLY greater):
    /// a value whose cpt equals the bound is a secret (kept), not word-like.
    /// Guards against a future `>=` typo that would silently suppress more.
    #[test]
    fn suppression_predicate_is_strictly_greater_than_the_owner_const() {
        for &s in WORD_LIKE_FP.iter().chain(REAL_SECRETS.iter()) {
            assert_eq!(
                is_word_like_low_bpe(s, ENTROPY_BPE_MAX_BYTES_PER_TOKEN),
                bytes_per_token(s) > ENTROPY_BPE_MAX_BYTES_PER_TOKEN,
                "is_word_like_low_bpe must equal `cpt > {ENTROPY_BPE_MAX_BYTES_PER_TOKEN}` for {s:?}"
            );
        }
    }

    #[test]
    fn empty_is_not_word_like() {
        assert_eq!(bytes_per_token(""), 0.0);
        assert!(!is_word_like_low_bpe("", ENTROPY_BPE_MAX_BYTES_PER_TOKEN));
    }

    #[test]
    fn unicode_efficiency_uses_utf8_bytes_not_scalar_count() {
        let localized_prose = "設定ファイルの秘密値をここに入力してください";
        let tokens = CL100K.encode_ordinary(localized_prose).len();
        let measured = bytes_per_token(localized_prose);
        let byte_ratio = localized_prose.len() as f64 / tokens as f64;
        let scalar_ratio = localized_prose.chars().count() as f64 / tokens as f64;

        assert_eq!(measured.to_bits(), byte_ratio.to_bits());
        assert!(
            measured > scalar_ratio,
            "UTF-8 byte efficiency must not collapse to Unicode scalar efficiency: bytes={measured}, scalars={scalar_ratio}"
        );
    }

    #[test]
    fn detector_policy_precedes_scan_fallback_without_affecting_other_detectors() {
        let candidate = "PInvoke.User32.WindowMessage.WM_SYSCOLORCHANGE";
        let strict = keyhog_core::DetectorSpec {
            bpe_max_bytes_per_token: Some(2.2),
            ..Default::default()
        };
        let permissive = keyhog_core::DetectorSpec {
            bpe_max_bytes_per_token: Some(99.0),
            ..Default::default()
        };
        let strict_bound = max_bytes_per_token_for_detector(Some(&strict), 99.0, None);
        let permissive_bound = max_bytes_per_token_for_detector(Some(&permissive), 2.2, None);
        assert!(is_word_like_low_bpe(candidate, strict_bound));
        assert!(!is_word_like_low_bpe(candidate, permissive_bound));
        assert_eq!(permissive_bound, 99.0);
        assert_eq!(max_bytes_per_token_for_detector(None, 2.2, None), 2.2);

        let inherited = keyhog_core::DetectorSpec::default();
        assert_eq!(
            max_bytes_per_token_for_detector(Some(&inherited), 1.9, None),
            1.9
        );
        assert_eq!(
            max_bytes_per_token_for_detector(Some(&strict), 2.2, Some(7.5)),
            7.5,
            "an explicit Tier-A scan setting must override detector TOML"
        );
    }

    #[test]
    fn shipped_opaque_and_password_policies_make_different_bpe_decisions() {
        let word_like = "correcthorsebatterystaple";
        let api_key = keyhog_core::detector_spec_by_id(crate::detector_ids::GENERIC_API_KEY)
            .expect("generic-api-key detector exists");
        let password = keyhog_core::detector_spec_by_id(crate::detector_ids::GENERIC_PASSWORD)
            .expect("generic-password detector exists");
        let api_bound = max_bytes_per_token_for_detector(Some(api_key), 2.2, None);
        let password_bound = max_bytes_per_token_for_detector(Some(password), 2.2, None);

        assert!(
            is_word_like_low_bpe(word_like, api_bound),
            "opaque API-key policy should reject a language-compressible value"
        );
        assert!(
            !is_word_like_low_bpe(word_like, password_bound),
            "password policy must keep a human-chosen word-like passphrase for downstream evidence"
        );
    }

    /// The Tier-A `entropy_bpe_max_bytes_per_token` override actually MOVES the
    /// suppression boundary: a word-like FP that the default 2.2 bound suppresses
    /// must be RELEASED under a loose bound above its own bytes-per-token, and a
    /// real secret must stay kept under a tight bound at 1.0 (never crossing into
    /// suppression from below). Proves the threshold is the single runtime
    /// authority, not the compiled const, so operators can trade precision for
    /// recall per corpus. Uses a concrete FP whose cpt sits strictly between the
    /// default and the loose bound so the flip is unambiguous.
    #[test]
    fn config_override_threshold_shifts_the_suppression_boundary() {
        // A word-like FP the default bound suppresses.
        let fp = "PInvoke.User32.WindowMessage.WM_SYSCOLORCHANGE";
        let fp_cpt = bytes_per_token(fp);
        assert!(
            fp_cpt > ENTROPY_BPE_MAX_BYTES_PER_TOKEN,
            "fixture must be suppressed by the default bound (cpt {fp_cpt:.3})"
        );
        // Suppressed at the default bound…
        assert!(is_word_like_low_bpe(fp, ENTROPY_BPE_MAX_BYTES_PER_TOKEN));
        // …but a loose override ABOVE its cpt releases it (higher recall route).
        let loose = fp_cpt + 1.0;
        assert!(
            !is_word_like_low_bpe(fp, loose),
            "loose override {loose:.3} must release the FP {fp:?} (cpt {fp_cpt:.3})"
        );
        // A real random secret stays KEPT even under a tight 1.0 bound: its cpt is
        // ~1.0–1.5, so tightening precision must not wrongly suppress it from below
        // unless the operator drives the bound below the secret's own cpt.
        let secret = "ghp_a8Xk9mQ2pL5vR7tN3wErtY1zAbCdEf0GhIj";
        let secret_cpt = bytes_per_token(secret);
        assert!(
            !is_word_like_low_bpe(secret, secret_cpt + 0.01),
            "secret {secret:?} (cpt {secret_cpt:.3}) must survive a bound just above its own cpt"
        );
    }
}
