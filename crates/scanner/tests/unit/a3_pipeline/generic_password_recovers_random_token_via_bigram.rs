use keyhog_scanner::context::CodeContext;
use keyhog_scanner::pipeline::should_suppress_named_detector_finding;

// KH-L-0414: the post-process weak-anchor suppressor
// (`should_suppress_named_detector_finding_weak`) applied the SAME
// `looks_like_pure_identifier` / `looks_like_word_separated_identifier` Tier-B
// gates that KH-L-0413 lifted on the scan-time generic bridge — so a real random
// password a generic-* / entropy-* / weakly-anchored named detector flagged was
// still dropped here as an "identifier". Both call sites now share
// `token_randomness::keep_identifier_gate`, so the discriminator agrees on both
// paths. Measured A/B (vs the pre-change binary): CredData TP +27 / FP +1 (96.4%
// marginal precision) AND mirror +8 TP with FP held at 12 (precision 0.9954).
//
// These tests pin the api.rs path directly (NOT the scan-time bridge that
// `regression_creddata_random_password_recall` covers): a random all-lowercase
// no-digit token must NOT be suppressed, while a pronounceable dictionary
// identifier of the same shape must still be.

#[test]
fn random_lowercase_token_not_suppressed_by_identifier_gate() {
    // `ufnlbbavawsdeecn` (a real CredData password): 16 all-lowercase letters,
    // no digit, IMPROBABLE English bigrams (`fn`, `lb`, `bb`, `vaw`). Before
    // KH-L-0414 `looks_like_pure_identifier` fired and this dropped; now the
    // bigram randomness check lifts the identifier gate.
    assert!(
        !should_suppress_named_detector_finding(
            "ufnlbbavawsdeecn",
            Some("config.env"),
            CodeContext::Unknown,
            None,
            "generic-password",
        ),
        "random lowercase password must NOT be suppressed by the identifier gate \
         once the bigram discriminator scores it random (KH-L-0414)"
    );
}

#[test]
fn lowercase_word_separated_random_password_recovered() {
    // Real CredData word-separated passwords are uniformly all-lowercase letters
    // + separators and score deeply random (`abxnj_gjvpuqzo` −10.4,
    // `aapqhgn-qhuuc-trnmf` −9.0). `keep_word_separated_gate` trusts the random
    // verdict for this clean shape, so they are recovered (KH-L-0414).
    for val in ["abxnj_gjvpuqzo", "aapqhgn-qhuuc-trnmf", "avy_tcfkongh"] {
        assert!(
            !should_suppress_named_detector_finding(
                val,
                Some("creds.env"),
                CodeContext::Unknown,
                None,
                "generic-secret",
            ),
            "lowercase word-separated random password {val:?} must be recovered — \
             it is the clean all-lowercase shape the discriminator trusts (KH-L-0414)"
        );
    }
}

#[test]
fn word_separated_acronym_identifier_stays_suppressed() {
    // Soundness boundary: the discriminator is an ENGLISH-WORD model, so
    // multi-segment programmer identifiers built from acronym fragments score as
    // "random" (`d2i_PKCS7_bio` −7.88, `curlx_memdup0` −7.09, both below the
    // −6.85 threshold) even though they are code, NOT secrets. KH-L-0414
    // therefore leaves `looks_like_word_separated_identifier` UNCONDITIONAL —
    // these must stay suppressed despite the misleading randomness score.
    for val in ["d2i_PKCS7_bio", "curlx_memdup0", "s3_secret_access_key"] {
        assert!(
            should_suppress_named_detector_finding(
                val,
                Some("openssl/apps/ts.c"),
                CodeContext::Unknown,
                None,
                "generic-secret",
            ),
            "word-separated acronym identifier {val:?} must stay suppressed — the \
             English bigram model mis-scores its acronyms as random, so this gate \
             is deliberately NOT discriminator-conditioned (KH-L-0414)"
        );
    }
}

#[test]
fn low_diversity_patterns_stay_suppressed() {
    // KH-L-0418 soundness guard: a repetitive / alternating PATTERN has
    // improbable English bigrams (it passes the log-prob threshold) but is NOT a
    // random token. `xzxzxzxz` is the worst case — 2 distinct letters,
    // alphanumeric, no 3-consecutive run, so the decision.rs repetitive/symbolic
    // gates miss it; only the distinct-letter guard in `is_random_token` keeps it
    // suppressed (it must read as an identifier, not get lifted as a secret).
    for val in ["xzxzxzxz", "qqqqwwww", "aaaaaaaa", "zzzzzzzzzzzz"] {
        assert!(
            should_suppress_named_detector_finding(
                val,
                Some("creds.env"),
                CodeContext::Unknown,
                None,
                "generic-secret",
            ),
            "low-diversity pattern {val:?} must stay suppressed — it is a \
             repetitive pattern, not a random secret (KH-L-0418 diversity guard)"
        );
    }
}

#[test]
fn dictionary_identifier_still_suppressed() {
    // Negative twin: pronounceable code references of the SAME shape must STILL
    // suppress — the discriminator scores them as dictionary (high bigram
    // probability), so the identifier gate keeps firing. Lifting these is the
    // +3554-FP class the unconditional lift caused (KH-L-0413).
    for (val, detector) in [
        ("getParameter", "generic-password"),
        ("defaultPassword", "generic-password"),
        ("configuration", "generic-secret"),
        ("access-token-value", "generic-secret"),
    ] {
        assert!(
            should_suppress_named_detector_finding(
                val,
                Some("WebgoatContext.java"),
                CodeContext::Unknown,
                None,
                detector,
            ),
            "dictionary identifier {val:?} (pronounceable) must stay suppressed — \
             it is a code reference, not a secret (KH-L-0414 negative twin)"
        );
    }
}
