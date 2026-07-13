//! Gap test: the universal-rejection prefix gate's exact reject/accept table.
//!
//! `matches_universal_rejection` is the first gate in the entropy plausibility
//! checks, it drops candidates that are obviously not free-standing secrets:
//! URLs, filesystem paths, CI/template variables, three-segment JWTs, SSH/PEM
//! key material, age/ansible-vault/sops/AWS-KMS envelopes, Windows drive paths,
//! and markdown fences. Each branch keeps a whole false-positive class out of
//! generation, and the helper had no direct coverage. Pin every rejection class
//! AND the two condition-sensitive near-misses (a one-dot `eyJ` and a short
//! `Ag` value must NOT be rejected).

use keyhog_scanner::testing::entropy_matches_universal_rejection_for_test as rejects;

const REJECTED: &[&str] = &[
    "https://example.com/path",                   // scheme `://`
    "/etc/passwd",                                // absolute path
    "./config",                                   // relative path
    "../secrets",                                 // parent path
    "${{ secrets.TOKEN }}",                       // GitHub Actions expression
    "{{ cookiecutter.x }}",                       // template var
    "${HOME}",                                    // shell var
    "(?i)foo",                                    // regex source
    "^prefix",                                    // regex anchor
    "ssh-ed25519 AAAAC3",                         // SSH public key
    "ecdsa-sha2-nistp256 AAAA",                   // SSH ECDSA key
    "eyJab.cdef.ghij",                            // 3-segment JWT (eyJ + exactly 2 dots)
    "$ANSIBLE_VAULT;1.1;AES256",                  // ansible-vault envelope
    "ENC[AES256_GCM,data:x]",                     // jasypt/sops ENC envelope
    "-----BEGIN RSA PRIVATE KEY-----",            // PEM block
    "Agxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", // sealed-secret `Ag` + len > 40
    "age1qzexample",                              // age recipient
    "vault:v1/secret",                            // vault path
    "AQICAHhabc",                                 // AWS KMS ciphertext blob
    "CiQAoabc",                                   // GCP KMS ciphertext blob
    "C:\\Users\\me",                              // Windows drive path (backslash)
    "D:/data/key",                                // Windows drive path (forward slash)
    "```json",                                    // markdown code fence
    "---",                                        // yaml/markdown rule
    "===",                                        // markdown heading underline
];

const ACCEPTED: &[&str] = &[
    "AKIAIOSFODNN7EXAMPLE", // a real key shape, no reject prefix
    "ghp_16C7e42F292c6912E7710c838347Ae178B4a", // GitHub PAT, no reject prefix
    "eyJonly.onedot",       // eyJ but only ONE dot -> not a JWT
    "Agshort",              // `Ag` but length <= 40 -> not sealed
];

#[test]
fn every_universal_rejection_class_rejects() {
    for &value in REJECTED {
        assert!(
            rejects(value),
            "{value:?} must be rejected by the universal-rejection gate"
        );
    }
}

#[test]
fn plausible_secrets_and_near_misses_are_not_rejected() {
    for &value in ACCEPTED {
        assert!(
            !rejects(value),
            "{value:?} must NOT be rejected (it carries no universal-rejection prefix)"
        );
    }
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin one example per class; these SWEEP the source-backed
// rules. Every rejection rule EXCEPT the JWT/PEM structural checks is MONOTONIC
// under suffix-append (a prefix-list `starts_with`, the `://` `contains`, the
// `Ag`+len>40 gate, and the drive-path byte prefix are all preserved when text is
// appended). So: (1) any string containing `://` is rejected; (2) a `X:\`/`X:/`
// drive prefix is rejected; (3) `Ag`+over-40 is rejected; (4) any already-rejected
// non-JWT/non-PEM value stays rejected under an arbitrary suffix. Traced against
// entropy/plausibility.rs:135. No proptest before.

use proptest::prelude::*;

/// Rejected examples whose rejection is MONOTONIC under append (prefix-list / `://`
/// / `Ag` / drive-path rules), excludes the JWT and PEM entries, whose structural
/// checks can flip when text is appended.
const SUFFIX_STABLE_REJECTED: &[&str] = &[
    "https://example.com/path",
    "/etc/passwd",
    "./config",
    "../secrets",
    "${{ secrets.TOKEN }}",
    "{{ cookiecutter.x }}",
    "${HOME}",
    "(?i)foo",
    "^prefix",
    "ssh-ed25519 AAAAC3",
    "ecdsa-sha2-nistp256 AAAA",
    "$ANSIBLE_VAULT;1.1;AES256",
    "ENC[AES256_GCM,data:x]",
    "age1qzexample",
    "vault:v1/secret",
    "AQICAHhabc",
    "CiQAoabc",
    "```json",
    "---",
    "===",
];

/// Drive-path separators (`X:\…` / `X:/…`).
const DRIVE_SEPARATORS: &[char] = &['\\', '/'];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// Any string containing the scheme separator `://` is rejected (URLs), no
    /// matter what surrounds it.
    #[test]
    fn a_scheme_separator_anywhere_is_rejected(
        pre in "[A-Za-z0-9]{0,12}",
        post in "[A-Za-z0-9/._-]{0,20}",
    ) {
        let value = format!("{pre}://{post}");
        prop_assert!(rejects(&value));
    }

    /// A Windows drive-path prefix (`{letter}:{\\|/}…`) is rejected.
    #[test]
    fn a_windows_drive_path_is_rejected(
        drive in "[A-Za-z]",
        s in 0usize..DRIVE_SEPARATORS.len(),
        rest in "[A-Za-z0-9\\\\/._-]{0,20}",
    ) {
        let value = format!("{drive}:{}{rest}", DRIVE_SEPARATORS[s]);
        prop_assert!(rejects(&value));
    }

    /// An `Ag`-prefixed value longer than 40 chars is rejected (sealed-secret).
    #[test]
    fn ag_prefixed_over_forty_chars_is_rejected(body in "[A-Za-z0-9]{39,80}") {
        let value = format!("Ag{body}");
        prop_assert!(value.len() > 40);
        prop_assert!(rejects(&value));
    }

    /// A rejection from a prefix / `://` / `Ag` / drive rule survives ANY appended
    /// suffix (those rules are monotonic under append).
    #[test]
    fn rejection_is_stable_under_suffix(
        i in 0usize..SUFFIX_STABLE_REJECTED.len(),
        suffix in "(?s).{0,20}",
    ) {
        let base = SUFFIX_STABLE_REJECTED[i];
        prop_assert!(rejects(base), "base {:?} must reject", base);
        let extended = format!("{base}{suffix}");
        prop_assert!(rejects(&extended), "{:?} must stay rejected", extended);
    }
}
