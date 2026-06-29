//! Gap test: the universal-rejection prefix gate's exact reject/accept table.
//!
//! `matches_universal_rejection` is the first gate in the entropy plausibility
//! checks — it drops candidates that are obviously not free-standing secrets:
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
