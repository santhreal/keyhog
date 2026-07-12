//! Adversarial property tier for the hosted-git input validators (reached via
//! the `SourceTestApi` facade). These are the crown-jewel security gates of the
//! github/gitlab/bitbucket org-scan flows:
//!
//!   * `validate_repo_name` — a repo/segment name is joined onto a temp dir
//!     (`temp_root.join(&repo.name)`); a `/`, `\`, or `..` would let a
//!     compromised API response write OUTSIDE the sandbox (path traversal).
//!   * `validate_org_name` — an org/user name is interpolated into the GitHub
//!     API URL path; a `/ ? # : @` or control byte would restructure the request.
//!   * `validate_clone_url` — a clone URL is handed to `git`; a non-`https://`
//!     scheme (`ext::`, `ssh://`, `file://`, `git://`) is a remote-code-execution
//!     gadget in git's transport negotiation, and an off-origin host / embedded
//!     credential / query / fragment is an exfil or confusion vector.
//!
//! The fixed-vector twins (`regression_github_org_name_validation`,
//! `unit/a5_lr2/gh_repo_*`, `gh_clone_*`, `unit/gates/hosted_git_security_
//! contract`) pin a handful of hostile inputs. This file SWEEPS the reject/accept
//! boundary over generated inputs, so a validator loosened in a refactor (a new
//! allowed char, a dropped scheme check) fails here on a shape nobody hand-wrote.
//! Every assertion states a contract the source code actually enforces — the
//! accept cases use inputs the validator MUST pass, the reject cases inputs it
//! MUST refuse, and the accept cases additionally re-derive the security
//! invariant (no separator / no non-github origin) from the accepted value.
//!
//! Gated on `feature = "github"`: the github facade validators delegate to the
//! same `hosted_git::validate_repo_name` / `validate_clone_url_for_origin` the
//! gitlab/bitbucket flows use, so this covers the shared core logic. Runs in the
//! all-features `--test all_tests` CI step (gated at `property/mod.rs`).

use keyhog_sources::testing::{SourceTestApi, TestApi};
use proptest::prelude::*;

/// Characters OUTSIDE the repo-name alphabet `[A-Za-z0-9._-]`, each of which
/// must force a rejection. Includes the traversal/separator bytes, URL and shell
/// structural punctuation, whitespace, and a control byte.
const REPO_FORBIDDEN_CHARS: &[char] = &[
    '/', '\\', ' ', '\t', '\n', '?', '#', ':', '@', '&', '|', '<', '>', '^', '%', '$', '*', '(',
    ')', '!', '"', '\'', '`', ';', ',', '=', '+', '~', '\0',
];

/// Non-`https` transport schemes git would honour — the RCE / off-transport
/// gadgets `validate_clone_url` exists to refuse. Each is spelled without
/// whitespace so it reaches (and fails) the scheme check rather than the earlier
/// whitespace guard.
const RCE_SCHEME_URLS: &[&str] = &[
    "ext::sh",
    "ext::rev",
    "ssh://git@github.com/o/r.git",
    "file:///etc/passwd",
    "git://github.com/o/r.git",
    "http://github.com/o/r.git",
    "ftp://github.com/o/r.git",
    "javascript:alert(1)",
    "fd::17/foo",
    "ext::git-remote-ext",
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3_000))]

    /// A repo name containing a path separator (`/` or `\`) is ALWAYS refused:
    /// this is the `temp_root.join(name)` sandbox-escape guard.
    #[test]
    fn repo_name_with_a_separator_is_always_rejected(
        head in "[A-Za-z0-9._-]{0,20}",
        sep in prop::sample::select(vec!['/', '\\']),
        tail in "[A-Za-z0-9._-]{0,20}",
    ) {
        let name = format!("{head}{sep}{tail}");
        prop_assert!(
            TestApi.validate_repo_name(&name).is_err(),
            "separator-bearing repo name {name:?} was accepted"
        );
    }

    /// A repo name carrying ANY out-of-alphabet character is refused — the
    /// allow-list is the whole defense, so a single smuggled structural byte
    /// (URL, shell, whitespace, NUL) must break validation.
    #[test]
    fn repo_name_with_out_of_alphabet_char_is_rejected(
        head in "[A-Za-z0-9._-]{0,20}",
        bad in prop::sample::select(REPO_FORBIDDEN_CHARS),
        tail in "[A-Za-z0-9._-]{0,20}",
    ) {
        let name = format!("{head}{bad}{tail}");
        prop_assert!(
            TestApi.validate_repo_name(&name).is_err(),
            "repo name {name:?} with forbidden char {bad:?} was accepted"
        );
    }

    /// The dot-only traversal names and the length bounds are refused; every
    /// other in-alphabet name is accepted AND, being accepted, provably cannot
    /// enable traversal (no separator, not a `.`/`..` self/parent ref).
    #[test]
    fn repo_name_accepts_clean_and_accepted_names_cannot_traverse(
        name in "[A-Za-z0-9._-]{1,100}",
    ) {
        let result = TestApi.validate_repo_name(&name);
        if name == "." || name == ".." {
            prop_assert!(result.is_err(), "dot-traversal name {name:?} was accepted");
        } else {
            prop_assert!(result.is_ok(), "clean name {name:?} rejected: {:?}", result.err());
            // Security invariant the acceptance guarantees for `temp_root.join`:
            prop_assert!(!name.contains('/') && !name.contains('\\'));
            prop_assert!(name != "." && name != "..");
        }
    }

    /// Over-length repo names (>100) are refused regardless of content.
    #[test]
    fn repo_name_over_length_is_rejected(name in "[A-Za-z0-9._-]{101,140}") {
        prop_assert!(
            TestApi.validate_repo_name(&name).is_err(),
            "{}-char repo name was accepted", name.len()
        );
    }

    /// An org name is accepted only for the GitHub alphabet (`[A-Za-z0-9-]`, no
    /// leading/trailing hyphen, <=39). An accepted name therefore carries no URL
    /// path/query structural byte, so `list_repos` cannot be steered off-path.
    #[test]
    fn org_name_accepts_clean_and_accepted_names_are_url_path_safe(
        stem in "[A-Za-z0-9]{1,20}",
        with_interior_hyphen in any::<bool>(),
        suffix in "[A-Za-z0-9]{1,10}",
    ) {
        let name = if with_interior_hyphen {
            format!("{stem}-{suffix}")
        } else {
            stem.clone()
        };
        prop_assert!(
            TestApi.validate_org_name(&name).is_ok(),
            "clean org name {name:?} rejected: {:?}",
            TestApi.validate_org_name(&name).err()
        );
        // The acceptance guarantees the name cannot restructure the API URL.
        for c in ['/', '?', '#', ':', '@', ' ', '.', '_', '\\'] {
            prop_assert!(!name.contains(c), "accepted org {name:?} contains structural {c:?}");
        }
    }

    /// Org names with a leading/trailing hyphen, an out-of-alphabet char, or
    /// over-length are refused.
    #[test]
    fn org_name_rejects_hyphen_edges_and_structural_chars(
        stem in "[A-Za-z0-9]{1,20}",
        bad in prop::sample::select(vec!['/', '?', '#', ':', '@', ' ', '.', '_', '\\', '\0']),
    ) {
        // Build every candidate in a `let` first: a `format!` placed directly
        // inside a bare `prop_assert!(cond)` is re-tokenized by the macro and its
        // arguments are dropped, so the names must be materialised beforehand.
        let leading_hyphen = format!("-{stem}");
        let trailing_hyphen = format!("{stem}-");
        let with_bad_char = format!("{stem}{bad}x");
        let over_length = "a".repeat(40);
        // Leading and trailing hyphen (a `-`-led name is a CLI-flag shape).
        prop_assert!(TestApi.validate_org_name(&leading_hyphen).is_err());
        prop_assert!(TestApi.validate_org_name(&trailing_hyphen).is_err());
        // Any structural / out-of-alphabet character.
        prop_assert!(
            TestApi.validate_org_name(&with_bad_char).is_err(),
            "org name with {bad:?} was accepted"
        );
        // Over-length (40 > 39).
        prop_assert!(TestApi.validate_org_name(&over_length).is_err());
    }

    /// Every non-`https` transport scheme is refused — the RCE guard. Combined
    /// with a generated clean github path so the scheme is the sole reason.
    #[test]
    fn clone_url_rejects_non_https_transport_schemes(idx in 0..RCE_SCHEME_URLS.len()) {
        let url = RCE_SCHEME_URLS[idx];
        prop_assert!(
            TestApi.validate_clone_url(url).is_err(),
            "non-https transport URL {url:?} was accepted (RCE vector)"
        );
    }

    /// Off-origin hosts, embedded credentials, query, fragment, and Windows
    /// command metacharacters on an otherwise-https URL are all refused.
    #[test]
    fn clone_url_rejects_off_origin_and_structural_hostile_forms(
        owner in "[A-Za-z0-9]{1,15}",
        repo in "[A-Za-z0-9]{1,15}",
    ) {
        let hostile = [
            format!("https://evil.example/{owner}/{repo}.git"),
            format!("https://github.com.evil.example/{owner}/{repo}.git"),
            format!("https://notgithub.com/{owner}/{repo}.git"),
            format!("https://github.com:8443/{owner}/{repo}.git"),
            format!("https://user:pass@github.com/{owner}/{repo}.git"),
            format!("https://tok@github.com/{owner}/{repo}.git"),
            format!("https://github.com/{owner}/{repo}.git?x=1"),
            format!("https://github.com/{owner}/{repo}.git#frag"),
            format!("https://github.com/{owner}&{repo}.git"),
            format!("https://github.com/{owner}|{repo}.git"),
        ];
        for url in hostile {
            prop_assert!(
                TestApi.validate_clone_url(&url).is_err(),
                "hostile clone URL {url:?} was accepted"
            );
        }
    }

    /// A clean `https://github.com/<owner>/<repo>.git` is accepted; and any
    /// accepted URL re-parses to https + host github.com + no userinfo (the
    /// safety invariant the whole validator exists to guarantee to `git`).
    #[test]
    fn clone_url_accepts_clean_github_https_and_accepted_is_safe(
        owner in "[A-Za-z0-9]{1,20}",
        repo in "[A-Za-z0-9]{1,20}",
    ) {
        let url = format!("https://github.com/{owner}/{repo}.git");
        prop_assert!(
            TestApi.validate_clone_url(&url).is_ok(),
            "clean github clone URL {url:?} rejected: {:?}",
            TestApi.validate_clone_url(&url).err()
        );
        // Independently confirm the accepted URL is exactly the safe shape.
        let parsed = reqwest::Url::parse(&url).expect("accepted URL parses");
        prop_assert_eq!(parsed.scheme(), "https");
        prop_assert_eq!(parsed.host_str(), Some("github.com"));
        prop_assert!(parsed.username().is_empty() && parsed.password().is_none());
        prop_assert!(parsed.query().is_none() && parsed.fragment().is_none());
    }
}
