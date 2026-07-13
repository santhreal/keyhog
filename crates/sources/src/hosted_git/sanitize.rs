use regex::Regex;
use std::sync::atomic::{AtomicU64, Ordering};

/// Number of times a redaction regex failed to compile and the sanitizer
/// therefore refused to emit the credential-bearing git stderr.
pub(crate) static REDACTION_COMPILE_FAILURES: AtomicU64 = AtomicU64::new(0);

const REDACTION_FAILED_PLACEHOLDER: &str =
    "<git error suppressed: a credential-redaction pattern failed to compile; \
     raw stderr withheld to avoid leaking secrets>";

pub(crate) fn sanitize_git_error_message(stderr: &str) -> String {
    use std::sync::OnceLock;

    static URL_CRED_RE: OnceLock<Result<Regex, String>> = OnceLock::new();
    static AUTH_HEADER_RE: OnceLock<Result<Regex, String>> = OnceLock::new();
    static TOKEN_RE: OnceLock<Result<Regex, String>> = OnceLock::new();

    // `[^/\s]+@` (not `[^/@\s]+@`): the userinfo runs to the LAST `@` before the
    // path `/` or whitespace, so a git basic-auth password carrying a literal
    // `@` (`https://user:pa@ss@host/…`: git surfaces raw stderr even though RFC
    // 3986 says `@` should be percent-encoded) is redacted WHOLE. The former
    // `[^/@\s]+` stopped at the FIRST `@`, redacting only `user:pa@` and leaking
    // the `ss@host` tail, the same first-`@`-vs-last-`@` leak `url_redaction.rs`
    // fixes with `rfind`. The `/`-exclusion still confines the match to the
    // authority so a later `@` in the path is never treated as a userinfo end.
    let url_cred =
        URL_CRED_RE.get_or_init(|| compile_redaction_regex(r"([a-z][a-z0-9+\-.]*://)([^/\s]+)@"));
    let auth_header = AUTH_HEADER_RE
        .get_or_init(|| compile_redaction_regex(r"(?i)(authorization:\s*(?:basic|bearer)\s+)\S+"));
    let token_pat = TOKEN_RE.get_or_init(|| {
        compile_redaction_regex(r"(?:ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}|glpat-[A-Za-z0-9_-]{20,64}|glrt-[A-Za-z0-9_-]{16,64}|gldt-[A-Za-z0-9_-]{16,64}|glcbt-[A-Za-z0-9_-]{16,64}|xoxb-[A-Za-z0-9-]{24,}|xoxp-[A-Za-z0-9-]{24,}|sk-proj-[A-Za-z0-9_-]{24,}|sk_live_[A-Za-z0-9]{24,}|sk_test_[A-Za-z0-9]{24,}|AKIA[0-9A-Z]{16})")
    });

    let url_cred = regex_result_as_option(url_cred);
    let auth_header = regex_result_as_option(auth_header);
    let token_pat = regex_result_as_option(token_pat);

    redact_with(stderr, url_cred, auth_header, token_pat)
}

fn compile_redaction_regex(pattern: &str) -> Result<Regex, String> {
    Regex::new(pattern).map_err(|error| error.to_string())
}

fn regex_result_as_option(result: &Result<Regex, String>) -> Option<&Regex> {
    match result {
        Ok(regex) => Some(regex),
        Err(_error) => None,
    }
}

pub(crate) fn redact_with(
    stderr: &str,
    url_cred: Option<&Regex>,
    auth_header: Option<&Regex>,
    token_pat: Option<&Regex>,
) -> String {
    let (Some(url_cred), Some(auth_header), Some(token_pat)) = (url_cred, auth_header, token_pat)
    else {
        REDACTION_COMPILE_FAILURES.fetch_add(1, Ordering::Relaxed);
        eprintln!(
            "keyhog: SECURITY - a git-error credential-redaction regex failed to \
             compile; refusing to surface raw git stderr"
        );
        return REDACTION_FAILED_PLACEHOLDER.to_string();
    };

    let mut result = url_cred.replace_all(stderr, "${1}<redacted>@").into_owned();
    result = auth_header
        .replace_all(&result, "${1}<redacted>")
        .into_owned();
    result = token_pat
        .replace_all(&result, "<redacted-token>")
        .into_owned();
    result.trim().to_string()
}

#[cfg(test)]
pub(crate) const REDACTION_FAILED_PLACEHOLDER_FOR_TEST: &str = REDACTION_FAILED_PLACEHOLDER;

#[cfg(test)]
mod tests {
    use super::*;

    fn live_patterns() -> (Regex, Regex, Regex) {
        (
            Regex::new(r"([a-z][a-z0-9+\-.]*://)([^/\s]+)@").unwrap(),
            Regex::new(r"(?i)(authorization:\s*(?:basic|bearer)\s+)\S+").unwrap(),
            Regex::new(r"(?:ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}|glpat-[A-Za-z0-9_-]{20,64}|glrt-[A-Za-z0-9_-]{16,64}|gldt-[A-Za-z0-9_-]{16,64}|glcbt-[A-Za-z0-9_-]{16,64}|xoxb-[A-Za-z0-9-]{24,}|xoxp-[A-Za-z0-9-]{24,}|sk-proj-[A-Za-z0-9_-]{24,}|sk_live_[A-Za-z0-9]{24,}|sk_test_[A-Za-z0-9]{24,}|AKIA[0-9A-Z]{16})").unwrap(),
        )
    }

    fn redact(stderr: &str) -> String {
        let (u, a, t) = live_patterns();
        redact_with(stderr, Some(&u), Some(&a), Some(&t))
    }

    #[test]
    fn redacts_every_credential_shape() {
        let token36 = "0123456789abcdefghijklmnopqrstuvwxyz";
        let github_pat = format!("github_pat_{}_{}", "A".repeat(22), "B".repeat(59));
        let ghp = format!("ghp_{token36}");
        let gho = format!("gho_{token36}");
        let glpat = "glpat-aB3kQp7VbT2hYRzNcMfW";
        let url_msg = format!("fatal: could not read from https://alice:{ghp}@github.com/x/y.git");
        let auth_msg = "remote: Authorization: Bearer sk_live_supersecrettokenvalue00000000";
        let xoxb = "xoxb-1111111111-2222222222-aBcDeFgHiJkLmNoPqRsTuVwX";
        let akia = "fatal: leaked AKIA1234567890ABCDEF in remote output";
        let gho_msg = format!("clone failed: {gho}");
        let pat_msg = format!("token={github_pat}");
        let gitlab_msg = format!("fatal: token {glpat}");

        let cases: &[(&str, &[&str], &str)] = &[
            (
                url_msg.as_str(),
                &[ghp.as_str(), "alice"],
                "<redacted>@github.com",
            ),
            (
                auth_msg,
                &["sk_live_supersecrettokenvalue00000000"],
                "Authorization: Bearer <redacted>",
            ),
            (xoxb, &[xoxb], "<redacted-token>"),
            (akia, &["AKIA1234567890ABCDEF"], "<redacted-token>"),
            (gho_msg.as_str(), &[gho.as_str()], "<redacted-token>"),
            (pat_msg.as_str(), &[github_pat.as_str()], "<redacted-token>"),
            (gitlab_msg.as_str(), &[glpat], "<redacted-token>"),
        ];

        for (input, must_not_contain, must_contain) in cases {
            let out = redact(input);
            for secret in *must_not_contain {
                assert!(
                    !out.contains(secret),
                    "credential `{secret}` leaked through redaction of {input:?}: got {out:?}"
                );
            }
            assert!(
                out.contains(must_contain),
                "expected {must_contain:?} in redacted output of {input:?}, got {out:?}"
            );
        }
    }

    #[test]
    fn url_credential_exact_output() {
        let ghp = format!("ghp_{}", "z".repeat(36));
        let input = format!("fatal: unable to access https://bob:{ghp}@github.com/o/r.git/");
        let out = redact(&input);
        assert_eq!(
            out,
            "fatal: unable to access https://<redacted>@github.com/o/r.git/"
        );
    }

    #[test]
    fn missing_pattern_fails_closed_and_counts() {
        let (u, a, t) = live_patterns();
        let secret = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let stderr = format!("fatal: https://x:{secret}@github.com leaked");
        let nones: [(Option<&Regex>, Option<&Regex>, Option<&Regex>); 3] = [
            (None, Some(&a), Some(&t)),
            (Some(&u), None, Some(&t)),
            (Some(&u), Some(&a), None),
        ];

        for (i, (pu, pa, pt)) in nones.into_iter().enumerate() {
            let before = REDACTION_COMPILE_FAILURES.load(Ordering::SeqCst);
            let out = redact_with(&stderr, pu, pa, pt);
            let after = REDACTION_COMPILE_FAILURES.load(Ordering::SeqCst);

            assert_eq!(out, REDACTION_FAILED_PLACEHOLDER_FOR_TEST, "case {i}");
            assert!(!out.contains(secret), "case {i}: secret leaked");
            assert_eq!(after - before, 1, "case {i}: counter delta");
        }
    }

    #[test]
    fn embedded_at_in_password_redacts_whole_userinfo() {
        // A basic-auth password containing a literal `@`: the userinfo runs to
        // the LAST `@` before the path, so the redaction must swallow the whole
        // `alice:pa@ss` and never leave the `ss@github.com` tail in the log. The
        // pre-fix `[^/@\s]+` stopped at the first `@` and leaked `ss`.
        let out = redact("fatal: could not read from https://alice:pa@ss@github.com/x/y.git");
        assert_eq!(
            out,
            "fatal: could not read from https://<redacted>@github.com/x/y.git"
        );
        assert!(
            !out.contains("pa@ss") && !out.contains("ss@github"),
            "password containing an `@` leaked its tail: {out}"
        );
    }

    #[test]
    fn embedded_at_without_path_still_redacts_userinfo() {
        // No path segment: whitespace (or end of the authority) bounds the
        // greedy userinfo match, so `u:se@cret` is still redacted whole and the
        // host survives.
        let out = redact("fatal: unable to access https://u:se@cret@example.org still failing");
        assert_eq!(
            out,
            "fatal: unable to access https://<redacted>@example.org still failing"
        );
        assert!(!out.contains("se@cret"), "userinfo tail leaked: {out}");
    }

    #[test]
    fn at_in_path_is_not_treated_as_userinfo_boundary() {
        // The `/`-exclusion confines the userinfo match to the authority: an `@`
        // that appears only in the PATH (after the first `/`) must NOT trigger a
        // spurious `<redacted>@` rewrite of the host.
        let out = redact("fatal: remote https://github.com/org/repo@v1.2.3 not found");
        assert_eq!(
            out,
            "fatal: remote https://github.com/org/repo@v1.2.3 not found"
        );
    }

    #[test]
    fn benign_message_unchanged() {
        let out = redact("  fatal: repository not found  ");
        assert_eq!(out, "fatal: repository not found");
    }
}
