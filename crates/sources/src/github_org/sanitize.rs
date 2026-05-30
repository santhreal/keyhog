use regex::Regex;

pub(super) fn sanitize_git_error_message(stderr: &str) -> String {
    use std::sync::OnceLock;

    static URL_CRED_RE: OnceLock<Option<Regex>> = OnceLock::new();
    static AUTH_HEADER_RE: OnceLock<Option<Regex>> = OnceLock::new();
    static TOKEN_RE: OnceLock<Option<Regex>> = OnceLock::new();

    let url_cred =
        URL_CRED_RE.get_or_init(|| Regex::new(r"([a-z][a-z0-9+\-.]*://)([^/@\s]+)@").ok());
    let auth_header = AUTH_HEADER_RE
        .get_or_init(|| Regex::new(r"(?i)(authorization:\s*(?:basic|bearer)\s+)\S+").ok());
    let token_pat = TOKEN_RE.get_or_init(|| {
        Regex::new(r"(?:ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}|xoxb-[A-Za-z0-9-]{24,}|xoxp-[A-Za-z0-9-]{24,}|sk-proj-[A-Za-z0-9_-]{24,}|sk_live_[A-Za-z0-9]{24,}|sk_test_[A-Za-z0-9]{24,}|AKIA[0-9A-Z]{16})").ok()
    });

    let mut result = stderr.to_string();
    if let Some(re) = url_cred {
        result = re.replace_all(&result, "${1}<redacted>@").into_owned();
    }
    if let Some(re) = auth_header {
        result = re.replace_all(&result, "${1}<redacted>").into_owned();
    }
    if let Some(re) = token_pat {
        result = re.replace_all(&result, "<redacted-token>").into_owned();
    }
    result.trim().to_string()
}
