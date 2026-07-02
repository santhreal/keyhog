//! SARIF artifact URI helpers.

use crate::winpath::is_windows_absolute;
use std::sync::OnceLock;

/// Render a filesystem path as a SARIF v2.1.0 `artifactLocation.uri`.
///
/// GitHub code-scanning (and most SARIF consumers) map alerts to repository
/// files by a REPO-RELATIVE uri. keyhog records absolute paths internally, so
/// an absolute path under the scan root - which is the repository root when
/// the GitHub Action runs `keyhog scan` from the checkout - is rendered
/// RELATIVE: `/repo/src/x.env` -> `src/x.env`. A bare `file://` absolute uri
/// uploads fine but never resolves against the checkout, so alerts would not
/// annotate the PR (the entire point of code-scanning). Paths that are already
/// relative are kept; absolute paths outside the scan root fall back to a
/// `file://` uri so they are at least unambiguous.
pub(crate) fn file_path_to_sarif_uri(path: &str) -> String {
    if let Some(rel) = relative_to_scan_root(path) {
        return render_relative_uri(&rel);
    }
    if path.starts_with('/') {
        format!("file://{}", percent_encode_path(path))
    } else if is_windows_absolute(path) {
        let normalised = path.replace('\\', "/");
        format!("file:///{}", percent_encode_path(&normalised))
    } else {
        // Already relative - percent-encode so spaces/specials stay valid.
        render_relative_uri(path)
    }
}

/// Percent-encode a repo-relative path for a SARIF `artifactLocation.uri`, then
/// disambiguate the leading-colon case. Per RFC 3986 §4.2 a relative-path
/// reference whose FIRST segment contains a `:` is indistinguishable from an
/// absolute URI with a scheme — `a:b.env` parses as scheme `a`, opaque part
/// `b.env`, so a consumer like GitHub code-scanning never resolves it against the
/// checkout and the alert is dropped or mis-mapped. Colons are legal in POSIX
/// filenames, so this is reachable from a real scan. Prefix such a path with
/// `./` (a no-op dot-segment) to force the colon to stay inside a path segment.
/// A colon in a LATER segment (`dir/a:b`) is already unambiguous and passes
/// through unchanged, as does the colon-free common case.
fn render_relative_uri(rel: &str) -> String {
    let encoded = percent_encode_path(rel);
    if first_segment_has_colon(&encoded) {
        format!("./{encoded}")
    } else {
        encoded
    }
}

/// True when the path segment before the first `/` (or the whole reference, if
/// there is no `/`) contains a `:` — the RFC 3986 §4.2 scheme-ambiguity trigger.
fn first_segment_has_colon(uri: &str) -> bool {
    match uri.split_once('/') {
        Some((first, _)) => first.contains(':'),
        None => uri.contains(':'),
    }
}

/// The scan root (process CWD), cached. SARIF is rendered once per run, after
/// the scan, from the same working directory the scan executed in.
fn scan_root() -> Option<&'static std::path::Path> {
    static ROOT: OnceLock<Option<std::path::PathBuf>> = OnceLock::new();
    // When the CWD is unreadable we return `None`, and `file_path_to_sarif_uri`
    // then emits an unambiguous absolute `file://` URI instead of a repo-relative
    // one (documented in that fn). The degradation is VISIBLE in the SARIF output
    // (absolute scheme), never a swallowed failure that loses a finding.
    ROOT.get_or_init(|| std::env::current_dir().ok()).as_deref() // LAW10: CWD-unreadable -> visible absolute file:// URI, no finding lost
}

/// If `path` is absolute and lives under the scan root, return it relative to
/// that root (forward-slashed). `None` when `path` is already relative or is
/// absolute but outside the scan root.
fn relative_to_scan_root(path: &str) -> Option<String> {
    if !path.starts_with('/') && !is_windows_absolute(path) {
        return None; // already relative; caller keeps it as-is
    }
    relative_to(path, scan_root()?)
}

/// Pure form: if absolute `path` lives under `root`, return it relative to
/// `root` (forward-slashed); `None` otherwise. Exposed for testing the
/// code-scanning relativization without depending on the process CWD.
pub(crate) fn relative_to(path: &str, root: &std::path::Path) -> Option<String> {
    let normalised = path.replace('\\', "/");
    std::path::Path::new(&normalised)
        .strip_prefix(root)
        .ok() // LAW10: malformed input => None (fail-closed at the boundary), recall-safe
        .map(|r| r.to_string_lossy().replace('\\', "/"))
}

/// Add the GitHub code-scanning rule properties that (a) map keyhog's severity
/// to an alert band and (b) categorize the rule as a security finding.
///
/// `security-severity` (a "0.0".."10.0" string) is what code-scanning reads to
/// set the alert's Critical/High/Medium/Low in the Security tab; without it
/// every keyhog alert shows a flat default severity, breaking triage. The
/// `security` tag files the rule under security alerts. GitHub bands:
/// >=9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.
pub(crate) fn apply_code_scanning_props(
    props: &mut serde_json::Map<String, serde_json::Value>,
    severity: crate::Severity,
) {
    let score = code_scanning_security_severity(severity);
    props.insert(
        "security-severity".to_string(),
        serde_json::Value::String(score.to_string()),
    );
    props.insert(
        "tags".to_string(),
        serde_json::Value::Array(vec![serde_json::Value::String("security".to_string())]),
    );
}

pub(crate) fn code_scanning_security_severity(severity: crate::Severity) -> &'static str {
    use crate::Severity as S;
    match severity {
        S::Critical => "9.5",
        S::High => "8.0",
        S::Medium => "5.0",
        S::Low => "2.0",
        S::ClientSafe => "1.0",
        S::Info => "0.0",
    }
}

/// Build the SARIF `partialFingerprints` map for a finding's credential hash,
/// the stable identity GitHub code-scanning uses to dedup alerts across runs.
/// The raw 32-byte hash is hex-encoded here, at the reporter boundary (the
/// `Finding` stores raw bytes - see `finding.rs`). An all-zero hash is the
/// "no credential identity" sentinel and yields `None`.
pub(crate) fn credential_fingerprints(
    credential_hash: crate::CredentialHash,
) -> Option<std::collections::BTreeMap<String, String>> {
    if credential_hash.is_zero() {
        return None;
    }
    let mut fp = std::collections::BTreeMap::new();
    fp.insert(
        "keyhog/credentialHash/v1".to_string(),
        crate::finding::hex_encode(credential_hash),
    );
    Some(fp)
}

fn percent_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for byte in path.bytes() {
        let safe =
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/' | b':');
        if safe {
            out.push(byte as char);
        } else {
            out.push('%');
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0F) as usize] as char);
        }
    }
    out
}
