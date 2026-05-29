//! SARIF artifact URI helpers.

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
pub fn file_path_to_sarif_uri(path: &str) -> String {
    if let Some(rel) = relative_to_scan_root(path) {
        return percent_encode_path(&rel);
    }
    if path.starts_with('/') {
        format!("file://{}", percent_encode_path(path))
    } else if is_windows_absolute(path) {
        let normalised = path.replace('\\', "/");
        format!("file:///{}", percent_encode_path(&normalised))
    } else {
        // Already relative - percent-encode so spaces/specials stay valid.
        percent_encode_path(path)
    }
}

/// The scan root (process CWD), cached. SARIF is rendered once per run, after
/// the scan, from the same working directory the scan executed in.
fn scan_root() -> Option<&'static std::path::Path> {
    static ROOT: OnceLock<Option<std::path::PathBuf>> = OnceLock::new();
    ROOT.get_or_init(|| std::env::current_dir().ok()).as_deref()
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
pub fn relative_to(path: &str, root: &std::path::Path) -> Option<String> {
    let normalised = path.replace('\\', "/");
    std::path::Path::new(&normalised)
        .strip_prefix(root)
        .ok()
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
pub fn apply_code_scanning_props(
    props: &mut serde_json::Map<String, serde_json::Value>,
    severity: crate::Severity,
) {
    use crate::Severity as S;
    let score = match severity {
        S::Critical => "9.5",
        S::High => "8.0",
        S::Medium => "5.0",
        S::Low => "2.0",
        S::ClientSafe => "1.0",
        S::Info => "0.0",
    };
    props.insert(
        "security-severity".to_string(),
        serde_json::Value::String(score.to_string()),
    );
    props.insert(
        "tags".to_string(),
        serde_json::Value::Array(vec![serde_json::Value::String("security".to_string())]),
    );
}

/// Build the SARIF `partialFingerprints` map for a finding's credential hash,
/// the stable identity GitHub code-scanning uses to dedup alerts across runs.
/// An empty hash yields `None` (no stable identity to key on).
pub fn credential_fingerprints(
    credential_hash: &str,
) -> Option<std::collections::BTreeMap<String, String>> {
    if credential_hash.is_empty() {
        return None;
    }
    let mut fp = std::collections::BTreeMap::new();
    fp.insert(
        "keyhog/credentialHash/v1".to_string(),
        credential_hash.to_string(),
    );
    Some(fp)
}

fn is_windows_absolute(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'/' || b[2] == b'\\')
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
