//! Shared SPEC waiver helpers for meta gap oracles.

use std::path::PathBuf;

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

pub fn spec_waiver_active(rel: &str) -> bool {
    let path = repo_root().join(rel);
    if !path.is_file() {
        return false;
    }
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return false;
    };
    let Some(expiry) = parse_expires(&raw) else {
        return false;
    };
    let today = chrono::Utc::now().date_naive();
    today <= expiry
}

fn parse_expires(raw: &str) -> Option<chrono::NaiveDate> {
    for line in raw.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("expires = ") {
            let date = rest.trim().trim_matches('"');
            return chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").ok();
        }
    }
    None
}
