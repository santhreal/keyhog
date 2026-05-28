//! KH-GAP-043 SPEC waiver: megakernel parity oracle is waived until expiry.

use std::path::PathBuf;

const WAIVER_REL: &str = "spec_waivers/megakernel_literal_set_parity.toml";

fn waiver_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(WAIVER_REL)
}

fn parse_waiver_expiry() -> Option<chrono::NaiveDate> {
    let raw = std::fs::read_to_string(waiver_path()).ok()?;
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

/// True while the on-disk SPEC waiver is present and not past `expires`.
pub fn megakernel_parity_waiver_active() -> bool {
    if !waiver_path().exists() {
        return false;
    }
    let Some(expiry) = parse_waiver_expiry() else {
        return false;
    };
    let today = chrono::Utc::now().date_naive();
    today <= expiry
}

/// True when `KEYHOG_USE_MEGAKERNEL` is still a no-op in engine sources.
pub fn megakernel_env_unwired_in_engine() -> bool {
    let engine_dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine"));
    for entry in std::fs::read_dir(engine_dir).expect("engine dir readable") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("engine source readable");
        if src.contains("KEYHOG_USE_MEGAKERNEL") {
            return false;
        }
    }
    true
}
