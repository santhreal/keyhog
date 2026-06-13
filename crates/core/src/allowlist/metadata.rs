//! Allowlist inline metadata parsing.

use super::InlineMetadata;

pub(super) fn parse_inline_metadata(s: &str) -> InlineMetadata {
    let mut meta = InlineMetadata::default();
    for token in s.split(';') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let Some(eq) = token.find('=') else { continue };
        let key = token[..eq].trim();
        let value = token[eq + 1..]
            .trim()
            .trim_matches(|c: char| c == '"' || c == '\'')
            .to_string();
        match key {
            "reason" => meta.reason = Some(value),
            "expires" => meta.expires = Some(value),
            "approved_by" => meta.approved_by = Some(value),
            _ => {
                tracing::warn!("unknown allowlist metadata key '{key}' (ignored)");
            }
        }
    }
    meta
}

pub(super) fn log_metadata_audit(kind: &str, entry: &str, meta: &InlineMetadata) {
    if meta.reason.is_none() && meta.approved_by.is_none() && meta.expires.is_none() {
        return;
    }
    tracing::info!(
        kind,
        entry,
        reason = meta.reason.as_deref().unwrap_or("<unspecified>"),
        approved_by = meta.approved_by.as_deref().unwrap_or("<unspecified>"),
        expires = meta.expires.as_deref().unwrap_or("<no expiry>"),
        "allowlist entry loaded with audit metadata"
    );
}

/// Returns today's date as `YYYY-MM-DD` UTC, computed from
/// `SystemTime::now()`. Hand-rolled to avoid pulling chrono into core.
pub(super) fn today_yyyy_mm_dd() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    // Civil-from-days, after Howard Hinnant.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i64::from(m <= 2);
    format!("{year:04}-{m:02}-{d:02}")
}
