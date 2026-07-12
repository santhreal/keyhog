//! Allowlist inline metadata parsing.

use std::time::{SystemTime, UNIX_EPOCH};

use super::InlineMetadata;

pub(super) fn parse_inline_metadata(s: &str) -> InlineMetadata {
    let mut meta = InlineMetadata::default();
    let parsed = metadata_tokens(s);
    if let Some(quote) = parsed.unterminated_quote {
        meta.malformed_tokens
            .push(format!("unterminated {quote} quote in metadata trailer"));
    }
    for token in parsed.tokens {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let Some(eq) = token.find('=') else {
            meta.malformed_tokens
                .push(format!("metadata token `{token}` is missing `=`"));
            continue;
        };
        let key = token[..eq].trim();
        let value = unquote_metadata_value(token[eq + 1..].trim());
        match key {
            "reason" => {
                assign_unique_field(&mut meta.reason, key, value, &mut meta.malformed_tokens)
            }
            "expires" => {
                assign_unique_field(&mut meta.expires, key, value, &mut meta.malformed_tokens)
            }
            "approved_by" => assign_unique_field(
                &mut meta.approved_by,
                key,
                value,
                &mut meta.malformed_tokens,
            ),
            _ => {
                meta.unknown_keys.push(key.to_string());
            }
        }
    }
    meta
}

/// Assign a metadata field, refusing a silent override on a repeated key
/// (Law 10). A duplicate is recorded as a malformed token so `load` fails the
/// scan closed rather than quietly keeping whichever `reason`/`expires`/
/// `approved_by` happened to come last.
fn assign_unique_field(
    field: &mut Option<String>,
    key: &str,
    value: String,
    malformed: &mut Vec<String>,
) {
    if field.is_some() {
        malformed.push(format!(
            "duplicate metadata key `{key}`; specify it at most once per entry"
        ));
    } else {
        *field = Some(value);
    }
}

struct MetadataTokens<'a> {
    tokens: Vec<&'a str>,
    unterminated_quote: Option<char>,
}

fn metadata_tokens(s: &str) -> MetadataTokens<'_> {
    let mut tokens = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let mut escaped = false;
    for (idx, ch) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote.is_some() && ch == '\\' {
            escaped = true;
            continue;
        }
        match (quote, ch) {
            (Some(active), current) if active == current => quote = None,
            (None, '"' | '\'') => quote = Some(ch),
            (None, ';') => {
                tokens.push(&s[start..idx]);
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    tokens.push(&s[start..]);
    MetadataTokens {
        tokens,
        unterminated_quote: quote,
    }
}

/// Strip one layer of matching quotes and unescape the `\"`, `\'`, `\\`
/// sequences that `metadata_tokens` honored while splitting, so a quoted
/// `reason="a\"b"` yields `a"b` rather than the literal `a\"b`. Backslashes
/// before any other character stay literal (shell-style), matching the
/// tokenizer's escape rule.
fn unquote_metadata_value(value: &str) -> String {
    let bytes = value.as_bytes();
    let quoted = bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''));
    if !quoted {
        return value.to_string();
    }
    let inner = &value[1..value.len() - 1];
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some(escaped @ ('"' | '\'' | '\\')) => out.push(escaped),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

pub(super) fn log_metadata_audit(kind: &str, entry: &str, meta: &InlineMetadata) {
    if meta.reason.is_none() && meta.approved_by.is_none() && meta.expires.is_none() {
        return;
    }
    tracing::info!(
        kind,
        entry,
        reason = meta.reason.as_deref().unwrap_or("<unspecified>"), // LAW10: log-display placeholder for an optional audit field; no recall/security effect
        approved_by = meta.approved_by.as_deref().unwrap_or("<unspecified>"), // LAW10: log-display placeholder; optional field
        expires = meta.expires.as_deref().unwrap_or("<no expiry>"), // LAW10: log-display placeholder; optional field
        "allowlist entry loaded with audit metadata"
    );
}

pub(super) fn try_today_days_since_epoch() -> Result<i64, String> {
    days_since_epoch(SystemTime::now())
}

pub(super) fn days_since_epoch_for_test(now: SystemTime) -> Result<i64, String> {
    days_since_epoch(now)
}

fn days_since_epoch(now: SystemTime) -> Result<i64, String> {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            format!(
                "system clock is before UNIX_EPOCH ({error}); fix host time before loading allowlist suppressions"
            )
        })?
        .as_secs();
    let secs = i64::try_from(secs).map_err(|error| {
        format!("system clock value is too large to enforce allowlist expiry ({error})")
    })?;
    Ok(secs.div_euclid(86_400))
}

pub(super) fn yyyy_mm_dd_from_days(days: i64) -> String {
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

pub(super) fn parse_yyyy_mm_dd_days(input: &str) -> Option<i64> {
    let bytes = input.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    // 4-digit year is always in `0..=9999`, so it shares the `u32` digit
    // accumulator with month/day (one owner) and widens to `i64` for the civil
    // arithmetic below.
    let year = i64::from(parse_fixed_u32(&bytes[0..4])?);
    let month = parse_fixed_u32(&bytes[5..7])?;
    let day = parse_fixed_u32(&bytes[8..10])?;
    if !(1..=12).contains(&month) {
        return None;
    }
    if day == 0 || day > days_in_month(year, month) {
        return None;
    }
    Some(days_from_civil(year, month, day))
}

fn parse_fixed_u32(bytes: &[u8]) -> Option<u32> {
    let mut value = 0u32;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value * 10 + u32::from(byte - b'0');
    }
    Some(value)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = year - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = i64::from(month);
    let d = i64::from(day);
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}
