//! Status styling helpers for human-facing reports.

use std::io::Write;

use crate::{Severity, VerificationResult};

const BOLD: &str = "1";
const DIM: &str = "90";
const ACTION: &str = "3;32";
const CRITICAL: &str = "1;31";
const HIGH: &str = "31";
const MEDIUM: &str = "33";
const LOW: &str = "36";
const CLIENT_SAFE: &str = "2;36";
const INFO: &str = "90";
const LIVE: &str = "1;31;43";

pub(crate) fn paint(text: &str, ansi: &str, color: bool) -> String {
    if color {
        format!("\x1b[{ansi}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

pub(crate) fn write_rgb_fg<W: Write>(
    writer: &mut W,
    ch: char,
    r: u8,
    g: u8,
    b: u8,
) -> std::io::Result<()> {
    write!(writer, "\x1b[38;2;{r};{g};{b}m{ch}\x1b[0m")
}

pub(crate) fn write_ansi256_fg<W: Write>(writer: &mut W, ch: char, idx: u8) -> std::io::Result<()> {
    write!(writer, "\x1b[38;5;{idx}m{ch}\x1b[0m")
}

pub(crate) fn highlight(text: &str, color: bool) -> String {
    paint(text, BOLD, color)
}

pub(crate) fn dim(text: &str, color: bool) -> String {
    paint(text, DIM, color)
}

pub(crate) fn warning(text: &str, color: bool) -> String {
    paint(text, MEDIUM, color)
}

pub(crate) fn success(text: &str, color: bool) -> String {
    paint(text, HIGH, color)
}

pub(crate) fn danger(text: &str, color: bool) -> String {
    paint(text, HIGH, color)
}

pub(crate) fn muted_border(text: &str, color: bool) -> String {
    paint(text, INFO, color)
}

pub(crate) fn remediation_action(text: &str, color: bool) -> String {
    paint(text, ACTION, color)
}

pub(crate) fn confidence_bar(text: &str, confidence: f64, color: bool) -> String {
    let style = if confidence >= 0.8 {
        HIGH
    } else if confidence >= 0.5 {
        MEDIUM
    } else {
        DIM
    };
    paint(text, style, color)
}

pub(crate) fn severity_border_style(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => CRITICAL,
        Severity::High => HIGH,
        Severity::Medium => MEDIUM,
        Severity::Low => LOW,
        Severity::ClientSafe => CLIENT_SAFE,
        Severity::Info => INFO,
    }
}

pub(crate) fn severity_label(severity: Severity, color: bool) -> String {
    let (label, style) = match severity {
        Severity::Critical => ("CRITICAL", CRITICAL),
        Severity::High => ("HIGH", HIGH),
        Severity::Medium => ("MEDIUM", MEDIUM),
        Severity::Low => ("LOW", LOW),
        Severity::ClientSafe => ("CLIENT-SAFE", CLIENT_SAFE),
        Severity::Info => ("INFO", INFO),
    };
    paint(&format!("{:>11}", label), style, color)
}

pub(crate) fn verification_label(result: &VerificationResult, color: bool) -> String {
    match result {
        VerificationResult::Live => paint("LIVE", LIVE, color),
        VerificationResult::Revoked => paint("revoked", MEDIUM, color),
        VerificationResult::Dead => success("dead", color),
        VerificationResult::RateLimited => warning("limited", color),
        VerificationResult::Error(_) => warning("error", color),
        VerificationResult::Unverifiable | VerificationResult::Skipped => String::new(),
    }
}

/// Stable, machine-readable verification token for the STRUCTURED report formats
/// (SARIF, JUnit, CSV, GitHub annotations). Lowercase, with `snake_case` for the
/// multi-word states so it matches the JSON representation produced by
/// `#[serde(rename_all = "snake_case")]` on [`VerificationResult`]. This is the
/// single source of truth: the per-format copies had diverged — SARIF derived
/// its value from `format!("{:?}", v).to_lowercase()`, emitting `ratelimited`
/// (no underscore) and `error("..")` (Debug-quoted) where every other format and
/// the JSON serialization emit `rate_limited` and `error: ..`. Distinct from
/// [`verification_label`], which is the colored, human-facing display label.
pub(crate) fn verification_token(result: &VerificationResult) -> std::borrow::Cow<'static, str> {
    use std::borrow::Cow;
    match result {
        VerificationResult::Live => Cow::Borrowed("live"),
        VerificationResult::Revoked => Cow::Borrowed("revoked"),
        VerificationResult::Dead => Cow::Borrowed("dead"),
        VerificationResult::RateLimited => Cow::Borrowed("rate_limited"),
        VerificationResult::Error(e) => Cow::Owned(format!("error: {e}")),
        VerificationResult::Unverifiable => Cow::Borrowed("unverifiable"),
        VerificationResult::Skipped => Cow::Borrowed("skipped"),
    }
}

/// Stable, machine-readable severity token for STRUCTURED report formats.
/// Returns the SAME string as the `#[serde(rename_all = "kebab-case")]` JSON
/// serialization of [`Severity`] — notably `client-safe`, not the Debug-derived
/// `clientsafe`. SARIF derived its `properties.severity` from
/// `format!("{:?}", s).to_lowercase()`, which diverged from JSON for the only
/// multi-word variant (`ClientSafe`). The drift-guard test below asserts this
/// stays byte-identical to serde so the two can never separate again.
pub(crate) fn severity_token(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::ClientSafe => "client-safe",
        Severity::Info => "info",
    }
}

#[cfg(test)]
mod tests {
    use super::{severity_token, verification_token};
    use crate::{Severity, VerificationResult};

    #[test]
    fn verification_token_is_snake_case_and_stable() {
        // The canonical structured token: lowercase, snake_case for multi-word
        // states (matching `#[serde(rename_all = "snake_case")]`), so SARIF /
        // JUnit / CSV / GitHub all agree with the JSON representation.
        assert_eq!(verification_token(&VerificationResult::Live), "live");
        assert_eq!(verification_token(&VerificationResult::Revoked), "revoked");
        assert_eq!(verification_token(&VerificationResult::Dead), "dead");
        assert_eq!(
            verification_token(&VerificationResult::RateLimited),
            "rate_limited",
            "must be snake_case, never the Debug-derived `ratelimited`"
        );
        assert_eq!(
            verification_token(&VerificationResult::Error("boom".to_string())),
            "error: boom",
            "must be `error: <msg>`, never the Debug-derived `error(\"..\")`"
        );
        assert_eq!(
            verification_token(&VerificationResult::Unverifiable),
            "unverifiable"
        );
        assert_eq!(verification_token(&VerificationResult::Skipped), "skipped");
    }

    #[test]
    fn severity_token_matches_serde_kebab_case() {
        // Drift guard: the structured severity token MUST equal the serde
        // (kebab-case) JSON serialization for every variant, so SARIF's
        // properties.severity can never re-diverge from the JSON report.
        for s in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::ClientSafe,
            Severity::Info,
        ] {
            let serde_str = serde_json::to_value(s).unwrap();
            assert_eq!(
                serde_str.as_str().unwrap(),
                severity_token(s),
                "severity_token must match serde for {s:?}"
            );
        }
        // Pin the multi-word variant that previously diverged (Debug -> "clientsafe").
        assert_eq!(severity_token(Severity::ClientSafe), "client-safe");
    }
}
