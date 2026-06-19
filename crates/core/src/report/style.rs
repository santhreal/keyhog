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
