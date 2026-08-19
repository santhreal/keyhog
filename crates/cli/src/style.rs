//! Terminal styling for CLI-only diagnostic subcommands.

use std::io::IsTerminal;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Palette {
    pub(crate) green: &'static str,
    pub(crate) red: &'static str,
    pub(crate) yellow: &'static str,
    pub(crate) cyan: &'static str,
    pub(crate) dim: &'static str,
    pub(crate) bold: &'static str,
    pub(crate) reset: &'static str,
}

const ANSI: Palette = Palette {
    green: "\x1b[32m",
    red: "\x1b[31m",
    yellow: "\x1b[33m",
    cyan: "\x1b[36m",
    dim: "\x1b[2m",
    bold: "\x1b[1m",
    reset: "\x1b[0m",
};

const PLAIN: Palette = Palette {
    green: "",
    red: "",
    yellow: "",
    cyan: "",
    dim: "",
    bold: "",
    reset: "",
};

pub(crate) fn terminal_palette(is_tty: bool, no_color: bool) -> Palette {
    if is_tty && !no_color {
        ANSI
    } else {
        PLAIN
    }
}

pub(crate) fn terminal_clear_line_prefix(is_tty: bool) -> &'static str {
    if is_tty {
        "\x1b[2K\r"
    } else {
        ""
    }
}

pub(crate) fn for_stdout() -> Palette {
    terminal_palette(std::io::stdout().is_terminal(), no_color_requested())
}

pub(crate) fn for_stderr() -> Palette {
    terminal_palette(std::io::stderr().is_terminal(), no_color_requested())
}

pub(crate) fn pass(label: &str, palette: &Palette) -> String {
    format!("{}{}{}", palette.green, label, palette.reset)
}

pub(crate) fn fail(label: &str, palette: &Palette) -> String {
    format!("{}{}{}", palette.red, label, palette.reset)
}

pub(crate) fn warn(label: &str, palette: &Palette) -> String {
    format!("{}{}{}", palette.yellow, label, palette.reset)
}

pub(crate) fn info(label: &str, palette: &Palette) -> String {
    format!("{}{}{}", palette.cyan, label, palette.reset)
}

// 24-bit truecolor severity / progress palette shared by the scan progress
// ticker and the completion severity/verification summary lines
// (`orchestrator::reporting`). Centralized here, the one CLI file exempt from
// the no-raw-ANSI-escape gate, so the orchestrator never embeds escape
// literals directly. Each is gated at its call site behind the ticker's `color`
// flag (TTY && !NO_COLOR), so piped / NO_COLOR output stays plain.
pub(crate) const SEV_BRAND: &str = "\x1b[38;2;255;214;10m";
pub(crate) const SEV_CRITICAL: &str = "\x1b[38;2;255;69;58m";
pub(crate) const SEV_HIGH: &str = "\x1b[38;2;255;159;10m";
pub(crate) const SEV_MEDIUM: &str = "\x1b[38;2;255;214;10m";
pub(crate) const SEV_LOW: &str = "\x1b[38;2;100;210;255m";
pub(crate) const SEV_SAFE: &str = "\x1b[38;2;48;209;88m";
pub(crate) const SEV_AMBER: &str = "\x1b[38;2;255;159;10m";
pub(crate) const SEV_RAIL: &str = "\x1b[38;2;74;74;82m";
pub(crate) const SEV_MUTED: &str = "\x1b[38;2;138;138;150m";
pub(crate) const SEV_BOLD: &str = "\x1b[1m";
pub(crate) const SEV_RESET: &str = "\x1b[0m";

/// Wrap `text` in `color_code` + reset when `color` is set, else return it
/// plain. The owned-style replacement for the orchestrator's former local
/// per-file colorizer, the deliberately distinct name keeps the no-raw-ANSI
/// gate's legacy-colorizer ban a true signal.
pub(crate) fn paint(text: String, color_code: &str, color: bool) -> String {
    if color {
        format!("{color_code}{text}{SEV_RESET}")
    } else {
        text
    }
}

/// Whether the operator requested no color via the `NO_COLOR` convention.
/// Centralized here (an env-read-allowlisted file) so call sites, e.g. the
/// orchestrator progress ticker, never read the environment directly.
///
/// Follows the [no-color.org](https://no-color.org) contract exactly: the
/// variable disables color only when it is present AND non-empty. An empty
/// `NO_COLOR=` (how a wrapper commonly clears an inherited value) must NOT
/// suppress color; `is_some()` alone would wrongly treat that as opt-out.
pub(crate) fn no_color_requested() -> bool {
    no_color_from_env(std::env::var_os("NO_COLOR").as_deref())
}

/// Pure no-color decision over a raw `NO_COLOR` value, split out so the
/// spec rule is unit-testable without mutating the process-global environment:
/// disable color iff the variable is present AND non-empty.
pub(crate) fn no_color_from_env(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|value| !value.is_empty())
}

/// Unified console finding output formatting for diagnostic/interactive CLI subcommands.
pub(crate) fn print_diagnostic_finding(
    prefix: &str,
    detector_id: &str,
    file_path: &str,
    line: Option<usize>,
    severity: keyhog_core::Severity,
    confidence: Option<f64>,
    credential_redacted: &str,
) -> std::io::Result<()> {
    let mut stdout = std::io::stdout();
    write_diagnostic_finding(
        &mut stdout,
        prefix,
        detector_id,
        file_path,
        line,
        severity,
        confidence,
        credential_redacted,
    )
}

/// Formats and writes a diagnostic finding to any generic writer (useful for unit testing).
pub(crate) fn write_diagnostic_finding<W: std::io::Write>(
    w: &mut W,
    prefix: &str,
    detector_id: &str,
    file_path: &str,
    line: Option<usize>,
    severity: keyhog_core::Severity,
    confidence: Option<f64>,
    credential_redacted: &str,
) -> std::io::Result<()> {
    let line_str = match line {
        Some(line) => format!(":{line}"),
        None => String::new(),
    };
    let conf_str = match confidence {
        Some(confidence) => format!(" ({confidence:.2})"),
        None => String::new(),
    };
    // Severity text comes from the one canonical table (`Severity::as_str`),
    // uppercased so watch / stream / scan all render severity identically.
    // `{:?}` here diverged for `ClientSafe` ("ClientSafe" vs "CLIENT-SAFE").
    writeln!(
        w,
        "{} {} {}{} {}{}  {}",
        prefix,
        detector_id,
        file_path,
        line_str,
        severity.as_str().to_uppercase(),
        conf_str,
        credential_redacted
    )
}

// Unit tests for this module live in `crates/cli/tests/unit/style.rs`, which
// white-box-includes this file via `#[path]` and can reach its private items
// (e.g. `no_color_from_env`, `ANSI`, `PLAIN`). No inline `#[cfg(test)] mod`
// block here: the `#[path]` include would try to resolve it as a source file
// and break, and the KH-GAP-004 gate forbids inline test blocks in src anyway.
