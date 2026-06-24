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
    terminal_palette(
        std::io::stdout().is_terminal(),
        std::env::var_os("NO_COLOR").is_some(),
    )
}

pub(crate) fn for_stderr() -> Palette {
    terminal_palette(
        std::io::stderr().is_terminal(),
        std::env::var_os("NO_COLOR").is_some(),
    )
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
    writeln!(
        w,
        "{} {} {}{} {:?}{}  {}",
        prefix, detector_id, file_path, line_str, severity, conf_str, credential_redacted
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyhog_core::Severity;

    #[test]
    fn test_write_diagnostic_finding_with_confidence_and_line() {
        let mut buf = Vec::new();
        write_diagnostic_finding(
            &mut buf,
            "FINDING",
            "detector_1",
            "src/main.rs",
            Some(42),
            Severity::Critical,
            Some(0.95),
            "redacted_secret",
        )
        .expect("diagnostic finding should write to in-memory buffer");
        let s = String::from_utf8(buf).expect("diagnostic output must be utf-8");
        assert_eq!(
            s,
            "FINDING detector_1 src/main.rs:42 Critical (0.95)  redacted_secret\n"
        );
    }

    #[test]
    fn test_write_diagnostic_finding_no_confidence_no_line() {
        let mut buf = Vec::new();
        write_diagnostic_finding(
            &mut buf,
            "WATCH",
            "detector_2",
            "src/lib.rs",
            None,
            Severity::Medium,
            None,
            "redacted_other",
        )
        .expect("diagnostic finding should write to in-memory buffer");
        let s = String::from_utf8(buf).expect("diagnostic output must be utf-8");
        assert_eq!(s, "WATCH detector_2 src/lib.rs Medium  redacted_other\n");
    }
}
