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
