//! Terminal styling shared by the installer + diagnostic subcommands.
//!
//! Before this module the ANSI palette was copy-pasted into every subcommand
//! (`doctor`, `update`, `repair`, `uninstall`, ...), and none of those copies
//! checked whether output was actually going to a terminal. Piping `keyhog
//! doctor` to a file or reading it in a CI log produced raw `\x1b[32m`
//! escapes. [`Palette`] centralizes the codes and gates them on `NO_COLOR`
//! (<https://no-color.org/>) plus TTY detection, so redirected output is plain
//! text. The scan reporter already does this for findings; this brings the
//! command surface to parity.

use std::io::IsTerminal;

/// ANSI palette. Each field is the escape sequence when color is enabled, or
/// the empty string when it is disabled, so call sites interpolate them
/// unconditionally: `format!("{green}ok{reset}")` is correct either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Palette {
    pub green: &'static str,
    pub red: &'static str,
    pub yellow: &'static str,
    pub dim: &'static str,
    pub bold: &'static str,
    pub reset: &'static str,
}

impl Palette {
    /// Full-color palette.
    pub const ANSI: Self = Self {
        green: "\x1b[32m",
        red: "\x1b[31m",
        yellow: "\x1b[33m",
        dim: "\x1b[2m",
        bold: "\x1b[1m",
        reset: "\x1b[0m",
    };

    /// No-op palette: every field is empty, so styled output renders as plain
    /// text.
    pub const PLAIN: Self = Self {
        green: "",
        red: "",
        yellow: "",
        dim: "",
        bold: "",
        reset: "",
    };

    /// Palette for `stdout`: colored only when stdout is a TTY and `NO_COLOR`
    /// is unset.
    pub fn for_stdout() -> Self {
        Self::resolve(
            std::io::stdout().is_terminal(),
            std::env::var_os("NO_COLOR").is_some(),
        )
    }

    /// Resolve a palette from explicit signals. Color requires a TTY and the
    /// absence of `NO_COLOR`; split out from env/TTY lookup so it is unit
    /// testable without touching global state.
    pub fn resolve(is_tty: bool, no_color: bool) -> Self {
        if is_tty && !no_color {
            Self::ANSI
        } else {
            Self::PLAIN
        }
    }
}
