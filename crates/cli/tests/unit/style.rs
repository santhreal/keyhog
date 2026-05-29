//! Palette TTY / NO_COLOR resolution.
//!
//! Moved out of `src/style.rs` per the `no_inline_tests_in_src` gate: tests
//! live under `tests/`, not in `#[cfg(test)]` modules inside production
//! source. `Palette` and its `resolve`/`ANSI`/`PLAIN` surface are already
//! `pub`, so the move needs no visibility change.

use keyhog::style::Palette;

#[test]
fn color_only_on_tty_without_no_color() {
    assert_eq!(Palette::resolve(true, false), Palette::ANSI);
    assert_eq!(Palette::resolve(true, false).green, "\x1b[32m");
}

#[test]
fn no_color_forces_plain_even_on_a_tty() {
    assert_eq!(Palette::resolve(true, true), Palette::PLAIN);
}

#[test]
fn non_tty_is_plain() {
    // The common pipe/redirect case: `keyhog doctor > out.txt` must not
    // embed escape sequences.
    assert_eq!(Palette::resolve(false, false), Palette::PLAIN);
    assert_eq!(Palette::resolve(false, false).reset, "");
}
