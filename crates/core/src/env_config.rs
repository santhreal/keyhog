//! Shared environment-variable parsing for numeric KeyHog knobs.
//!
//! These helpers are deliberately stderr-visible. Numeric env vars usually
//! affect timeouts, routing, or worker sizing; malformed values must not vanish
//! into defaults without telling the operator what actually ran.

use std::env::VarError;

/// Read a `usize` env var, requiring `value >= min`, or return `default`.
///
/// Missing variables use `default` quietly. Malformed, non-UTF-8, or too-small
/// values print one stderr line and then use `default`.
pub fn usize_at_least_or_default(name: &str, min: usize, default: usize) -> usize {
    match std::env::var(name) {
        Ok(raw) => match raw.parse::<usize>() {
            Ok(value) if value >= min => value,
            _ => {
                warn_default(name, Some(&raw), min, default);
                default
            }
        },
        Err(VarError::NotPresent) => default,
        Err(VarError::NotUnicode(_)) => {
            warn_default(name, None, min, default);
            default
        }
    }
}

/// Read a `u64` env var, requiring `value >= min`, or return `default`.
///
/// Missing variables use `default` quietly. Malformed, non-UTF-8, or too-small
/// values print one stderr line and then use `default`.
pub fn u64_at_least_or_default(name: &str, min: u64, default: u64) -> u64 {
    match std::env::var(name) {
        Ok(raw) => match raw.parse::<u64>() {
            Ok(value) if value >= min => value,
            _ => {
                warn_default(name, Some(&raw), min, default);
                default
            }
        },
        Err(VarError::NotPresent) => default,
        Err(VarError::NotUnicode(_)) => {
            warn_default(name, None, min, default);
            default
        }
    }
}

/// Read an optional `u64` env var, requiring `value >= min`.
///
/// Missing variables return `None` quietly. Malformed, non-UTF-8, or too-small
/// values print one stderr line and then return `None`.
pub fn optional_u64_at_least(name: &str, min: u64) -> Option<u64> {
    match std::env::var(name) {
        Ok(raw) => match raw.parse::<u64>() {
            Ok(value) if value >= min => Some(value),
            _ => {
                warn_ignored(name, Some(&raw), min);
                None
            }
        },
        Err(VarError::NotPresent) => None,
        Err(VarError::NotUnicode(_)) => {
            warn_ignored(name, None, min);
            None
        }
    }
}

fn warn_default<T: std::fmt::Display>(name: &str, raw: Option<&str>, min: T, default: T) {
    match raw {
        Some(raw) => eprintln!(
            "keyhog: invalid {name}={raw:?}; expected an integer >= {min}; using {default}"
        ),
        None => eprintln!(
            "keyhog: invalid non-UTF-8 {name}; expected an integer >= {min}; using {default}"
        ),
    }
}

fn warn_ignored<T: std::fmt::Display>(name: &str, raw: Option<&str>, min: T) {
    match raw {
        Some(raw) => {
            eprintln!("keyhog: invalid {name}={raw:?}; expected an integer >= {min}; ignoring")
        }
        None => {
            eprintln!("keyhog: invalid non-UTF-8 {name}; expected an integer >= {min}; ignoring")
        }
    }
}
