//! Cross-OS build contract: the `simd` backend must not reference Unix-only FFI
//! (`libc::geteuid`) outside a `#[cfg(unix)]` scope, or the DEFAULT build
//! (default features include `simd`) fails to compile on Windows — exactly the
//! regression this guards.
//!
//! `simd/backend.rs` previously called `unsafe { libc::geteuid() }`
//! unconditionally for cache-dir namespacing, so `cargo build` / `cargo install`
//! (default features) could not compile on the `*-pc-windows-*` targets. The fix
//! routes every uid read through `current_uid()`, which is `#[cfg(unix)]` →
//! `geteuid` and `#[cfg(not(unix))]` → a constant. hyperscan (a C++ dep) can't be
//! cross-compiled to Windows in CI here, so this source-shape gate is the
//! maintainable proxy for "the Rust in this module stays Windows-buildable".

use std::path::Path;

fn backend_src() -> String {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/simd/backend.rs");
    std::fs::read_to_string(&src).expect("read simd/backend.rs")
}

/// Strip `//` line comments so comment text mentioning the FFI never trips the
/// substring checks (the inline-test gate learned this the hard way).
fn code_only(text: &str) -> String {
    text.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn current_uid_has_both_platform_arms() {
    let code = code_only(&backend_src());
    let compact = code.replace(char::is_whitespace, "");
    // The Unix arm (real geteuid) and the non-Unix arm (constant) must BOTH be
    // present — that split is the entire fix.
    assert!(
        compact.contains("#[cfg(unix)]fncurrent_uid"),
        "missing the #[cfg(unix)] current_uid() arm (geteuid)"
    );
    assert!(
        compact.contains("#[cfg(not(unix))]fncurrent_uid"),
        "missing the #[cfg(not(unix))] current_uid() arm — the default Windows \
         build would fall back to an unconditional libc::geteuid()"
    );
}

#[test]
fn every_geteuid_call_is_cfg_unix_guarded() {
    let code = code_only(&backend_src());

    // Every `libc::geteuid()` call site must sit under a `#[cfg(unix)]` guard.
    // There are exactly two legitimate sites: the `current_uid()` Unix arm and
    // the `#[cfg(unix)]` ownership/permissions block. Each must be preceded by a
    // `#[cfg(unix)]` attribute within a small window of lines (the attribute that
    // guards its enclosing fn/block). A new UNGATED call (the regression) appears
    // with no `#[cfg(unix)]` above it and fails here.
    let lines: Vec<&str> = code.lines().collect();
    let mut sites = 0usize;
    let mut ungated: Vec<usize> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !line.contains("libc::geteuid") {
            continue;
        }
        sites += 1;
        // Look back up to 6 lines for the cfg(unix) guard of the enclosing item.
        let lo = i.saturating_sub(6);
        let guarded = lines[lo..i]
            .iter()
            .any(|l| l.replace(char::is_whitespace, "").contains("#[cfg(unix)]"));
        if !guarded {
            ungated.push(i + 1);
        }
    }

    assert!(
        sites >= 1,
        "expected at least one libc::geteuid() site (the current_uid Unix arm); \
         found none — did the helper move?"
    );
    assert!(
        ungated.is_empty(),
        "libc::geteuid() called without a #[cfg(unix)] guard at line(s) {ungated:?} \
         — this breaks the default Windows build. Route uid through current_uid()."
    );
}
