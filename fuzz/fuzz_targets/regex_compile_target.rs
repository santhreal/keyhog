//! Detector-regex compiler fuzz.
//!
//! Goal: a malformed user-supplied regex in a detector TOML must
//! return `Err`, never panic. The detector set is user-extensible
//! (drop a TOML into `detectors/` and keyhog picks it up), so any
//! panic in the regex compile path is reachable from valid user
//! input and counts as a release-blocking bug.

#![no_main]

use keyhog_core::PatternSpec;
use keyhog_scanner::compiler::compile_pattern;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The fuzzer input becomes the regex string. Restrict to valid
    // UTF-8 (regex source is `&str`).
    let Ok(regex) = std::str::from_utf8(data) else {
        return;
    };
    // Bound pattern length: real detector regexes top out around 500
    // chars; a 100 KiB regex tells us nothing useful about the
    // compiler's panic surface.
    if regex.len() > 2048 {
        return;
    }
    let spec = PatternSpec {
        regex: regex.to_string(),
        description: None,
        group: None,
        // A fuzzed regex string has no client-safe semantics; `false` is
        // the neutral `#[serde(default)]` value.
        client_safe: false,
    };
    // Any outcome is acceptable EXCEPT panic. The Result branch is
    // discarded - we are not asserting which inputs compile, only
    // that the compiler is panic-free for every input shape.
    let _ = compile_pattern(0, 0, &spec, "fuzz-detector");
});
