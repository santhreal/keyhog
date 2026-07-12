#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the hand-rolled PDF text extractor in `keyhog-sources`: `(...)` literal
// string parsing (with balanced-paren depth + `\` escapes + octal escapes),
// `<...>` hex string parsing, `<<>>` dictionary skipping, FlateDecode stream
// inflate, and the dictionary-window boundary search. This is the reachable
// target when a user scans an ATTACKER-SUPPLIED `.pdf`, so the oracle is the
// strongest robustness contract: for ANY input bytes the extractor must never
// panic, slice out of bounds, or hang. A crash here is a real DoS/robustness
// bug (untrusted document -> scanner abort). `keyhog_sources::fuzz_extract_pdf_text`
// is compiled only under `--cfg fuzzing` (this crate), so it is not production
// API surface.
fuzz_target!(|data: &[u8]| {
    // 10 MiB decode budget mirrors a realistic `--max-file-size` ceiling; the
    // per-stream inflate cap must keep a decompression bomb bounded regardless
    // of this figure.
    let _ = keyhog_sources::fuzz_extract_pdf_text(data, 10 * 1024 * 1024);
});
