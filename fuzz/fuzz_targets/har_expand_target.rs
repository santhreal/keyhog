#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the HAR expander in `keyhog-sources`: `har_text` UTF-16/UTF-8 decoding,
// BOM/whitespace trimming, the HAR-marker sniff, serde_json parsing, and the
// request/response chunk rendering + base64 body compaction. This is the
// reachable target when a user scans an ATTACKER-SUPPLIED `.har`, so the oracle
// is "no panic / OOB / hang on ANY bytes". `keyhog_sources::fuzz_try_expand_har`
// is compiled only under `--cfg fuzzing`, so it is not production API surface.
fuzz_target!(|data: &[u8]| {
    // Small max_size so the per-HAR "4x expanded budget" defense is actually
    // exercised (a malicious HAR that inflates past the budget must be bounded).
    let _ = keyhog_sources::fuzz_try_expand_har(data, 64 * 1024);
});
