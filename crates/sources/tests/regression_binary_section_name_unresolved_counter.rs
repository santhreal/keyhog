//! LANE close-law10 regression: the binary section-name partial-parse counter
//! (`BINARY_SECTION_NAME_UNRESOLVED`) is a real, resettable, public coverage
//! signal — NOT a silent drop.
//!
//! Before the fix, `extract_sections` resolved every ELF/PE/Mach-O section name
//! with `unwrap_or("")`: a corrupt section-name string table silently produced
//! an empty name, and because `""` is never a high-value target section, a
//! `.rodata`/`.data`/`__cstring` blob that may hold embedded secrets vanished
//! from the scan with no trace (Law 10 false-clean). The fix bumps this counter
//! at every name-resolution failure and surfaces it in the end-of-scan summary
//! and SARIF notifications.
//!
//! This test pins the public plumbing: the field exists in `SkipCounts`, starts
//! at zero, and is cleared by `reset_skip_counters`. The per-format bump logic is
//! unit-tested directly against `resolve_section_name` inside
//! `crates/sources/src/binary/sections.rs`.

#![cfg(feature = "binary")]

use keyhog_sources::{skip_counts, testing::reset_skip_counters};

#[test]
fn binary_section_name_unresolved_is_a_public_resettable_counter() {
    reset_skip_counters();
    let c = skip_counts();
    assert_eq!(
        c.binary_section_name_unresolved, 0,
        "after reset the partial-parse counter must read exactly 0"
    );

    // It is deliberately a SECTION-level partial-coverage signal, so it must NOT
    // be folded into the file-skip `total()` (which counts whole-file skips).
    // total() sums only the five whole-file categories; an unresolved section is
    // surfaced as its own line, not as a skipped file.
    assert_eq!(
        c.total(),
        0,
        "a freshly-reset SkipCounts has a zero file-skip total"
    );
}
