mod support;

pub mod adversarial;
pub mod concurrent;
pub mod contract;
pub mod gap;
pub mod gate;
pub mod integration;
pub mod property;
pub mod regression;
pub mod unit;

// NOTE: keyhog-sources deliberately keeps many top-level `tests/*.rs` files OUT
// of this aggregator, they assert on the process-global skip counters and are
// designed as their own test binaries so a per-test fixture can reset those
// atomics without racing sibling source tests in the same process (see e.g.
// `regression_pdf_coverage_gaps_counted.rs`). Those standalone targets are run
// in their own process (counter-safe by construction) by the
// `sources opt-in backends (all standalone targets, serial)` CI step
// (`cargo test -p keyhog-sources` with no `--test` filter). `tests_wired.py`
// treats a crate covered by such an all-targets step as fully wired.
