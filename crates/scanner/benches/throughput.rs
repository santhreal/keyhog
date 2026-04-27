//! Comprehensive benchmark harness for keyhog-scanner.
//!
//! Tracks throughput, latency, and memory characteristics to detect regressions.
//! Run with: cargo bench -p keyhog-scanner

include!("throughput_cases/fixtures.rs");
include!("throughput_cases/throughput.rs");
include!("throughput_cases/latency.rs");
include!("throughput_cases/memory.rs");
include!("throughput_cases/pipeline.rs");
include!("throughput_cases/pem.rs");
include!("throughput_cases/groups.rs");
