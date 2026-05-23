#![allow(unsafe_code)]

//! Benchmark runner library surface for the vyre engine.
//!
//! Provides the core CLI parse hooks, registry integration,
//! regression monitoring, and release matrices.

use vyre_driver_cuda as _;
use vyre_driver_reference as _;
use vyre_driver_spirv as _;
use vyre_driver_wgpu as _;

/// API definitions for external benchmark drivers.
#[allow(missing_docs)]
pub mod api;
/// Reference test cases and standard regression suites.
#[allow(missing_docs)]
pub mod cases;
/// Command-line interface definition and argument parsing.
#[allow(missing_docs)]
pub mod cli;
/// Evolutionary solver benchmarks and auto-tuners.
#[allow(missing_docs)]
pub mod evolve;
/// Target device capability and telemetry probes.
#[allow(missing_docs)]
pub mod probes;
/// The benchmark registry and metadata catalog.
#[allow(missing_docs)]
pub mod registry;
/// Parity release matrix verification logic.
#[allow(missing_docs)]
pub mod release_matrix;
/// HTML/Markdown report formatting and artifact writing.
#[allow(missing_docs)]
pub mod report;
/// Context and thread coordination for the test runner.
#[allow(missing_docs)]
pub mod runner;
