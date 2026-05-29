pub mod baseline;
pub mod cli_misc;
// daemon module + wire tests are unix-only (Unix-domain sockets).
#[cfg(unix)]
pub mod daemon_wire;
pub mod file_gate;
pub mod format;
pub mod gates;
pub mod installer;
pub mod orchestrator;
pub mod orchestrator_config;
pub mod path_validation;
pub mod sources;
pub mod style;
pub mod subcommands_detectors;
pub mod subcommands_explain;
pub mod test_fixture_suppressions;
pub mod value_parsers;
