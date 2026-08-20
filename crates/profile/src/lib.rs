//! Record causal performance evidence for one KeyHog run.
//!
//! Start a [`Session`] at the beginning of the production operation. Record
//! macro state changes with [`Session::transition`]. Wrap measured work in
//! [`span`], then call [`Session::finish`] to produce a versioned [`RunProfile`].
//!
//! ```
//! use keyhog_profile::{RunIdentity, RunState, Session, Stage, span};
//!
//! let identity = RunIdentity::new(
//!     "0.5.49",
//!     "detector-digest",
//!     "config-digest",
//!     "filesystem",
//!     "small-text",
//!     "auto",
//! );
//! let mut session = Session::start(identity).expect("start profile");
//! session.transition(RunState::Scanning);
//! {
//!     let _read = span(Stage::SourceRead);
//!     std::hint::black_box(42);
//! }
//! let profile = session.finish(RunState::Completed);
//!
//! assert_eq!(profile.status, RunState::Completed);
//! assert_eq!(profile.stages[0].stage, Stage::SourceRead);
//! assert_eq!(profile.stages[0].calls, 1);
//! ```
//!
//! # Runtime ownership
//!
//! A session owns an isolated [`Runtime`]. The session enters that runtime on
//! the calling thread. Propagate a clone explicitly when work crosses a thread
//! boundary. This keeps concurrent runs isolated.
//!
//! ```
//! use keyhog_profile::{RunIdentity, RunState, Session, Stage, span};
//!
//! let identity = RunIdentity::new("0.5.49", "d", "c", "stdin", "stream", "auto");
//! let session = Session::start(identity).expect("start profile");
//! let runtime = session.runtime();
//! std::thread::spawn(move || runtime.scope(|| {
//!     let _scan = span(Stage::BackendDispatch);
//! }))
//! .join()
//! .expect("join worker");
//! let profile = session.finish(RunState::Completed);
//! assert_eq!(profile.stages[0].stage, Stage::BackendDispatch);
//! ```
//!
//! # Recording cost
//!
//! The disabled span path checks one relaxed atomic and does not read the clock.
//! Enabled spans update fixed atomic counters indexed by [`MetricId`]. They do
//! not allocate, hash metric names, or format text. Vector construction, JSON
//! serialization, and report analysis run only when counters are drained or a
//! session is finished.
//!
//! `cargo bench -p keyhog-profile --bench overhead_budget` enforces absolute
//! median budgets for disabled checks, aggregate spans, and causal spans. The
//! regular CI workflow runs this gate with an optimized benchmark build.
//!
//! # Metrics and collectors
//!
//! [`METRICS`] is the static registry for metric names, kinds, and units. A
//! collector implements [`SnapshotCollector`] and reports a
//! [`CollectorCapability`] before sampling. The default `process-metrics`
//! feature samples process CPU time, resident memory, virtual memory, and thread
//! count. Disable default features when you need stage timing without platform
//! process sampling. The profile then reports the collector as disabled instead
//! of silently emitting unavailable measurements.
//!
//! # Persisted records
//!
//! [`PROFILE_SCHEMA`] identifies the profile envelope. Every persisted component
//! also carries its own numeric version. Missing component versions decode as
//! version one for compatibility with early records. Compare identity fields,
//! collector capabilities, workload state, and metric units before comparing
//! measurements from two profiles.
//!
//! # Privacy
//!
//! The profiler records counts, durations, run identity, execution choices, and
//! process resources. Do not use source content, credentials, raw URLs, or
//! sensitive paths as identity labels. [`RunProfile::render_text`] and
//! [`RunProfile::to_json_pretty`] serialize the labels supplied by the caller.

mod allocation;
mod analysis;
mod collector;
mod comparison;
mod config;
mod detail;
mod hardware;
mod host_parallelism;
mod identity;
pub mod insight;
mod metrics;
mod resources;
mod runtime;
mod schema;
mod schema_v2;
mod session;
mod system;

mod api;
pub use api::*;
