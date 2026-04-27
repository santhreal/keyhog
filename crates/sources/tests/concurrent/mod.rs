//! Concurrent-iteration tests for source backends.
//!
//! Multiple sources iterating in parallel must not corrupt shared state
//! (interner caches, walker thread pool, ziftsieve internals).

mod parallel_filesystem;
