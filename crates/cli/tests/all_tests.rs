// `adversarial` and `property` are NOT here: each is its own bounded test
// binary (`tests/adversarial.rs`, `tests/property.rs`). They were silently
// orphaned (empty mod.rs) and, for adversarial, each test spawns the keyhog
// binary — folding 75 of those into this already-large binary is the
// OOM-SIGKILL driver. Standalone binaries bound peak memory and link size.
pub mod concurrent;
pub mod contract;
pub mod dogfood;
pub mod e2e;
pub mod gap;
pub mod gate;
pub mod integration;
pub mod regression;
pub mod reliability;
pub mod stress;
pub mod unit;
