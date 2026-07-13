//! Loud, recall-preserving degradation for static prefilter automata (Law 10).
//!
//! keyhog's keyword/regex *prefilters* (the multiline keyword gate, the
//! generic-assignment value bridge, the Caesar rotated-prefix gate, …) are all
//! built from **compile-time-constant** literal/regex sources. `AhoCorasick::new`
//! / `Regex::new` failing on them is therefore not an expected runtime condition
//!, it is a build-invariant violation. The historical handling was to swallow
//! the error (`.ok()` → `None`) and let the consumer fall back to its safe path
//! (scan the chunk unconditionally / try every shift). That preserves recall but
//! does so **silently**: an operator would never learn a prefilter had turned
//! itself off, masking either a real regression or a silent performance cliff.
//! Law 10 forbids the *silent* part, not the recall-preserving fallback itself.
//!
//! Call [`warn_prefilter_disabled`] from the failing `LazyLock` initializer. A
//! `LazyLock` runs its initializer exactly once, so the warning fires exactly
//! once per process while the consumer keeps its recall-preserving behavior. This
//! matches the loud `keyhog: …` stderr channel used by the GPU degrade path
//! (`engine::gpu_forced`).

use std::fmt::Display;

/// Emit one loud stderr line when a static, build-from-constant prefilter
/// automaton fails to compile. `site` names the prefilter for the operator;
/// `err` is the underlying build error.
///
/// The caller is expected to keep its recall-preserving fallback (scan the
/// chunk unconditionally, try every shift, …): this surfaces the degradation,
/// it does not change behavior.
pub(crate) fn warn_prefilter_disabled(site: &str, err: &dyn Display) {
    eprintln!(
        "keyhog: PREFILTER DISABLED [{site}]: built-from-constant automaton failed to compile \
({err}). Falling back to the unconditional scan path, recall is preserved, but the prefilter \
no longer prunes work, so this scan and every later one in this process run slower. This is a \
build-invariant violation (the pattern source is compile-time constant); please report it."
    );
}
