//! Runtime fallback/prefilter toggle overrides, extracted from `fallback.rs`.
//! Each toggle is an env-var default plus a process-global `AtomicU8` override
//! (0 = follow env, 1 = force on, 2 = force off) so a single differential test
//! can drive one input down both code paths. Pure env/atomic plumbing — no scan
//! state. Re-exported through `fallback` (`pub use super::fallback_toggles::*`),
//! so existing `fallback::set_*` / `fallback::*_enabled` paths are unchanged.
use std::sync::atomic::{AtomicU8, Ordering::Relaxed};
use std::sync::OnceLock;

/// Runtime override for the anchor enable flag: 0 = follow env, 1 = force on,
/// 2 = force off. Lets a differential test scan one input down BOTH the
/// anchored and whole-chunk fallback paths in a single process (the env read is
/// cached, so it alone can't be toggled mid-run).
static FALLBACK_ANCHOR_OVERRIDE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Override shared-anchor fallback localization (test/diagnostic). `Some(true)`
/// forces it on, `Some(false)` forces the legacy whole-chunk path, `None`
/// restores the env-driven default. Recall is identical either way — this only
/// selects the performance route, so it is safe to flip at runtime.
pub fn set_fallback_anchor_mode(mode: Option<bool>) {
    let v = match mode {
        None => 0,
        Some(true) => 1,
        Some(false) => 2,
    };
    FALLBACK_ANCHOR_OVERRIDE.store(v, Relaxed);
}

/// Runtime override for the homoglyph ASCII-gate (0=env, 1=on, 2=off). Lets a
/// validation test scan one input with the gate on and off to prove the
/// confirmed path covers every homoglyph variant's pure-ASCII matches.
static HOMOGLYPH_GATE_OVERRIDE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Override the homoglyph ASCII-gate (test/diagnostic). `Some(true)` forces it
/// on (skip homoglyph variants on pure-ASCII chunks), `Some(false)` forces
/// every homoglyph variant to run, `None` restores the default (on).
pub fn set_fallback_homoglyph_gate(mode: Option<bool>) {
    let v = match mode {
        None => 0,
        Some(true) => 1,
        Some(false) => 2,
    };
    HOMOGLYPH_GATE_OVERRIDE.store(v, Relaxed);
}

/// Whether the homoglyph ASCII-gate is enabled (default on). Set
/// `KEYHOG_HOMOGLYPH_GATE=0` (or `set_fallback_homoglyph_gate(Some(false))`) to
/// run every homoglyph variant on every chunk (the unoptimized path).
pub(crate) fn homoglyph_gate_enabled() -> bool {
    match HOMOGLYPH_GATE_OVERRIDE.load(Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_HOMOGLYPH_GATE").as_deref() != Ok("0"))
}

/// Runtime override for the homoglyph ASCII-SKIP (0=env, 1=on, 2=off).
static HOMOGLYPH_ASCII_SKIP_OVERRIDE: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(0);

/// Override the homoglyph ASCII-skip (test/diagnostic). `Some(true)` forces it
/// on, `Some(false)` off, `None` = env default. The differential gate
/// `homoglyph_ascii_skip_parity` flips this in-process to prove that skipping
/// every homoglyph variant on a pure-ASCII chunk drops no finding (the base
/// literal-prefix pattern is in the AC/confirmed path — see `compiler_build.rs`,
/// which pushes BOTH the homoglyph fallback variant AND the base prefix to
/// `ac_literals`/`ac_map`).
pub fn set_homoglyph_ascii_skip(mode: Option<bool>) {
    HOMOGLYPH_ASCII_SKIP_OVERRIDE.store(
        match mode {
            None => 0,
            Some(true) => 1,
            Some(false) => 2,
        },
        Relaxed,
    );
}

/// Whether to SKIP the always-active homoglyph fallback variants on a pure-ASCII
/// chunk. Tempting because `fb:prefilter` (the ~2,730-pattern pass over every
/// chunk) is the #1 scan cost and the variants only ADD reach on non-ASCII bytes.
///
/// **MEASURED NEGATIVE — default OFF.** RE-CONFIRMED 2026-06-09 by a full-finding
/// diff over the mirror corpus (skip vs no-skip via a top-level is_ascii gate):
/// the skip DROPS ~30 real findings (e.g. `jwt-token`) and the drops cascade into
/// spurious adds via overlap suppression. The base prefix IS in the phase-1 AC,
/// but the confirmed-extraction path that the trigger feeds has DIFFERENT
/// downstream gating (companion / keyword-proximity / confidence) than the
/// fallback path, so the always-active variant fires where confirmed does not —
/// the variant is load-bearing on ASCII, not redundant. The real fix is to close
/// that gap (make confirmed extraction catch those findings) BEFORE any ASCII
/// skip — not the skip itself. Gated behind `KEYHOG_HOMOGLYPH_ASCII_SKIP=1`
/// (measurement only). NOTE: earlier "recall-neutral" measurements were vacuous —
/// HS was the default prefilter and early-returned before this per-batch skip ran.
pub(crate) fn homoglyph_ascii_skip_enabled() -> bool {
    match HOMOGLYPH_ASCII_SKIP_OVERRIDE.load(Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_HOMOGLYPH_ASCII_SKIP").as_deref() == Ok("1"))
}

static FALLBACK_REVERSE_OVERRIDE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Diagnostic: override the fallback extraction-order reversal (test hook).
pub fn set_fallback_reverse(mode: Option<bool>) {
    FALLBACK_REVERSE_OVERRIDE.store(
        match mode {
            None => 0,
            Some(true) => 1,
            Some(false) => 2,
        },
        Relaxed,
    );
}

/// Diagnostic: reverse the fallback active-pattern extraction order. Used to
/// prove whether the final finding set is INDEPENDENT of fallback extraction
/// order — if it is, an O(text) literal prefilter (which marks in a different
/// order than the RegexSet) is safe to adopt.
pub(crate) fn fallback_reverse_enabled() -> bool {
    match FALLBACK_REVERSE_OVERRIDE.load(Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_FALLBACK_REVERSE").as_deref() == Ok("1"))
}

/// Whether shared-anchor fallback localization is enabled. On by default; set
/// `KEYHOG_FALLBACK_ANCHOR=0` (or `set_fallback_anchor_mode(Some(false))`) to
/// force the legacy whole-chunk path. Recall is identical either way — this is
/// a pure performance route.
pub(crate) fn fallback_anchor_enabled() -> bool {
    match FALLBACK_ANCHOR_OVERRIDE.load(Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_FALLBACK_ANCHOR").as_deref() != Ok("0"))
}

/// Override for the fallback prefix-literal skip gate (test/diagnostic).
/// `Some(true)` forces it on, `Some(false)` off, `None` = env default (on).
/// Recall is identical either way — the gate only skips batches whose patterns
/// ALL provably require a prefix literal that is absent from the chunk.
static PREFIX_GATE_OVERRIDE: AtomicU8 = AtomicU8::new(0);

/// Override for the prefilter `{N,}`→`{N}` truncation (the lazy-DFA lever).
/// `Some(true)` forces it on, `Some(false)` off, `None` = env default.
/// Recall-identical either way (the truncated set is a sound SUPERSET marking
/// gate; extraction with the full pattern filters) — proven by
/// `prefilter_truncate_parity`; it only trades prefilter speed for a little
/// extra extraction.
static PREFILTER_TRUNCATE_OVERRIDE: AtomicU8 = AtomicU8::new(0);

/// Override for the Hyperscan always-active prefilter. `Some(true)` forces the
/// HS engine, `Some(false)` forces the legacy `regex::RegexSet` batches, `None`
/// = env default (on when an HS engine compiled). The two engines mark the SAME
/// active set on every chunk (`fallback_prefilter_hs_parity`) and produce
/// IDENTICAL findings end-to-end (`fallback_prefilter_hs_findings_parity`), so
/// recall is unchanged either way — this only selects the SIMD-fast path vs the
/// ~1000x-slower RegexSet reference. Lets the parity gates A/B both in one run.
static FALLBACK_HS_OVERRIDE: AtomicU8 = AtomicU8::new(0);

/// Select the always-active prefilter engine (test/diagnostic). Recall is
/// identical; this only trades the SIMD fast path for the RegexSet reference.
pub fn set_fallback_hs(mode: Option<bool>) {
    FALLBACK_HS_OVERRIDE.store(
        match mode {
            None => 0,
            Some(true) => 1,
            Some(false) => 2,
        },
        Relaxed,
    );
}

/// Whether the HS always-active prefilter is enabled. Default ON: the HS engine
/// is ~1000x the `regex::RegexSet` throughput on the always-active set
/// (`fallback_prefilter_hs_vs_regexset`) and is the measured #1 scan cost.
/// `KEYHOG_FALLBACK_HS=0` forces the legacy reference path.
#[cfg(feature = "simd")]
pub(crate) fn fallback_hs_enabled() -> bool {
    match FALLBACK_HS_OVERRIDE.load(Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_FALLBACK_HS").as_deref() != Ok("0"))
}

/// Max chunk length (bytes) for which the HS prefilter is used; larger chunks
/// fall through to the `regex::RegexSet` batches. HS's per-scan cost is roughly
/// constant in chunk size (dominated by the unicode-homoglyph automaton), so it
/// beats the RegexSet's per-call setup on SMALL chunks but loses once the
/// per-byte automaton work over a large chunk dominates. Tunable via
/// `KEYHOG_FALLBACK_HS_MAX_LEN`; default chosen so the small-file regime (the
/// common case) takes HS and 16 KiB chunks take the RegexSet.
#[cfg(feature = "simd")]
pub(crate) fn hs_prefilter_max_len() -> usize {
    static MAX: OnceLock<usize> = OnceLock::new();
    *MAX.get_or_init(|| {
        std::env::var("KEYHOG_FALLBACK_HS_MAX_LEN")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(4096)
    })
}

pub fn set_prefilter_truncate(mode: Option<bool>) {
    PREFILTER_TRUNCATE_OVERRIDE.store(
        match mode {
            None => 0,
            Some(true) => 1,
            Some(false) => 2,
        },
        Relaxed,
    );
}

pub(crate) fn prefilter_truncate_enabled() -> bool {
    match PREFILTER_TRUNCATE_OVERRIDE.load(Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    // Default ON: −16.8% end-to-end on the mirror corpus (interleaved median of
    // 9), recall-identical (`prefilter_truncate_parity` 200k + contracts +
    // encoding-explosion + no-hit-recall). The `{N,}` bodies forced the folded
    // prefilter RegexSet onto the slow PikeVM path; bounding them keeps it on the
    // lazy-DFA. Helps BOTH the 16 KiB parent scan and every decode sub-chunk.
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_PREFILTER_TRUNCATE").as_deref() != Ok("0"))
}

pub fn set_fallback_prefix_gate(mode: Option<bool>) {
    PREFIX_GATE_OVERRIDE.store(
        match mode {
            None => 0,
            Some(true) => 1,
            Some(false) => 2,
        },
        Relaxed,
    );
}

pub(crate) fn fallback_prefix_gate_enabled() -> bool {
    match PREFIX_GATE_OVERRIDE.load(Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    // Default OFF: on the mirror corpus the gate skipped only ~17% of gateable
    // batches (the folded-prefix literal union is too broad — one credential
    // prefix anywhere in a chunk or spliced sub-chunk makes every batch run) and
    // the per-chunk AC `is_match` cost cancelled the saving end-to-end. Kept
    // behind the toggle as a sound, parity-validated lever for corpora with
    // genuinely literal-sparse chunks. The decode-recursion win is the focus
    // restriction (`KEYHOG_DECODE_FOCUS`), not this gate.
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_FALLBACK_PREFIX_GATE").as_deref() == Ok("1"))
}

/// Override for the decode-recursion FOCUS restriction (the real lever).
/// `Some(true)` forces it on, `Some(false)` off, `None` = env default (on).
/// When on, the fallback pass on a decode sub-chunk scans only a window around
/// the freshly decoded text (`ChunkMetadata::decoded_span`) instead of the whole
/// spliced parent context — the context was already scanned (and any finding
/// deduped) by the parent chunk. Signals (`keyword_nearby`), line offsets and
/// the keyword AC still run over the FULL splice, so confidence/report decisions
/// are unchanged; only the expensive prefilter RegexSet + regex extraction are
/// windowed. Recall-validated by `decode_focus_parity`.
static DECODE_FOCUS_OVERRIDE: AtomicU8 = AtomicU8::new(0);

pub fn set_decode_focus(mode: Option<bool>) {
    DECODE_FOCUS_OVERRIDE.store(
        match mode {
            None => 0,
            Some(true) => 1,
            Some(false) => 2,
        },
        Relaxed,
    );
}

pub(crate) fn decode_focus_enabled() -> bool {
    match DECODE_FOCUS_OVERRIDE.load(Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_DECODE_FOCUS").as_deref() != Ok("0"))
}
