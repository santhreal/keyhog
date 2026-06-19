//! Megakernel GPU-coverage CLASSIFIER — what actually keeps fallback patterns
//! off the GPU, and how to fix each class.
//!
//! `megakernel_catalog_pack` reports "1261/1668 packed, 407 host-path" at a
//! per-rule budget of **1024** states. That number conflates three very
//! different causes, and the fix differs per cause:
//!
//!   * **budget-bound** — the unanchored DFA lowers fine, it just needs > 1024
//!     states (`AKIA[A-Z0-9]{16}` = 2468). Fix: raise the per-rule budget (and
//!     pay transition-table memory). No new machinery.
//!   * **explosion** — the `.*?`-prefix subset construction blows past any sane
//!     budget because the body is a LARGE charclass over a LONG bound
//!     (`AIza[A-Za-z0-9_-]{35}`: 64-char class × 35). Fix: the literal-core
//!     hybrid (AC-find a literal anchor, verify the body with a small anchored
//!     DFA) — but ONLY if the pattern HAS a usable literal anchor.
//!   * **uncompilable** — PCRE features (lookaround / backref) the NFA builder
//!     rejects outright. These MUST take the loud host path (Law 10).
//!
//! This test classifies the REAL detector set so the GPU-coverage work targets
//! the actual distribution instead of a guess. It is a measurement, not a gate.
//!
//! Run: cargo test -p keyhog-scanner --features gpu \
//!        --test megakernel_literal_core_premise -- --ignored --nocapture

#[path = "support/mod.rs"]
mod support;
use support::paths::detector_dir;

use vyre_libs::scan::build_regex_dfa_unanchored;

const MAX_MATCHES: u32 = 200_000;
/// Budgets to sweep. 1024 = the current catalog budget; the rest show how much
/// raising it alone recovers, and what genuinely survives every budget.
const BUDGETS: &[usize] = &[1024, 4096, 16384, 65536];

#[derive(Default, Debug, Clone, Copy)]
struct Bucket {
    packable: usize,
    explosion: usize,
    uncompilable: usize,
    size: usize,
    transition_words: u64,
}

/// Leading literal run before the first regex metacharacter — the AC anchor the
/// literal-core hybrid would key on. Returns it only when >= 3 bytes (shorter
/// anchors fire too often to be a useful prefilter).
fn literal_anchor(pattern: &str) -> Option<String> {
    let mut lit = String::new();
    let mut chars = pattern.chars().peekable();
    while let Some(&c) = chars.peek() {
        if matches!(
            c,
            '[' | '(' | ')' | '\\' | '.' | '*' | '+' | '?' | '{' | '}' | '|' | '^' | '$'
        ) {
            break;
        }
        lit.push(c);
        chars.next();
    }
    (lit.len() >= 3).then_some(lit)
}

#[test]
#[ignore = "measurement over the real detector set; run with --ignored --nocapture"]
fn classify_fallback_gpu_coverage() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors unavailable: {e}");
            return;
        }
    };
    let regexes: Vec<String> = detectors
        .iter()
        .flat_map(|d| d.patterns.iter().map(|p| p.regex.clone()))
        .collect();
    eprintln!("classifying {} fallback patterns\n", regexes.len());

    for &budget in BUDGETS {
        use rayon::prelude::*;
        let bucket = regexes
            .par_iter()
            .map(|re| {
                match build_regex_dfa_unanchored(
                    std::slice::from_ref(&re.as_str()),
                    MAX_MATCHES,
                    budget,
                ) {
                    Ok(pipe) => {
                        let mut b = Bucket::default();
                        b.packable = 1;
                        b.transition_words = u64::from(pipe.dfa.state_count) * 256;
                        b
                    }
                    Err(e) => {
                        let dbg = format!("{e:?}");
                        let mut b = Bucket::default();
                        if dbg.contains("Compile") {
                            b.uncompilable = 1;
                        } else if dbg.contains("Size") {
                            b.size = 1;
                        } else {
                            b.explosion = 1; // Lower(StateExplosion ...)
                        }
                        b
                    }
                }
            })
            .reduce(Bucket::default, |mut a, b| {
                a.packable += b.packable;
                a.explosion += b.explosion;
                a.uncompilable += b.uncompilable;
                a.size += b.size;
                a.transition_words += b.transition_words;
                a
            });
        eprintln!(
            "budget {budget:>6}: packable {:>4} | explosion {:>3} | uncompilable {:>3} | size {:>2} \
             | host-path {:>3} | ~{:.1} MB transitions",
            bucket.packable,
            bucket.explosion,
            bucket.uncompilable,
            bucket.size,
            bucket.explosion + bucket.uncompilable + bucket.size,
            (bucket.transition_words * 4) as f64 / 1_048_576.0,
        );
    }

    // Of whatever still explodes at the largest budget, how many have a literal
    // anchor the hybrid could use vs how many are genuinely anchorless?
    let big = *BUDGETS.last().unwrap();
    use rayon::prelude::*;
    let explode: Vec<&String> = regexes
        .par_iter()
        .filter(|re| {
            matches!(
                build_regex_dfa_unanchored(std::slice::from_ref(&re.as_str()), MAX_MATCHES, big),
                Err(ref e) if !format!("{e:?}").contains("Compile")
                           && !format!("{e:?}").contains("Size")
            )
        })
        .collect();
    let anchored = explode
        .iter()
        .filter(|p| literal_anchor(p).is_some())
        .count();
    eprintln!(
        "\nat budget {big}: {} patterns still explode — {} hybrid-eligible (literal anchor >=3B), \
         {} anchorless (need a different lever)",
        explode.len(),
        anchored,
        explode.len() - anchored,
    );
    for p in explode.iter().take(25) {
        eprintln!("    explode: anchor={:?}  {}", literal_anchor(p), p);
    }
}
