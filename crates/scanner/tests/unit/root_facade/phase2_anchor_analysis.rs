//! Static classification of the keyword-gated phase-2 pattern set, sizing the
//! prize for regex-anchored phase-2 localization.
//!
//! `scan_phase2_patterns` runs each fired phase-2 pattern's capture regex
//! over the WHOLE chunk. The phase-2 breakdown shows that pass is 77-85% of
//! per-chunk scan time. The proposed optimization runs each fired pattern only
//! in small windows around occurrences of a regex-REQUIRED literal (an anchor
//! that, by `regex_syntax` proof, every match must contain), instead of the
//! whole chunk. That is sound iff the anchor is a required literal of every
//! match -- declared `detector.keywords` do NOT qualify (they are prefilter
//! metadata, not guaranteed match substrings; see `backend_triggered.rs` HS
//! union comment). This test reports how much of the phase-2 set carries such
//! a regex-proven anchor.
//!
//! Run:
//!   cargo test --profile release-fast -p keyhog-scanner --test \
//!     phase2_anchor_analysis -- --ignored --nocapture

use super::support;
use support::paths::detector_dir;

use keyhog_scanner::testing::{phase2_anchor_stats, phase2_pattern_diagnostics};
use keyhog_scanner::CompiledScanner;
use regex_syntax::hir::literal::{ExtractKind, Extractor};
use regex_syntax::ParserBuilder;

/// Minimum length of every literal in a prefix/suffix set for it to be a usable
/// anchor. A 1-2 byte anchor occurs too densely to prune the scan window; below
/// the keyword-AC's own >=4 floor is intentional here (anchors are required, so
/// even a 3-byte required literal like `sk-` or `1/` prunes a 16 KB chunk hard).
const MIN_ANCHOR_LEN: usize = 3;

#[derive(Default)]
struct Tally {
    total: usize,
    parse_fail: usize,
    prefix_anchorable: usize,
    suffix_anchorable: usize,
    either_anchorable: usize,
    bounded_len: usize,
    anchorable_and_bounded: usize,
    no_anchor: Vec<String>,
}

/// Classify one fallback regex. Returns (prefix_ok, suffix_ok, bounded).
fn classify(src: &str) -> Option<(bool, bool, bool, Option<usize>, Option<usize>)> {
    // Parse with default flags: extract the CANONICAL literals. Runtime matches
    // them ASCII-case-insensitively (the AC anchor is built caseless), so a
    // case-sensitive parse is sound and avoids the case-fold literal explosion
    // that turns every prefix into an infinite seq.
    let hir = ParserBuilder::new().build().parse(src).ok()?;
    let min_anchor_ok = |ex_kind: ExtractKind| -> bool {
        let mut ex = Extractor::new();
        ex.kind(ex_kind);
        let seq = ex.extract(&hir);
        // A finite, enumerable seq is a sound prefilter: every match begins
        // (resp. ends) with one of its members. Require every member >= the
        // anchor floor so the driving AC stays selective.
        match (seq.is_finite(), seq.len(), seq.min_literal_len()) {
            (true, Some(n), Some(min_len)) if n > 0 && min_len >= MIN_ANCHOR_LEN => true,
            _ => false,
        }
    };
    let prefix_ok = min_anchor_ok(ExtractKind::Prefix);
    let suffix_ok = min_anchor_ok(ExtractKind::Suffix);
    let props = hir.properties();
    let max_len = props.maximum_len();
    let min_len = props.minimum_len();
    Some((prefix_ok, suffix_ok, max_len.is_some(), max_len, min_len))
}

#[test]
#[ignore = "static analysis; run with --ignored --nocapture"]
fn phase2_anchor_prize() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let (total, always_active, aae) = phase2_anchor_stats(&scanner);
    eprintln!(
        "ANCHOR STATS: phase2_total={total} always_active={always_active} \
         always_active_eligible={aae} prefilter_remaining={}",
        always_active - aae
    );
    let phase2_patterns = phase2_pattern_diagnostics(&scanner);

    let mut t = Tally::default();
    t.total = phase2_patterns.len();
    let mut sample_anchorable: Vec<String> = Vec::new();

    for (src, _keywords) in &phase2_patterns {
        match classify(src) {
            None => t.parse_fail += 1,
            Some((prefix_ok, suffix_ok, bounded, max_len, _min_len)) => {
                if prefix_ok {
                    t.prefix_anchorable += 1;
                }
                if suffix_ok {
                    t.suffix_anchorable += 1;
                }
                if bounded {
                    t.bounded_len += 1;
                }
                let either = prefix_ok || suffix_ok;
                if either {
                    t.either_anchorable += 1;
                    if sample_anchorable.len() < 25 {
                        let kind = if prefix_ok { "prefix" } else { "suffix" };
                        sample_anchorable.push(format!(
                            "  [{kind}, max_len={max_len:?}] {}",
                            truncate(src, 70)
                        ));
                    }
                }
                if either && bounded {
                    t.anchorable_and_bounded += 1;
                }
                if !either && t.no_anchor.len() < 25 {
                    t.no_anchor.push(format!("  {}", truncate(src, 80)));
                }
            }
        }
    }

    let pct = |n: usize| 100.0 * n as f64 / t.total.max(1) as f64;
    eprintln!(
        "=== PHASE-2 ANCHOR PRIZE ({} phase-2 patterns) ===",
        t.total
    );
    eprintln!(
        "  parse_fail           : {:>4} ({:>5.1}%)",
        t.parse_fail,
        pct(t.parse_fail)
    );
    eprintln!(
        "  prefix-anchorable    : {:>4} ({:>5.1}%)",
        t.prefix_anchorable,
        pct(t.prefix_anchorable)
    );
    eprintln!(
        "  suffix-anchorable    : {:>4} ({:>5.1}%)",
        t.suffix_anchorable,
        pct(t.suffix_anchorable)
    );
    eprintln!(
        "  EITHER-anchorable    : {:>4} ({:>5.1}%)",
        t.either_anchorable,
        pct(t.either_anchorable)
    );
    eprintln!(
        "  bounded max_len      : {:>4} ({:>5.1}%)",
        t.bounded_len,
        pct(t.bounded_len)
    );
    eprintln!(
        "  anchorable & bounded : {:>4} ({:>5.1}%)",
        t.anchorable_and_bounded,
        pct(t.anchorable_and_bounded)
    );
    eprintln!("--- sample anchorable ---");
    for s in &sample_anchorable {
        eprintln!("{s}");
    }
    eprintln!("--- sample NON-anchorable (whole-chunk stays) ---");
    for s in &t.no_anchor {
        eprintln!("{s}");
    }
}

#[test]
#[ignore = "diagnostic; run with --ignored --nocapture"]
fn dump_xox_literal_cover() {
    use regex_syntax::hir::literal::Seq;
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    for (src, kw) in phase2_pattern_diagnostics(&scanner) {
        if !src.to_lowercase().contains("xox") {
            continue;
        }
        let ci = true; // detector fallbacks compile case-insensitive
        let hir = ParserBuilder::new()
            .case_insensitive(ci)
            .build()
            .parse(&src);
        let seq: Option<Seq> = hir.as_ref().ok().map(|h| {
            let mut ex = Extractor::new();
            ex.kind(ExtractKind::Prefix);
            ex.extract(h)
        });
        let (finite, exact, len, minlen) = match &seq {
            Some(s) => (s.is_finite(), s.is_exact(), s.len(), s.min_literal_len()),
            None => (false, false, None, None),
        };
        let lits: Vec<String> = seq
            .as_ref()
            .and_then(|s| s.literals())
            .map(|ls| {
                ls.iter()
                    .filter_map(|l| std::str::from_utf8(l.as_bytes()).ok().map(str::to_string))
                    .take(12)
                    .collect()
            })
            .unwrap_or_default();
        eprintln!(
            "finite={finite} exact={exact} len={len:?} minlen={minlen:?} kw={kw:?}\n  src={}\n  lits(first12)={lits:?}",
            truncate(&src, 90)
        );
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..FloorCharBoundary::floor_char_boundary(s, n)])
    }
}

trait FloorCharBoundary {
    fn floor_char_boundary(&self, index: usize) -> usize;
}
impl FloorCharBoundary for str {
    fn floor_char_boundary(&self, index: usize) -> usize {
        let mut i = index.min(self.len());
        while i > 0 && !self.is_char_boundary(i) {
            i -= 1;
        }
        i
    }
}
