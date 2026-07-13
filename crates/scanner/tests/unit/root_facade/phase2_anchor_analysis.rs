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

use keyhog_scanner::testing::{
    phase2_always_active_family_breakdown, phase2_anchor_stats, phase2_pattern_diagnostics,
};
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

/// Composition of the always-active (`phase2_n`) pool by detector family.
///
/// The recall-neutral decode-path perf lever (F3, BACKLOG) skips the
/// generic/entropy subset of this pool during decode rescans, because the
/// adjudicator's decode-guard already suppresses every generic/entropy finding on
/// decoded content, so marking that subset there is pure discarded work. This
/// test proves how many always-active patterns are NOT generic/entropy: that count
/// decides whether the decode skip can drop the WHOLE prefilter (`other == 0`) or
/// must exclude only the generic/entropy subset (`other > 0`) so no-keyword vendor
/// patterns still run. Runs on the real embedded detector corpus, so it also locks
/// the composition against a future detector that silently enters the pool.
#[test]
fn phase2_always_active_pool_family_composition() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let b = phase2_always_active_family_breakdown(&scanner);
    let ge_real = b.generic_entropy_real;
    let ge_homo = b.generic_entropy_homoglyph;
    let vendor_real = b.vendor_real;
    let vendor_homo = b.vendor_homoglyph;
    let real_total = ge_real + vendor_real;
    let homo_total = ge_homo + vendor_homo;
    eprintln!(
        "ALWAYS-ACTIVE POOL BREAKDOWN:\n  \
         REAL (non-homoglyph, runs on ASCII): generic/entropy={ge_real} vendor={vendor_real} (total {real_total})\n  \
         HOMOGLYPH (ASCII-skipped): generic/entropy={ge_homo} vendor={vendor_homo} (total {homo_total})\n  \
         distinct non-homoglyph vendor ids: {}",
        b.vendor_real_ids.len()
    );
    // TRUTH PINNED 2026-07-08: what actually runs the 84.3%-of-scan HS prefilter on
    // ASCII source is the REAL (non-homoglyph) always-active subset; homoglyph
    // variants are `homoglyph_ascii_skip`-skipped on pure-ASCII chunks. This test
    // reports both so the F3 perf lever targets the RIGHT set: if `vendor_real` is
    // large, the ASCII cost is vendor-anchorless patterns (register their required
    // literal as a phase-1 keyword to gate them); if it is ~0, the ASCII cost is the
    // handful of generic/entropy patterns and the homoglyph variants only bite on
    // non-ASCII text. Assert the pool is non-empty in each axis we rely on; the
    // eprintln! is the authoritative record (exact counts vary with the corpus).
    assert!(
        ge_real + ge_homo > 0,
        "expected generic/entropy detectors in the always-active pool; got 0"
    );
    assert!(
        real_total + homo_total > 100,
        "always-active pool unexpectedly tiny (real={real_total} homo={homo_total}); \
         the phase-2 partition or detector corpus changed shape, re-derive F3"
    );
}

/// F3 perf experiment: does the HS always-active prefilter waste time scanning the
/// 2792 inert homoglyph variants on ASCII chunks, or does HS's own literal prefilter
/// already gate them for free? Times the full DB vs a homoglyph-excluded lean DB on
/// representative ASCII haystacks. A large full/lean ratio means the missing HS
/// homoglyph-ASCII-skip is a real, recall-neutral perf lever worth building; ~1
/// means HS already handles it and the 84.3% prefilter cost is elsewhere.
#[cfg(feature = "simd")]
#[test]
#[ignore = "perf experiment; run with --ignored --nocapture"]
fn hs_homoglyph_ascii_skip_prize() {
    use keyhog_scanner::testing::bench_hs_homoglyph_skip;
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Representative ASCII haystacks (all pure-ASCII, so every homoglyph variant is
    // inert). Sizes/shapes span the real chunk distribution: small keyword-dense
    // config, a larger code-like body, and a high-entropy token line.
    let keyword_dense = "api_key = \"AKIA1234567890ABCDEF\"\n\
         password: hunter2\nsecret_token=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n\
         aws_secret_access_key = 'abcdefghijklmnopqrstuvwxyz0123456789ABCD'\n"
        .repeat(16);
    let code_like = "fn handler(req: Request) -> Response {\n    \
         let user = db.lookup(req.user_id());\n    // validate the session cookie\n    \
         if !session.is_valid() { return Response::unauthorized(); }\n    \
         let payload = serde_json::to_string(&user).unwrap();\n    Response::ok(payload)\n}\n"
        .repeat(24);
    let entropy_line = "data = b64encode(os.urandom(64)).decode()  # \
         Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6\n"
        .repeat(12);

    let n_calls = 2000;
    for (label, hay) in [
        ("keyword_dense", &keyword_dense),
        ("code_like", &code_like),
        ("entropy_line", &entropy_line),
    ] {
        assert!(hay.is_ascii(), "{label} haystack must be ASCII");
        let (full_ns, lean_ns, full_n, lean_n) = bench_hs_homoglyph_skip(&scanner, hay, n_calls);
        // Full `mark_matches` = no-candidate gate (anchor_present) + engine dispatch
        // + the HS mark. Comparing to `lean_ns` (HS mark alone) isolates how much of
        // the prefilter leaf is the gate/anchor overhead vs the HS scan, the
        // re-diagnosis of the remaining 83%-of-scan prefilter cost after the lean-DB
        // fix cut the HS mark to a few µs.
        let mark_ns =
            keyhog_scanner::testing::mark_matches_gate_ns_per_call(&scanner, hay, n_calls);
        let ratio = if lean_ns > 0.0 {
            full_ns / lean_ns
        } else {
            0.0
        };
        eprintln!(
            "HS-HOMOGLYPH-SKIP [{label}] len={:>6}B  hs_full={full_ns:>8.0} ns ({full_n} pats)  \
             hs_lean={lean_ns:>8.0} ns ({lean_n} pats)  full/lean={ratio:.2}x  \
             mark_matches={mark_ns:>8.0} ns (gate+anchor+hs_lean)",
            hay.len()
        );
    }
}

/// Recall-neutrality LOCK for the HS homoglyph-ASCII skip: on representative ASCII
/// haystacks, the lean ASCII sub-DB must differ from the full DB by EXACTLY the
/// homoglyph variants, it may never drop a non-homoglyph pattern and may never
/// over-mark. This is the unit-level proof behind the `homoglyph_ascii_skip`
/// invariant for the HS path (the full CredData/mirror bench proves it end-to-end).
/// A live gate (not `#[ignore]`): if a future change makes the lean DB drop a real
/// pattern on ASCII, this fails LOUDLY before any recall is lost in the field.
#[cfg(feature = "simd")]
#[test]
fn hs_homoglyph_ascii_skip_drops_only_homoglyph_variants() {
    use keyhog_scanner::testing::hs_mark_full_vs_lean_diff;
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Cover real credential shapes (so the full DB actually marks something to
    // compare) across ASCII text: vendor prefixes, generic key=value, high entropy.
    let haystacks = [
        "AKIA1234567890ABCDEF and ghp_0123456789abcdefghijklmnopqrstuvwxyz",
        "api_key = \"sk_live_0123456789abcdefghijklmno\"\npassword: correct-horse",
        "xoxb-1111111111-2222222222-abcdefghijklmnopqrstuvwx token=deadbeefcafebabe",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0123456789\n",
        "just some prose with no secrets at all, only ordinary english words here",
        "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6",
    ];
    for hay in haystacks {
        assert!(hay.is_ascii(), "haystack must be ASCII: {hay:?}");
        let (full_n, lean_n, non_homoglyph_dropped, lean_extra) =
            hs_mark_full_vs_lean_diff(&scanner, hay);
        assert!(
            non_homoglyph_dropped.is_empty(),
            "lean ASCII HS DB dropped NON-homoglyph pattern(s) {non_homoglyph_dropped:?} on {hay:?} \
             (full marked {full_n}, lean {lean_n}), that is a RECALL LOSS, not a homoglyph skip"
        );
        assert!(
            lean_extra.is_empty(),
            "lean ASCII HS DB over-marked {lean_extra:?} on {hay:?}, lean must be a strict subset"
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
