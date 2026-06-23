//! SWE-101 regression gate: the always-active phase-2 prefilter must do **no
//! per-pattern work** on a chunk that cannot activate any always-active pattern.
//!
//! The user's #1 named issue: "phase-2 must NEVER eat runtime — not
//! 0.000000001s." Before the fix, `Phase2AlwaysActivePrefilter::mark_matches`
//! ran its expensive per-pattern body — the Hyperscan `scan_each` enumeration
//! plus its HS-incompatible whole-chunk-regex loop, or the `regex::RegexSet`
//! batch loop — UNCONDITIONALLY on every chunk (~10µs/chunk over 518k chunks
//! ≈ 5.3s of pure no-candidate overhead). The fix gates the body behind ONE fast
//! combined Aho-Corasick over every always-active pattern's required-prefix
//! literal: a no-hit over a pure-ASCII chunk proves nothing can fire, so the body
//! is skipped at ~ns AC-`is_match` cost.
//!
//! This test PINS that behavior with the live `mark_matches` instrumentation
//! counters (`phase2_mark_stats`):
//!   1. ZERO-WORK — a no-candidate chunk increments `MARK_GATE_SKIPS` and adds
//!      ZERO to `MARK_PERPATTERN_WORK`. A single unit of per-pattern work on a
//!      no-candidate chunk is the exact SWE-101 regression and fails the gate.
//!   2. SOUNDNESS / FINDINGS PARITY — scanning a credential-bearing corpus with
//!      the gate ON vs FORCED OFF (`set_no_candidate_gate(Some(false))`) yields a
//!      BYTE-IDENTICAL finding set, proving the gate is recall-neutral (Law 6/9).
//!   3. RECALL SURVIVAL — a chunk carrying a real fallback credential still
//!      produces its finding through the gated path (the gate never drops a live
//!      detection), and every `mark_matches` call resolves to exactly one of
//!      {gate skip, per-pattern body}.

use super::support;
use support::contracts::test_chunk as make_chunk;
use support::paths::detector_dir;

use std::collections::BTreeSet;
use std::sync::{Mutex, OnceLock};

use keyhog_scanner::CompiledScanner;

/// The `mark_matches` instrumentation counters (`phase2_mark_stats`) are
/// PROCESS-GLOBAL atomics. The counter-reading tests in this binary run in
/// parallel by default, so a concurrent scan would pollute a reset→scan→read
/// window. Serialize every counter-sensitive test so each owns the counters for
/// the duration of its single-chunk scan. (Findings parity in the third test does
/// not read counters, but it also scans and thus must not race a reader.)
static COUNTER_LOCK: Mutex<()> = Mutex::new(());

const DETECTOR_IDS: &[&str] = &[
    "asana-pat",
    "stripe-secret-key",
    "github-classic-pat",
    "slack-bot-token",
    "generic-password",
];

fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let mut detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors load");
        detectors.retain(|detector| DETECTOR_IDS.contains(&detector.id.as_str()));
        for id in DETECTOR_IDS {
            assert!(
                detectors.iter().any(|detector| detector.id == *id),
                "no-candidate gate detector subset missing shipped detector {id}"
            );
        }
        CompiledScanner::compile(detectors).expect("scanner compile")
    })
}

/// `(detector_id, credential, offset)` — the finding identity the gate must
/// preserve exactly across gate-on vs gate-off.
type FindingKey = (String, String, usize);

fn finding_keys(scanner: &CompiledScanner, text: &str, path: &str) -> BTreeSet<FindingKey> {
    let chunk = make_chunk(text, path);
    scanner.clear_fragment_cache();
    scanner
        .scan(&chunk)
        .iter()
        .map(|m| {
            (
                m.detector_id.as_ref().to_string(),
                m.credential.as_ref().to_string(),
                m.location.offset,
            )
        })
        .collect()
}

/// A pure-ASCII chunk that is BULLETPROOF candidate-free: only spaces, tabs and
/// newlines. No 3+ byte credential prefix literal can possibly occur in
/// whitespace, no detector keyword is present, and there is no high-entropy run,
/// so the phase-2 prefilter's combined gate must skip on EVERY `mark_matches`
/// call here regardless of which literals the gate was built from. (Using prose
/// risks an incidental 3-byte collision with some always-active literal, which
/// would make the gate fire and the `work == 0` assert flaky for the wrong
/// reason; whitespace removes that risk entirely.)
const NO_CANDIDATE_TEXT: &str =
    "\n    \t  \n        \n  \t\t  \n   \n      \n  \n        \n   \t \n  \n";

#[test]
fn no_candidate_chunk_does_zero_per_pattern_work() {
    let _guard = COUNTER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let scanner = support::compile_full_detector_scanner();
    scanner.clear_fragment_cache();
    crate::engine::phase2_mark_stats_reset();
    // Warm: scan the no-candidate chunk once so the counters reflect exactly one
    // production `mark_matches` invocation pattern.
    let keys = finding_keys(&scanner, NO_CANDIDATE_TEXT, "notes.rs");
    assert!(
        keys.is_empty(),
        "no-candidate chunk must produce zero findings; got {keys:?}"
    );

    let (calls, skips, work) = crate::engine::phase2_mark_stats();
    // The direct scan path always reaches `mark_matches` (scan_inner →
    // scan_prepared_with_triggered → scan_phase2_patterns → mark_matches), so at
    // least one call must have happened.
    assert!(
        calls >= 1,
        "expected mark_matches to be invoked on the direct scan path (calls={calls})"
    );
    // FLAGSHIP ASSERT: a no-candidate chunk must do ZERO per-pattern marking work.
    assert_eq!(
        work, 0,
        "SWE-101 REGRESSION: the phase-2 prefilter did per-pattern work on a \
         no-candidate chunk ({work} call(s) entered the expensive body). A fallback \
         must NEVER eat runtime on a chunk with no candidate."
    );
    // And every call must have been a gate skip (the cheap ~ns AC path).
    assert_eq!(
        skips, calls,
        "every mark_matches call on a no-candidate chunk must hit the combined-gate \
         fast path (skips={skips} calls={calls}); a non-skip means the gate was \
         absent or did not fire — the per-pattern body ran"
    );
}

#[test]
fn always_active_finding_survives_the_gate() {
    let _guard = COUNTER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let scanner = scanner();
    crate::engine::phase2_mark_stats_reset();
    // asana-pat shape `1/<16-20 digits>/<32 hex>` — a prefix-less / keyword-less
    // always-active phase-2 detector (issue #69 class), exactly the kind the
    // no-candidate gate must NOT drop: whichever path the gate takes (full body on
    // an anchor hit, or the precise non-anchorable check on the skip path), the
    // pattern must still be marked and the finding produced.
    let text = "asana = \"1/1234567890123456/0123456789abcdef0123456789abcdef\"\n";
    let keys = finding_keys(&scanner, text, "asana.cfg");
    let fired = keys.iter().any(|(det, _, _)| det == "asana-pat");
    assert!(
        fired,
        "the always-active asana-pat finding must survive the no-candidate gate; got {keys:?}"
    );

    // Structural invariant: every `mark_matches` call resolves to EXACTLY one of
    // {gate skip, per-pattern body} — never both, never neither. A drift here means
    // the counters (and the SWE-101 accounting they pin) are wrong.
    let (calls, skips, work) = crate::engine::phase2_mark_stats();
    assert!(calls >= 1, "mark_matches must run (calls={calls})");
    assert_eq!(
        skips + work,
        calls,
        "every mark_matches call must be exactly one of skip/work (skips={skips} \
         work={work} calls={calls})"
    );
}

#[test]
fn boolean_admission_honors_homoglyph_ascii_skip() {
    let _guard = COUNTER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let scanner = scanner();
    let prefilter = scanner
        .phase2_always_active_prefilter
        .as_ref()
        .expect("embedded detectors must build the always-active phase-2 prefilter");
    let text = "stripe = \"rk_live_2S2FrlCUpmb2ou955jvUlPSH\"\n";

    keyhog_scanner::testing::set_phase2_hs(&scanner, Some(false));
    keyhog_scanner::testing::set_homoglyph_ascii_skip(&scanner, Some(false));
    let fold_tuning = scanner.tuning().resolve();
    let fold_path_admits = prefilter.any_active_match(text, &fold_tuning);

    keyhog_scanner::testing::set_homoglyph_ascii_skip(&scanner, Some(true));
    let skip_tuning = scanner.tuning().resolve();
    let skip_path_admits = prefilter.any_active_match(text, &skip_tuning);
    keyhog_scanner::testing::set_phase2_hs(&scanner, None);
    keyhog_scanner::testing::set_homoglyph_ascii_skip(&scanner, None);

    assert!(
        fold_path_admits,
        "control path must prove the ASCII text was admitted only by the folded homoglyph batch"
    );
    assert!(
        !skip_path_admits,
        "boolean no-hit admission must mirror mark_matches' proven ASCII homoglyph skip \
         instead of over-admitting pure-ASCII chunks through generated variants"
    );
}

#[test]
fn gate_is_recall_neutral_findings_byte_identical() {
    let _guard = COUNTER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let scanner = scanner();
    // A corpus that exercises both candidate and no-candidate lines so the gate's
    // skip path AND its run path both contribute findings.
    let corpus = "\
# config with a mix of real secrets and ordinary lines
db_host = \"localhost\"
db_port = 5432
asana = \"1/1234567890123456/0123456789abcdef0123456789abcdef:0123456789abcdef0123456789abcdef\"
note = \"this line is just prose with nothing sensitive at all\"
github = \"ghp_0123456789abcdefghijklmnopqrstuvwxyzAB\"
timeout_seconds = 30
slack = \"xoxb-0000000000-0000000000-abcdefghijklmnopqrstuvwx\"
comment = \"the quick brown fox jumps over the lazy dog repeatedly\"
";

    // Gate ON (the shipped default).
    keyhog_scanner::testing::set_no_candidate_gate(&scanner, Some(true));
    let on = finding_keys(&scanner, corpus, "mixed.cfg");

    // Gate FORCED OFF — the pre-fix path that runs the per-pattern body on every
    // chunk. Findings MUST be byte-identical.
    keyhog_scanner::testing::set_no_candidate_gate(&scanner, Some(false));
    let off = finding_keys(&scanner, corpus, "mixed.cfg");

    // Restore instance-local override to "follow env".
    keyhog_scanner::testing::set_no_candidate_gate(&scanner, None);

    assert_eq!(
        on, off,
        "SWE-101 combined no-candidate gate changed the finding set (recall/precision \
         regression). gate-on={on:?}\n gate-off={off:?}"
    );
    // Sanity: the corpus must actually produce findings, or parity proves nothing.
    assert!(
        !on.is_empty(),
        "test corpus must surface at least one finding; got none"
    );
}
