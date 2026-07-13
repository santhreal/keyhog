//! Line-length / window-boundary runner, a credential-sufficient secret
//! surfaces at any BYTE OFFSET, including past the in-memory window cap.
//!
//! Minified JS, a base64 blob dumped without wrapping, single-line k8s
//! ConfigMap output: a credential can sit megabytes into one unbroken line. A
//! scanner that pre-tokenises on newlines and applies a hard per-line ceiling
//! silently never reaches it; one that stops after its first ≤1 MiB window
//! never reaches a credential past the cap.
//!
//! BEHAVIOR contract, not an accuracy rate
//! ---------------------------------------
//! We place a credential-sufficient secret VERBATIM after a filler prefix of
//! the chosen length and assert it still surfaces. The credential bytes are
//! left untouched, a multiline PEM keeps its internal newlines; collapsing
//! them with `replace('\n', " ")` would mutate the credential into a DIFFERENT
//! string (the bug this rewrite removes, which dropped every `ssh-private-key`
//! positive at *every* offset including 0). So this is a *credential-
//! sufficiency invariance* contract (see `support::contracts`): a credential
//! that fires on its own bytes alone MUST still surface no matter how far into
//! the buffer it sits. The in-memory `scan(&chunk)` path WINDOWS any chunk over
//! `MAX_SCAN_CHUNK_BYTES` (1 MiB) into overlapping ≤1 MiB windows
//! (`WINDOW_OVERLAP_BYTES` = 128 KiB), and `max_file_size` is a filesystem-
//! walker bound that does NOT apply here, so there is no legitimate
//! per-line/per-chunk cap on this path below the 16 MiB decode ceiling, and
//! every credential-sufficient miss at any offset below is a real windowing
//! recall bug. We gate exactly that, all-or-nothing.
//!
//! Why the seam sample is the LONGEST credentials, not the whole corpus
//! -------------------------------------------------------------------
//! The seam offsets generate megabyte chunks; scanning one per gated primary in
//! a debug build is minutes of wall-clock (Law 7, the prior version took
//! 315 s). The windowing math bounds exactly what the seam can probe: the
//! windows of a ~1.5 MiB chunk are [0, 1 MiB] and [1 MiB − 128 KiB, 1.9 MiB],
//! so any credential no longer than the 128 KiB overlap is FULLY CONTAINED in
//! some window regardless of where it lands. The only thing the seam adds over
//! the realistic ladder is "does `scan_windowed` iterate PAST window 1 and find
//! a credential there", a single scanner behavior, hardest for the LONGEST
//! credential (closest to the containment bound). We therefore run the seam
//! over the `SEAM_SAMPLE` longest gated credentials. The restriction is logged,
//! not silent (CLAUDE.md Law 10), and the realistic ladder still gates EVERY
//! gated primary up to 64 KiB.
//!
//! Companion-required positives (a bare UUID, a low-entropy body needing a
//! keyword anchor) depend on surrounding context a transform may perturb; their
//! survival is an accuracy RATE owned by the bench, so they are counted ONCE at
//! baseline for corpus context and never gated or swept across offsets.

mod support;
use support::contracts::{
    load_contracts, make_chunk, primaries, scanner, sufficiency_mask, surfaces, Primary,
};

use std::collections::BTreeMap;

const SOURCE_TYPE: &str = "line-length";

/// Realistic offsets (bytes from line start) every GATED primary is placed at:
/// the common single-line range up to 64 KiB. Roughly geometric so a per-line
/// ceiling between rungs surfaces at the nearest rung.
const REALISTIC_OFFSETS: &[usize] = &[0, 256, 4 * 1024, 16 * 1024, 64 * 1024];

/// Seam offsets that cross `MAX_SCAN_CHUNK_BYTES` (1 MiB): 1 MiB places the
/// credential right at the first window's end boundary; 1.5 MiB places it beyond
/// the first window entirely so only the second overlapping window can reach it.
/// Both prove `scan_windowed` iterates past window 1. Megabyte chunks, run only
/// over the seam sample, see `SEAM_SAMPLE`.
const SEAM_OFFSETS: &[usize] = &[1024 * 1024, 1024 * 1024 + 512 * 1024];

/// Number of longest gated credentials the megabyte seam scans run over. The
/// windowing guarantee (containment for any credential ≤ 128 KiB overlap) makes
/// the longest credentials the binding worst case; a small sample proves
/// `scan_windowed` reaches past window 1 without minutes of debug scanning.
const SEAM_SAMPLE: usize = 8;

/// Mid-line prefix/suffix byte pairs. `credential_sufficient_secrets_survive_
/// long_line_offsets` only ever places the credential at END-of-line (long
/// prefix, NOTHING after it). But in minified JS, a single-line config dump, or
/// a base64 blob, a credential sits in the MIDDLE of the line with filler both
/// BEFORE and AFTER it. `(500, 500)` is exactly the reported shape
/// (`filler·500 + secret + filler·500`); the larger pairs push the trailing
/// filler further out. Trailing content must not cause a mid-line credential to
/// be dropped, the in-memory path windows with no per-line cap, so a mid-line
/// miss is the same class of windowing recall bug the end-of-line ladder gates.
const MID_LINE_PAIRS: &[(usize, usize)] =
    &[(500, 500), (4 * 1024, 4 * 1024), (16 * 1024, 4 * 1024)];

/// How many distinct-detector, single-line credential-sufficient secrets to pack
/// onto ONE line for the multi-secret recall gate. Real `.env` / minified /
/// single-line config lines routinely carry several secrets at once.
const MULTI_SECRET_LINE_COUNT: usize = 12;

/// String-VALUE quote delimiters a credential is routinely wrapped in, the
/// unambiguous "this is a value" context of JSON, YAML, TOML, and source string
/// literals. A credential-sufficient secret MUST still surface wrapped in either
/// quote (the overwhelmingly common config/code shape).
///
/// NOTE, deliberately QUOTES ONLY. Bracket-family wraps (`(…)`, `[…]`, `{…}`,
/// `<…>`, `` `…` ``) are an AMBIGUOUS context: a bare high-entropy base64 blob
/// inside `foo(…)` or `[…]` may be an argument/array element rather than a
/// secret, so the generic path treating it as lower-confidence can be intended
/// precision, not a recall bug. It is NOT gated here as a hard invariant,
/// because this suite asserts only unambiguous credential-value contexts.
const WRAP_DELIMS: &[(&str, &str)] = &[("\"", "\""), ("'", "'")];

const FILLER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789..";

fn make_filler(n: usize) -> String {
    let mut out = String::with_capacity(n);
    while out.len() < n {
        let take = (n - out.len()).min(FILLER.len());
        out.push_str(&FILLER[..take]);
    }
    out
}

#[test]
fn credential_sufficient_secrets_survive_long_line_offsets() {
    let scanner = scanner();
    let contracts = load_contracts();
    let primaries: Vec<Primary> = primaries(&contracts);
    let sufficient = sufficiency_mask(&scanner, SOURCE_TYPE, &primaries);
    let n_sufficient = sufficient.iter().filter(|b| **b).count();

    // Each offset's filler is built ONCE and reused across every probe. The old
    // code rebuilt `make_filler(offset)` on every probe, so the 1.5 MiB seam
    // fillers were re-allocated hundreds of times (a Law-7 cost bug).
    let mut fillers: BTreeMap<usize, String> = BTreeMap::new();
    for &offset in REALISTIC_OFFSETS.iter().chain(SEAM_OFFSETS) {
        fillers.entry(offset).or_insert_with(|| make_filler(offset));
    }

    // Place a credential VERBATIM at `offset` bytes and ask whether it
    // surfaces. The credential bytes (including any internal newlines) are never
    // mutated, so byte-preservation, and therefore the soundness of the
    // credential-sufficiency invariance (holds by construction).
    let probe = |p: &Primary, offset: usize| -> bool {
        let prefix = &fillers[&offset];
        let text = format!("{prefix} {}", p.credential);
        let chunk = make_chunk(&text, SOURCE_TYPE, "oneliner.txt");
        surfaces(&scanner, &chunk, &p.credential)
    };

    let mut gated_assertions = 0usize;
    let mut gated_hits = 0usize;
    let mut violations: Vec<String> = Vec::new();

    // Realistic ladder: every gated primary at every realistic offset.
    for (idx, p) in primaries.iter().enumerate() {
        if !sufficient[idx] {
            continue;
        }
        for &offset in REALISTIC_OFFSETS {
            gated_assertions += 1;
            if probe(p, offset) {
                gated_hits += 1;
            } else {
                violations.push(format!(
                    "{detector} :: offset={offset} :: standalone-firing credential {cred:?} \
                     DROPPED at this line offset",
                    detector = p.detector_id,
                    cred = p.credential,
                ));
            }
        }
    }

    // Seam ladder: the SEAM_SAMPLE longest gated credentials at megabyte offsets
    // (see header). Longest = worst case for window containment.
    let mut gated_desc_by_len: Vec<usize> =
        (0..primaries.len()).filter(|&i| sufficient[i]).collect();
    gated_desc_by_len.sort_by_key(|&i| std::cmp::Reverse(primaries[i].credential.len()));
    let seam_idxs: Vec<usize> = gated_desc_by_len.into_iter().take(SEAM_SAMPLE).collect();
    for &idx in &seam_idxs {
        let p = &primaries[idx];
        for &offset in SEAM_OFFSETS {
            gated_assertions += 1;
            if probe(p, offset) {
                gated_hits += 1;
            } else {
                violations.push(format!(
                    "{detector} :: offset={offset} (seam) :: standalone-firing credential \
                     {cred:?} DROPPED past the 1 MiB window cap",
                    detector = p.detector_id,
                    cred = p.credential,
                ));
            }
        }
    }

    // Companion-required corpus context, counted ONCE at baseline. Their text
    // (which carries the keyword anchor) is inlined; this is informational
    // their per-offset survival is a bench-owned RATE, never gated here.
    let mut companion_runs = 0usize;
    let mut companion_hits = 0usize;
    let baseline_filler = &fillers[&0];
    for (idx, p) in primaries.iter().enumerate() {
        if sufficient[idx] {
            continue;
        }
        companion_runs += 1;
        let text = format!("{baseline_filler} {}", p.text.replace('\n', " "));
        let chunk = make_chunk(&text, SOURCE_TYPE, "oneliner.txt");
        if surfaces(&scanner, &chunk, &p.credential) {
            companion_hits += 1;
        }
    }

    let seam_lens: Vec<usize> = seam_idxs
        .iter()
        .map(|&i| primaries[i].credential.len())
        .collect();
    eprintln!(
        "line-length: {n_sufficient}/{} primaries fire standalone; gated survival \
         {gated_hits}/{gated_assertions} (must be 100%) across realistic offsets \
         {REALISTIC_OFFSETS:?} (every gated primary) + seam offsets {SEAM_OFFSETS:?} over the {} \
         longest gated credentials (lengths {seam_lens:?}). companion-required baseline: \
         {companion_hits}/{companion_runs} fire at offset 0 (informational; per-offset survival \
         is a bench RATE).",
        primaries.len(),
        seam_idxs.len(),
    );

    assert!(
        violations.is_empty(),
        "line-length credential-sufficiency invariance violated ({} cases): a credential that \
         fires standalone was dropped at a larger byte offset, a per-line/window-cap recall bug \
         on the in-memory scan path (which windows, so no legitimate cap applies below 16 MiB):\n  \
         - {}",
        violations.len(),
        violations.join("\n  - "),
    );
}

/// Complement of the offset ladder: a credential-sufficient secret embedded in
/// the MIDDLE of a long single line: `filler + secret + filler`, all on one
/// line, must still surface. The offset ladder only ever places the credential
/// at end-of-line, so trailing content past the credential was never gated; a
/// minified bundle or single-line config dump routinely puts a secret mid-line.
/// Same all-or-nothing credential-sufficiency invariance: a secret that fires on
/// its own bytes must survive regardless of what follows it on the line.
#[test]
fn credential_sufficient_secrets_survive_embedded_mid_line() {
    let scanner = scanner();
    let contracts = load_contracts();
    let primaries: Vec<Primary> = primaries(&contracts);
    let sufficient = sufficiency_mask(&scanner, SOURCE_TYPE, &primaries);
    let n_sufficient = sufficient.iter().filter(|b| **b).count();

    // Each distinct filler length built once and reused across every probe.
    let mut fillers: BTreeMap<usize, String> = BTreeMap::new();
    for &(pre, suf) in MID_LINE_PAIRS {
        fillers.entry(pre).or_insert_with(|| make_filler(pre));
        fillers.entry(suf).or_insert_with(|| make_filler(suf));
    }

    let mut gated_assertions = 0usize;
    let mut gated_hits = 0usize;
    let mut violations: Vec<String> = Vec::new();

    for (idx, p) in primaries.iter().enumerate() {
        if !sufficient[idx] {
            continue;
        }
        for &(pre, suf) in MID_LINE_PAIRS {
            // Credential VERBATIM (internal newlines preserved), space-delimited,
            // filler both before AND after, all in one chunk.
            let prefix = &fillers[&pre];
            let suffix = &fillers[&suf];
            let text = format!("{prefix} {} {suffix}", p.credential);
            let chunk = make_chunk(&text, SOURCE_TYPE, "midline.txt");
            gated_assertions += 1;
            if surfaces(&scanner, &chunk, &p.credential) {
                gated_hits += 1;
            } else {
                violations.push(format!(
                    "{detector} :: prefix={pre} suffix={suf} :: standalone-firing credential \
                     {cred:?} DROPPED when embedded mid-line with trailing filler",
                    detector = p.detector_id,
                    cred = p.credential,
                ));
            }
        }
    }

    eprintln!(
        "line-length mid-line: {n_sufficient}/{} primaries fire standalone; gated survival \
         {gated_hits}/{gated_assertions} (must be 100%) across prefix/suffix pairs \
         {MID_LINE_PAIRS:?} for every gated primary.",
        primaries.len(),
    );

    assert!(
        violations.is_empty(),
        "mid-line credential-sufficiency invariance violated ({} cases): a credential that fires \
         standalone was DROPPED when placed in the MIDDLE of a long line with trailing filler, a \
         windowing/tokenisation recall bug for minified / single-line content (the in-memory path \
         windows, so no legitimate per-line cap applies):\n  - {}",
        violations.len(),
        violations.join("\n  - "),
    );
}

/// Multi-secret one-line recall: a real `.env` / minified / single-line config
/// line often carries SEVERAL secrets. Reporting the first must not stop the
/// scan of the line or evict the rest. EVERY credential-sufficient secret
/// packed onto a single line must surface. Uses DISTINCT detectors (distinct
/// credential bytes) so no value/detector dedup can mask a genuine drop.
/// Complementary to the single-secret offset/mid-line ladders above (which each
/// place exactly ONE secret per chunk).
#[test]
fn every_secret_on_a_densely_packed_line_surfaces() {
    let scanner = scanner();
    let contracts = load_contracts();
    let primaries: Vec<Primary> = primaries(&contracts);
    let sufficient = sufficiency_mask(&scanner, SOURCE_TYPE, &primaries);

    // First N gated primaries from DISTINCT detectors, single-line credentials
    // only (so the pack is a genuine ONE line, not a multiline PEM spread).
    let mut chosen: Vec<&Primary> = Vec::new();
    let mut seen_detectors: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (idx, p) in primaries.iter().enumerate() {
        if !sufficient[idx] || p.credential.contains('\n') {
            continue;
        }
        if seen_detectors.insert(p.detector_id.as_str()) {
            chosen.push(p);
            if chosen.len() == MULTI_SECRET_LINE_COUNT {
                break;
            }
        }
    }
    assert!(
        chosen.len() >= 2,
        "need >=2 distinct-detector single-line standalone-firing primaries to gate multi-secret \
         recall; got {}",
        chosen.len()
    );

    // Pack every chosen secret onto ONE line, delimited so each keeps a word
    // boundary (a bare-value config list shape).
    let line = chosen
        .iter()
        .map(|p| p.credential.as_str())
        .collect::<Vec<_>>()
        .join(" | ");
    let chunk = make_chunk(&line, SOURCE_TYPE, "packed.txt");

    let mut violations: Vec<String> = Vec::new();
    for p in &chosen {
        if !surfaces(&scanner, &chunk, &p.credential) {
            violations.push(format!(
                "{detector} :: standalone-firing credential {cred:?} DROPPED when packed onto one \
                 line with {n} other secrets",
                detector = p.detector_id,
                cred = p.credential,
                n = chosen.len() - 1,
            ));
        }
    }

    eprintln!(
        "line-length multi-secret: {}/{} distinct-detector secrets packed on one line all surfaced.",
        chosen.len() - violations.len(),
        chosen.len(),
    );
    assert!(
        violations.is_empty(),
        "multi-secret one-line recall violated ({} of {} dropped): a standalone-firing credential \
         was not reported when several secrets share a line, the scanner must surface EVERY secret \
         on a line, not just the first:\n  - {}",
        violations.len(),
        chosen.len(),
        violations.join("\n  - "),
    );
}

/// String-value quote recall: a credential is almost never bare, it sits as a
/// quoted VALUE, `"ghp_…"` / `'glpat-…'` (JSON/YAML/TOML/source string literals).
/// A quote is the unambiguous "this is a value" context, so a credential-
/// sufficient secret must still surface wrapped in either quote. Complements the
/// whitespace/BOM runner (which wraps in WHITESPACE) with the quoted-value case.
/// (Bracket-family wraps are intentionally excluded, see `WRAP_DELIMS`.)
#[test]
fn credential_sufficient_secrets_survive_string_value_quotes() {
    let scanner = scanner();
    let contracts = load_contracts();
    let primaries: Vec<Primary> = primaries(&contracts);
    let sufficient = sufficiency_mask(&scanner, SOURCE_TYPE, &primaries);
    let n_sufficient = sufficient.iter().filter(|b| **b).count();

    let mut gated_assertions = 0usize;
    let mut gated_hits = 0usize;
    let mut violations: Vec<String> = Vec::new();

    for (idx, p) in primaries.iter().enumerate() {
        // Single-line credentials only, a multiline PEM carries its own
        // delimiters and would confound a "wrapped in one pair" probe.
        if !sufficient[idx] || p.credential.contains('\n') {
            continue;
        }
        for &(open, close) in WRAP_DELIMS {
            // e.g. `"ghp_…"`, `'glpat-…'`: a quoted value with benign filler
            // either side so the wrap is mid-content, not at a buffer edge.
            let text = format!("lead {open}{}{close} tail", p.credential);
            let chunk = make_chunk(&text, SOURCE_TYPE, "wrapped.txt");
            gated_assertions += 1;
            if surfaces(&scanner, &chunk, &p.credential) {
                gated_hits += 1;
            } else {
                violations.push(format!(
                    "{detector} :: wrap={open}…{close} :: standalone-firing credential {cred:?} \
                     DROPPED when wrapped as a quoted string value",
                    detector = p.detector_id,
                    cred = p.credential,
                ));
            }
        }
    }

    eprintln!(
        "line-length quotes: {n_sufficient} primaries fire standalone; gated survival \
         {gated_hits}/{gated_assertions} (must be 100%) across quote wraps {WRAP_DELIMS:?} for \
         every single-line gated primary.",
    );
    assert!(
        violations.is_empty(),
        "quoted-value credential-sufficiency invariance violated ({} cases): a credential that \
         fires standalone was DROPPED when wrapped as a quoted string value, the JSON/YAML/source \
         norm, so this is a real boundary-handling recall bug:\n  - {}",
        violations.len(),
        violations.join("\n  - "),
    );
}
