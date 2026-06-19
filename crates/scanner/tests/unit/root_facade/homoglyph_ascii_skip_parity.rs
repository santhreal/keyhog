//! Differential recall gate for the homoglyph ASCII-SKIP optimization.
//!
//! On a pure-ASCII chunk, the always-active homoglyph (plain) fallback variants
//! are skipped entirely instead of folded-and-run — the dominant `fb:prefilter`
//! cost (~43% of scan on all-ASCII source). This is sound ONLY if skipping them
//! drops no finding: a homoglyph variant exists for a detector whose BASE literal
//! prefix is ALSO in the AC/confirmed path (`compiler_build.rs` pushes both), and
//! on a chunk with no non-ASCII bytes the variant's only matchable form is that
//! base, already covered by the AC-triggered confirmed pass.
//!
//! This scans the mirror corpus + 20k generated ASCII inputs with skip ON vs OFF
//! and asserts byte-identical `RawMatch` sets. A divergence names the exact
//! detector+credential a homoglyph variant catches on ASCII that the base AC does
//! NOT — i.e. a real coverage gap to close, NOT a reason to weaken the test. A
//! second test confirms the skip is a no-op on a non-ASCII (homoglyph) chunk.

use super::support;
use support::paths::{corpus_dir, detector_dir};

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::path::PathBuf;

struct Lcg(u64);
impl Lcg {
    fn next_u32(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) as u32
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u32() as usize) % n
        }
    }
}

/// Token shapes that route through the fallback/homoglyph path AND have a base
/// AC literal prefix, so both the variant and the base exist.
const TOKENS: &[&str] = &[
    "sk_live_0123456789abcdefABCDEFxyz0",
    "rk_live_2S2FrlCUpmb2ou955jvUlPSH",
    "AKIAIOSFODNN7EXAMPLE",
    "api_key = \"AbCdEf0123456789xyzABCD\"",
    "API_KEY: 'tok_0123456789abcdefXYZ'",
    "8x8_api_key=\"sub0123456789abcdefAB\"",
    "500px_api_key = \"abcdEFGH01234567xyz\"",
    "everland_access_key: \"K0123456789abcdefABCD\"",
    "client_secret=\"0123456789abcdefABCDEFxyz\"",
    "STRIPE_RESTRICTED_KEY=\"rk_live_2S2FrlCUpmb2ou955jvUlPSH\"",
];

const FILLER: &[u8] = b"abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789\n\t=:;,.\"'(){}[]/_- the quick brown fox config value path import export return function const let var\n";

fn gen_ascii_chunk(rng: &mut Lcg) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let lead = rng.below(40);
    for _ in 0..lead {
        buf.push(FILLER[rng.below(FILLER.len())]);
    }
    let token_count = match rng.below(6) {
        0 => 0,
        1 | 2 => 1,
        3 => 3,
        _ => rng.below(3) + 1,
    };
    for _ in 0..token_count {
        let tok = TOKENS[rng.below(TOKENS.len())];
        buf.extend_from_slice(tok.as_bytes());
        match rng.below(3) {
            0 => {}
            1 => buf.push(b' '),
            _ => {
                let gap = rng.below(30);
                for _ in 0..gap {
                    buf.push(FILLER[rng.below(FILLER.len())]);
                }
            }
        }
    }
    let trail = rng.below(40);
    for _ in 0..trail {
        buf.push(FILLER[rng.below(FILLER.len())]);
    }
    buf
}

fn chunk_of(bytes: &[u8], label: &str) -> Chunk {
    Chunk {
        data: String::from_utf8_lossy(bytes).into_owned().into(),
        metadata: ChunkMetadata {
            source_type: "homoglyph-skip-parity".into(),
            path: Some(label.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

type Key = (String, String, String);
fn canonical(matches: &[Vec<RawMatch>]) -> Vec<Key> {
    let mut v: Vec<Key> = matches
        .iter()
        .flatten()
        .map(|m| {
            (
                m.detector_id.to_string(),
                m.credential.to_string(),
                format!("{:?}", m.location),
            )
        })
        .collect();
    v.sort();
    v
}

/// Scan `chunk` with the homoglyph ASCII-skip OFF (fold; the recall baseline) and
/// ON (the optimization), returning `(skip_on, fold_off)`.
fn scan_both(scanner: &CompiledScanner, chunk: &Chunk) -> (Vec<Key>, Vec<Key>) {
    // The homoglyph ASCII-skip lever lives in the legacy RegexSet prefilter path;
    // force HS off so the lever is actually exercised (HS bypasses it).
    keyhog_scanner::testing::set_phase2_hs(&scanner, Some(false));
    keyhog_scanner::testing::set_homoglyph_ascii_skip(&scanner, Some(false));
    scanner.clear_fragment_cache();
    let off = canonical(
        &scanner.scan_chunks_with_backend(std::slice::from_ref(chunk), ScanBackend::CpuFallback),
    );
    keyhog_scanner::testing::set_homoglyph_ascii_skip(&scanner, Some(true));
    scanner.clear_fragment_cache();
    let on = canonical(
        &scanner.scan_chunks_with_backend(std::slice::from_ref(chunk), ScanBackend::CpuFallback),
    );
    keyhog_scanner::testing::set_homoglyph_ascii_skip(&scanner, None);
    (on, off)
}

fn report(on: &[Key], off: &[Key], input: &[u8]) -> String {
    let dropped: Vec<&Key> = off.iter().filter(|k| !on.contains(k)).take(5).collect();
    let added: Vec<&Key> = on.iter().filter(|k| !off.contains(k)).take(5).collect();
    format!(
        "homoglyph ASCII-skip diverged on {:?}\n  dropped-by-skip (recall LOSS): {:?}\n  added-by-skip: {:?}",
        String::from_utf8_lossy(&input[..input.len().min(160)]),
        dropped,
        added,
    )
}

fn collect_files(root: &PathBuf, limit: usize) -> Vec<Vec<u8>> {
    let mut files = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                if let Ok(b) = std::fs::read(&p) {
                    files.push(b);
                    if files.len() >= limit {
                        return files;
                    }
                }
            }
        }
    }
    files
}

// The SOUNDNESS gate for the `homoglyph_ascii_skip` optimization (now default ON).
// It PASSES: closing the base-AC coverage gap — phase-1 marks triggers with
// OVERLAPPING AC matching, so a detector whose base literal is shadowed by a
// longer literal (e.g. `secret` inside `client_secret`) is still AC-confirmed —
// made skip ≡ fold at the raw-match level on every ASCII chunk. This gate now
// guards that the skip stays recall-neutral: a divergence means a NEW shadow
// case the overlapping triggers don't cover, i.e. a real coverage regression,
// NOT a reason to weaken the test. Default `KEYHOG_PARITY_N` + corpus cap keep CI
// fast; set `KEYHOG_PARITY_N` higher for an exhaustive sweep.
#[test]
fn homoglyph_ascii_skip_parity_default() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    let n: usize = std::env::var("KEYHOG_PARITY_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5_000);

    let mut rng = Lcg(0x1234_5678_9abc_def0);
    let mut checked = 0usize;
    for i in 0..n {
        let bytes = gen_ascii_chunk(&mut rng);
        // Only ASCII inputs exercise the skip (it is a no-op on non-ASCII).
        if !bytes.is_ascii() {
            continue;
        }
        let chunk = chunk_of(&bytes, &format!("gen-{i}"));
        let (on, off) = scan_both(&scanner, &chunk);
        assert_eq!(on, off, "{}", report(&on, &off, &bytes));
        checked += 1;
    }

    // Real mirror corpus — the representative ASCII source files. Capped for CI
    // speed; the synthetic sweep above plus this sample is a strong regression
    // gate, and `KEYHOG_PARITY_N` widens the synthetic half for exhaustive runs.
    if let Some(root) = corpus_dir() {
        for (i, f) in collect_files(&root, 3000).into_iter().enumerate() {
            if !f.is_ascii() {
                continue;
            }
            let chunk = chunk_of(&f, &format!("corpus-{i}"));
            let (on, off) = scan_both(&scanner, &chunk);
            assert_eq!(on, off, "{}", report(&on, &off, &f));
            checked += 1;
        }
    }

    eprintln!("homoglyph_ascii_skip_parity: {checked} ASCII inputs checked, skip ≡ fold");
    assert!(checked >= n, "expected >= {n} checks, got {checked}");
}

/// The skip is gated on `chunk.is_ascii()`, so a chunk containing an actual
/// non-ASCII homoglyph must run the variant unchanged — the optimization never
/// touches the case homoglyph detection exists for.
#[test]
fn homoglyph_variant_unaffected_on_non_ascii() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    // "аpi_key" with a Cyrillic 'а' (U+0430) — a non-ASCII chunk.
    let input = "\u{0430}pi_key = \"AbCdEf0123456789xyzABCD\"\n".as_bytes();
    assert!(!input.is_ascii());
    let chunk = chunk_of(input, "nonascii");
    let (on, off) = scan_both(&scanner, &chunk);
    assert_eq!(
        on,
        off,
        "skip must be a no-op on a non-ASCII chunk: {}",
        report(&on, &off, input)
    );
}
