//! Differential recall gate for the homoglyph ASCII-SKIP optimization.
//!
//! On a pure-ASCII chunk, the always-active homoglyph (plain) fallback variants
//! are skipped entirely instead of folded-and-run, the dominant `phase2:prefilter`
//! cost (~43% of scan on all-ASCII source). This is sound ONLY if skipping them
//! drops no finding: a homoglyph variant exists for a detector whose BASE literal
//! prefix is ALSO in the AC/confirmed path (`compiler_build.rs` pushes both), and
//! on a chunk with no non-ASCII bytes the variant's only matchable form is that
//! base, already covered by the AC-triggered confirmed pass.
//!
//! This scans the mirror corpus + generated ASCII inputs through the shipped
//! detector specs represented by the parity tokens with skip ON vs OFF and
//! asserts byte-identical `RawMatch` sets. A divergence names the exact
//! detector+credential a homoglyph variant catches on ASCII that the base AC does
//! NOT, i.e. a real coverage gap to close, NOT a reason to weaken the test. A
//! second test confirms the skip is a no-op on a non-ASCII (homoglyph) chunk.

use super::support;
use support::paths::{corpus_dir, corpus_files, detector_dir};

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::OnceLock;

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

const DETECTOR_IDS: &[&str] = &[
    "stripe-secret-key",
    "aws-access-key",
    "generic-password",
    "8x8-api-credentials",
    "500px-api-key",
    "4everland-api-token",
];

const FILLER: &[u8] = b"abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789\n\t=:;,.\"'(){}[]/_- the quick brown fox config value path import export return function const let var\n";
const DEFAULT_PARITY_N: usize = 64;
const DEFAULT_CORPUS_CAP: usize = 0;

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

fn deterministic_ascii_cases() -> Vec<Vec<u8>> {
    let mut cases = Vec::new();
    for token in TOKENS {
        cases.push(token.as_bytes().to_vec());
        cases.push(format!("const value = {token};\n").into_bytes());
        cases.push(format!("client_secret = \"{token}\"\n").into_bytes());
        cases.push(format!("prefix secret {token} suffix token\n").into_bytes());
        cases.push(format!("{}\n{}\n", "a".repeat(96), token).into_bytes());
    }
    cases
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
fn canonical(matches: &[RawMatch]) -> Vec<Key> {
    let mut v: Vec<Key> = matches
        .iter()
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

fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let mut detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
        detectors.retain(|detector| DETECTOR_IDS.contains(&detector.id.as_str()));
        for id in DETECTOR_IDS {
            assert!(
                detectors.iter().any(|detector| detector.id == *id),
                "homoglyph parity detector subset missing shipped detector {id}"
            );
        }
        CompiledScanner::compile(detectors).expect("compile")
    })
}

/// Scan `chunk` with the homoglyph ASCII-skip OFF (fold; the recall baseline) and
/// ON (the optimization), returning `(skip_on, fold_off)`.
fn scan_both(scanner: &CompiledScanner, chunk: &Chunk) -> (Vec<Key>, Vec<Key>) {
    // The homoglyph ASCII-skip lever lives in the legacy RegexSet prefilter path;
    // force HS off so the lever is actually exercised (HS bypasses it).
    keyhog_scanner::testing::set_phase2_hs(&scanner, Some(false));
    keyhog_scanner::testing::set_homoglyph_ascii_skip(&scanner, Some(false));
    scanner.clear_fragment_cache();
    let off = canonical(&scanner.scan_with_backend(chunk, ScanBackend::CpuFallback));
    keyhog_scanner::testing::set_homoglyph_ascii_skip(&scanner, Some(true));
    scanner.clear_fragment_cache();
    let on = canonical(&scanner.scan_with_backend(chunk, ScanBackend::CpuFallback));
    keyhog_scanner::testing::set_homoglyph_ascii_skip(&scanner, None);
    (on, off)
}

/// As [`scan_both`], but keeps HS ON and scans via `SimdCpu` so the HYPERSCAN
/// always-active path is exercised. With the fix, the HS engine honors
/// `homoglyph_ascii_skip` via its lean ASCII sub-DB, so skip-ON and skip-OFF must
/// still produce byte-identical `RawMatch` sets on ASCII, the end-to-end proof
/// that routing ASCII marking through the lean DB adds no FP and drops no TP.
fn scan_both_hs(scanner: &CompiledScanner, chunk: &Chunk) -> (Vec<Key>, Vec<Key>) {
    keyhog_scanner::testing::set_phase2_hs(scanner, Some(true));
    keyhog_scanner::testing::set_homoglyph_ascii_skip(scanner, Some(false));
    scanner.clear_fragment_cache();
    let off = canonical(&scanner.scan_with_backend(chunk, ScanBackend::SimdCpu));
    keyhog_scanner::testing::set_homoglyph_ascii_skip(scanner, Some(true));
    scanner.clear_fragment_cache();
    let on = canonical(&scanner.scan_with_backend(chunk, ScanBackend::SimdCpu));
    keyhog_scanner::testing::set_homoglyph_ascii_skip(scanner, None);
    keyhog_scanner::testing::set_phase2_hs(scanner, None);
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

// The SOUNDNESS gate for the `homoglyph_ascii_skip` optimization (now default ON).
// It PASSES: closing the base-AC coverage gap, phase-1 marks triggers with
// OVERLAPPING AC matching, so a detector whose base literal is shadowed by a
// longer literal (e.g. `secret` inside `client_secret`) is still AC-confirmed 
// made skip ≡ fold at the raw-match level on every ASCII chunk. This gate now
// guards that the skip stays recall-neutral: a divergence means a NEW shadow
// case the overlapping triggers don't cover, i.e. a real coverage regression,
// NOT a reason to weaken the test. Default `KEYHOG_PARITY_N` + corpus cap keep CI
// fast; set `KEYHOG_PARITY_N` higher for an exhaustive sweep.
#[test]
fn homoglyph_ascii_skip_parity_default() {
    let _telemetry_guard = super::super::telemetry_serial::lock();
    let scanner = scanner();
    scanner.clear_fragment_cache();

    let n: usize = std::env::var("KEYHOG_PARITY_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PARITY_N);
    let corpus_cap: usize = std::env::var("KEYHOG_PARITY_CORPUS_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_CORPUS_CAP);

    let deterministic_cases = deterministic_ascii_cases();
    for (i, bytes) in deterministic_cases.iter().enumerate() {
        assert!(bytes.is_ascii(), "deterministic case {i} must be ASCII");
        let chunk = chunk_of(bytes, &format!("deterministic-{i}"));
        let (on, off) = scan_both(scanner, &chunk);
        assert_eq!(on, off, "{}", report(&on, &off, bytes));
    }

    let mut rng = Lcg(0x1234_5678_9abc_def0);
    let mut checked = deterministic_cases.len();
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

    // Optional real mirror corpus sample. The full lib-test binary already runs
    // near the memory ceiling before this root-facade tail, so the default gate
    // uses deterministic token/context cases plus a bounded synthetic sweep.
    // `KEYHOG_PARITY_CORPUS_N` widens this half for dedicated parity runs.
    if let Some(root) = corpus_dir() {
        for (i, f) in corpus_files(&root, corpus_cap).into_iter().enumerate() {
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
    assert!(
        checked >= n + TOKENS.len(),
        "expected random sweep plus deterministic token coverage, got {checked}"
    );
}

/// SOUNDNESS gate for the HYPERSCAN homoglyph-ASCII skip (the lean ASCII sub-DB).
/// Mirrors `homoglyph_ascii_skip_parity_default` but drives the HS/`SimdCpu` path:
/// with the fix, marking ASCII chunks through the lean DB (which excludes the ~2.8k
/// homoglyph variants) must yield byte-identical `RawMatch` sets to the full DB, no
/// FP added, no TP dropped. Before the fix the HS path scanned the full DB on ASCII
/// (findings-identical but ~100-215× slower); this locks that the speed fix stayed
/// findings-neutral. A divergence names the exact detector+credential a homoglyph
/// variant catches on ASCII that the base path does not, a real gap, not a reason
/// to weaken the test.
#[test]
fn homoglyph_ascii_skip_parity_hs_backend() {
    let _telemetry_guard = super::super::telemetry_serial::lock();
    let scanner = scanner();
    scanner.clear_fragment_cache();

    let deterministic_cases = deterministic_ascii_cases();
    for (i, bytes) in deterministic_cases.iter().enumerate() {
        assert!(bytes.is_ascii(), "deterministic case {i} must be ASCII");
        let chunk = chunk_of(bytes, &format!("hs-deterministic-{i}"));
        let (on, off) = scan_both_hs(scanner, &chunk);
        assert_eq!(on, off, "HS backend: {}", report(&on, &off, bytes));
    }

    // Bounded synthetic ASCII sweep through the HS path (kept smaller than the
    // RegexSet default gate (this tail runs near the lib-test memory ceiling)).
    let mut rng = Lcg(0x0f0e_0d0c_0b0a_0908);
    let n: usize = std::env::var("KEYHOG_PARITY_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PARITY_N / 4);
    let mut checked = deterministic_cases.len();
    for i in 0..n {
        let bytes = gen_ascii_chunk(&mut rng);
        if !bytes.is_ascii() {
            continue;
        }
        let chunk = chunk_of(&bytes, &format!("hs-gen-{i}"));
        let (on, off) = scan_both_hs(scanner, &chunk);
        assert_eq!(on, off, "HS backend: {}", report(&on, &off, &bytes));
        checked += 1;
    }
    eprintln!(
        "homoglyph_ascii_skip_parity_hs_backend: {checked} ASCII inputs checked, HS skip ≡ full"
    );
}

/// The skip is gated on `chunk.is_ascii()`, so a chunk containing an actual
/// non-ASCII homoglyph must run the variant unchanged, the optimization never
/// touches the case homoglyph detection exists for.
#[test]
fn homoglyph_variant_unaffected_on_non_ascii() {
    let _telemetry_guard = super::super::telemetry_serial::lock();
    let scanner = scanner();
    scanner.clear_fragment_cache();
    // "аpi_key" with a Cyrillic 'а' (U+0430) (a non-ASCII chunk).
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
