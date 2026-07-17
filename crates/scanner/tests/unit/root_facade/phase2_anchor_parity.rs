//! Differential parity gate: the shared-anchor phase-2 path must produce a
//! finding set IDENTICAL to the legacy whole-chunk path, on every input. Any
//! divergence is an unsound literal extraction (a dropped or extra match) and a
//! recall bug (the gate fails loudly with the offending input).
//!
//! Scans each input through residual Hyperscan, residual portable RegexSet, and
//! the legacy whole-chunk path, then compares the canonical
//! `(detector_id, credential)` multisets. Runs over a large seeded-synthetic
//! corpus that stresses the cursor-equivalence edges (adjacent/overlapping
//! tokens, offset 0, end-of-buffer, repeats, homoglyph noise, assignment
//! shapes, private-key blocks) plus the real mirror corpus when present.
//!
//! Run the big sweep:
//!   KEYHOG_PARITY_N=200000 cargo test --profile release-fast -p keyhog-scanner \
//!     --test phase2_anchor_parity -- --ignored --nocapture

use super::support;
use support::paths::{corpus_dir, corpus_files, detector_dir};

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScanExecutionRoute};
use std::sync::OnceLock;

/// Tiny deterministic LCG so the corpus is reproducible without a crate dep and
/// without the banned `Math.random`/time entropy.
struct Lcg(u64);
impl Lcg {
    fn next_u32(&mut self) -> u32 {
        // Numerical Recipes constants.
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

/// Representative secret shapes that route through the keyword/phase-2 path
/// (no usable literal *prefix* in keyhog's extractor, so they live in
/// `fallback`). Mix of service tokens, JWT, assignment shapes, and a key block.
const TOKENS: &[&str] = &[
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB",
    "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab",
    "ghs_0123456789abcdefABCDEF0123456789abcdef",
    "sk_live_0123456789abcdefABCDEFxyz0",
    "sk-ant-api03-AbCdEf0123456789AbCdEf0123456789AbCdEf",
    "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUv",
    "npm_abcdefghijklmnopqrstuvwxyz0123456789AB",
    "gsk_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQR",
    "AKIAIOSFODNN7EXAMPLE",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummY_sig_here",
    "token = \"s3cr3tV@lueABCDEFGH12345\"",
    "secret: 'topSecretValue0123456789'",
    "password=Hunter2Hunter2Hunter2xx",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Q\n-----END RSA PRIVATE KEY-----",
];

const DETECTOR_IDS: &[&str] = &[
    "github-classic-pat",
    "github-oauth-access-token",
    "github-app-installation-token",
    "stripe-secret-key",
    "anthropic-api-key",
    "slack-bot-token",
    "npm-access-token",
    "google-api-key",
    "aws-access-key",
    "private-key",
    "generic-password",
];

const DEFAULT_PARITY_N: usize = 256;
const DEFAULT_CORPUS_CAP: usize = 0;

const FILLER: &[u8] = b"abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789\n\t=:;,.\"'(){}[]/_- the quick brown fox config value path import export return function const let var\n";

/// Homoglyph bytes to occasionally sprinkle (Cyrillic/Greek lookalikes), so the
/// homoglyph detector variants are exercised on both paths.
const HOMOGLYPHS: &[&str] = &["А", "Е", "О", "Р", "ѕ", "к", "Ι", "Ν"];

fn gen_chunk(rng: &mut Lcg) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let kind = rng.below(8);
    let lead = rng.below(40);
    for _ in 0..lead {
        buf.push(FILLER[rng.below(FILLER.len())]);
    }
    let token_count = match kind {
        0 => 0,     // pure noise (exercises generic/entropy, no fallback)
        1 | 2 => 1, // single token
        3 => 4,     // repeats / adjacency
        _ => rng.below(3) + 1,
    };
    for t in 0..token_count {
        let tok = TOKENS[rng.below(TOKENS.len())];
        buf.extend_from_slice(tok.as_bytes());
        // Adjacent vs separated placement stresses cursor-advance equivalence.
        match rng.below(3) {
            0 => {} // immediately adjacent to next token
            1 => buf.push(b' '),
            _ => {
                let gap = rng.below(30);
                for _ in 0..gap {
                    buf.push(FILLER[rng.below(FILLER.len())]);
                }
            }
        }
        // Occasionally inject a homoglyph near the token.
        if kind == 5 && t == 0 {
            buf.extend_from_slice(HOMOGLYPHS[rng.below(HOMOGLYPHS.len())].as_bytes());
        }
    }
    let trail = rng.below(40);
    for _ in 0..trail {
        buf.push(FILLER[rng.below(FILLER.len())]);
    }
    // Sometimes a token sits exactly at offset 0 or at end-of-buffer.
    if kind == 6 {
        let tok = TOKENS[rng.below(TOKENS.len())];
        let mut prefixed = tok.as_bytes().to_vec();
        prefixed.extend_from_slice(&buf);
        buf = prefixed;
    }
    if kind == 7 {
        let tok = TOKENS[rng.below(TOKENS.len())];
        buf.extend_from_slice(tok.as_bytes());
    }
    buf
}

fn deterministic_cases() -> Vec<Vec<u8>> {
    let mut cases = Vec::new();
    for token in TOKENS {
        cases.push(token.as_bytes().to_vec());
        cases.push(format!("const value = {token};\n").into_bytes());
        cases.push(format!("client_secret = \"{token}\"\n").into_bytes());
        cases.push(format!("prefix token secret {token} suffix token\n").into_bytes());
        cases.push(format!("{token}{token}\n").into_bytes());
        cases.push(format!("{}\n{}\n", "a".repeat(128), token).into_bytes());
    }
    cases
}

fn chunk_of(bytes: &[u8], label: &str) -> Chunk {
    Chunk {
        data: String::from_utf8_lossy(bytes).into_owned().into(),
        metadata: ChunkMetadata {
            source_type: "phase2-parity".into(),
            path: Some(label.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

/// Canonical, order-independent representation of a finding set. Includes the
/// source location so a missed/extra match at a DIFFERENT offset (same
/// detector+credential) is still caught (recall is per-location).
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

fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let mut detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
        detectors.retain(|detector| DETECTOR_IDS.contains(&detector.id.as_str()));
        for id in DETECTOR_IDS {
            assert!(
                detectors.iter().any(|detector| detector.id == *id),
                "phase2 anchor parity detector subset missing shipped detector {id}"
            );
        }
        CompiledScanner::compile(detectors).expect("compile")
    })
}

struct PathResults {
    localized_hs: Vec<Key>,
    anchor_hs: Vec<Key>,
    requested_localizer_gate_off: Vec<Key>,
    localized_portable: Vec<Key>,
    whole: Vec<Key>,
}

fn scan_paths(scanner: &CompiledScanner, chunk: &Chunk) -> PathResults {
    // Clear the cross-chunk fragment-reassembly cache between scans:
    // it persists on the scanner across calls, so scanning the SAME chunk twice
    // back-to-back would let the first scan's reassembly state perturb the
    // second (a test-only hazard, in production each chunk is scanned once and
    // the cache evolves identically for a fixed anchor setting).
    // Optimized plan through the residual Hyperscan engine.
    keyhog_scanner::testing::set_phase2_anchor_mode(&scanner, Some(true));
    keyhog_scanner::testing::set_phase2_homoglyph_gate(&scanner, Some(true));
    keyhog_scanner::testing::set_phase2_hs(&scanner, Some(true));
    scanner.clear_fragment_cache();
    let optimized_hs = scanner.scan_coalesced_with_backend_admission_and_route(
        std::slice::from_ref(chunk),
        ScanBackend::CpuFallback,
        None,
        ScanExecutionRoute {
            phase2_localizer: true,
        },
    );
    // Main-anchor residual only: case-sensitive patterns remain in the
    // prefilter because the optional plain localizer is off.
    scanner.clear_fragment_cache();
    let anchor_hs = scanner.scan_coalesced_with_backend_admission_and_route(
        std::slice::from_ref(chunk),
        ScanBackend::CpuFallback,
        None,
        ScanExecutionRoute {
            phase2_localizer: false,
        },
    );
    // A route request cannot remove plain patterns when the runtime gate that
    // executes the plain localizer is disabled.
    keyhog_scanner::testing::set_phase2_homoglyph_gate(&scanner, Some(false));
    scanner.clear_fragment_cache();
    let requested_localizer_gate_off = scanner.scan_coalesced_with_backend_admission_and_route(
        std::slice::from_ref(chunk),
        ScanBackend::CpuFallback,
        None,
        ScanExecutionRoute {
            phase2_localizer: true,
        },
    );
    // The same residual ownership plan through the portable RegexSet engine.
    keyhog_scanner::testing::set_phase2_homoglyph_gate(&scanner, Some(true));
    keyhog_scanner::testing::set_phase2_hs(&scanner, Some(false));
    scanner.clear_fragment_cache();
    let optimized_portable = scanner.scan_coalesced_with_backend_admission_and_route(
        std::slice::from_ref(chunk),
        ScanBackend::CpuFallback,
        None,
        ScanExecutionRoute {
            phase2_localizer: true,
        },
    );
    // Fully-unoptimized baseline: every phase-2 pattern runs the legacy
    // whole-chunk path, including every homoglyph variant on every chunk.
    keyhog_scanner::testing::set_phase2_anchor_mode(&scanner, Some(false));
    keyhog_scanner::testing::set_phase2_homoglyph_gate(&scanner, Some(false));
    scanner.clear_fragment_cache();
    let baseline = scanner.scan_coalesced_with_backend_admission_and_route(
        std::slice::from_ref(chunk),
        ScanBackend::CpuFallback,
        None,
        ScanExecutionRoute {
            phase2_localizer: false,
        },
    );
    assert!(!scanner.default_execution_route().phase2_localizer);
    PathResults {
        localized_hs: canonical(&optimized_hs),
        anchor_hs: canonical(&anchor_hs),
        requested_localizer_gate_off: canonical(&requested_localizer_gate_off),
        localized_portable: canonical(&optimized_portable),
        whole: canonical(&baseline),
    }
}

fn assert_corpus(scanner: &CompiledScanner, files: &[Vec<u8>], tag: &str) -> usize {
    let mut checked = 0;
    for (i, f) in files.iter().enumerate() {
        let chunk = chunk_of(f, &format!("{tag}-{i}"));
        let paths = scan_paths(scanner, &chunk);
        if paths.localized_hs != paths.whole {
            report_divergence(&paths.localized_hs, &paths.whole, f);
            panic!("PARITY VIOLATION on {tag}-{i}: anchored HS != whole-chunk phase-2");
        }
        if paths.anchor_hs != paths.whole {
            report_divergence(&paths.anchor_hs, &paths.whole, f);
            panic!("PARITY VIOLATION on {tag}-{i}: anchor-only HS != whole-chunk phase-2");
        }
        if paths.requested_localizer_gate_off != paths.whole {
            report_divergence(&paths.requested_localizer_gate_off, &paths.whole, f);
            panic!("PARITY VIOLATION on {tag}-{i}: disabled localizer gate dropped a finding");
        }
        if paths.localized_portable != paths.whole {
            report_divergence(&paths.localized_portable, &paths.whole, f);
            panic!("PARITY VIOLATION on {tag}-{i}: anchored portable != whole-chunk phase-2");
        }
        checked += 1;
    }
    checked
}

fn report_divergence(anchored: &[Key], whole: &[Key], input: &[u8]) {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<&Key, (i64, i64)> = BTreeMap::new();
    for k in anchored {
        counts.entry(k).or_default().0 += 1;
    }
    for k in whole {
        counts.entry(k).or_default().1 += 1;
    }
    eprintln!("--- PARITY DIVERGENCE ---");
    eprintln!(
        "input ({} bytes): {:?}",
        input.len(),
        String::from_utf8_lossy(&input[..input.len().min(200)])
    );
    for (k, (a, w)) in counts {
        if a != w {
            let tag = if w > a {
                "MISSING in anchored (recall loss!)"
            } else {
                "EXTRA in anchored"
            };
            eprintln!(
                "  [{tag}] anchored×{a} whole×{w}  det={} cred={:.40} loc={}",
                k.0, k.1, k.2
            );
        }
    }
}

fn synthetic(scanner: &CompiledScanner, n: usize) -> usize {
    let mut rng = Lcg(0x1234_5678_9abc_def0);
    let mut checked = 0;
    for i in 0..n {
        let bytes = gen_chunk(&mut rng);
        let chunk = chunk_of(&bytes, &format!("syn-{i}"));
        let paths = scan_paths(scanner, &chunk);
        if paths.localized_hs != paths.whole {
            report_divergence(&paths.localized_hs, &paths.whole, &bytes);
            panic!("PARITY VIOLATION on synthetic input #{i}: residual HS");
        }
        if paths.anchor_hs != paths.whole {
            report_divergence(&paths.anchor_hs, &paths.whole, &bytes);
            panic!("PARITY VIOLATION on synthetic input #{i}: anchor-only HS");
        }
        if paths.requested_localizer_gate_off != paths.whole {
            report_divergence(&paths.requested_localizer_gate_off, &paths.whole, &bytes);
            panic!("PARITY VIOLATION on synthetic input #{i}: disabled localizer gate");
        }
        if paths.localized_portable != paths.whole {
            report_divergence(&paths.localized_portable, &paths.whole, &bytes);
            panic!("PARITY VIOLATION on synthetic input #{i}: residual portable");
        }
        checked += 1;
    }
    checked
}

/// Isolated fallback-pass diff on the mirror-16k chunks: compares ONLY
/// `scan_phase2_patterns` output (no reassembly/decode), so it names the
/// exact detector whose raw match set diverges.
#[test]
#[ignore = "diagnostic; run with --ignored --nocapture"]
fn phase2_only_diff_mirror() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let Some(root) = corpus_dir() else {
        eprintln!("no corpus; skipping");
        return;
    };
    let files = corpus_files(&root, 6000);
    let mut chunks_16k: Vec<Vec<u8>> = Vec::new();
    let mut cur = Vec::new();
    for f in &files {
        cur.extend_from_slice(f);
        cur.push(b'\n');
        if cur.len() >= 16 * 1024 {
            chunks_16k.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        chunks_16k.push(cur);
    }
    let mut diverged = 0;
    for (i, c) in chunks_16k.iter().enumerate() {
        let chunk = chunk_of(c, &format!("mirror-16k-{i}"));
        keyhog_scanner::testing::set_phase2_anchor_mode(&scanner, Some(true));
        let a = scanner.debug_scan_phase2_only(&chunk);
        keyhog_scanner::testing::set_phase2_anchor_mode(&scanner, Some(false));
        let w = scanner.debug_scan_phase2_only(&chunk);
        let ak = canonical(&[a]);
        let wk = canonical(&[w]);
        if ak != wk {
            diverged += 1;
            eprintln!("== chunk {i} FALLBACK-ONLY divergence ==");
            report_divergence(&ak, &wk, c);
            if diverged >= 5 {
                break;
            }
        }
    }
    keyhog_scanner::testing::set_phase2_anchor_mode(&scanner, None);
    eprintln!("phase2-only diff: {diverged} diverging chunks");
}

#[test]
fn phase2_anchor_parity_default() {
    let _telemetry_guard = super::super::telemetry_serial::lock();
    let scanner = scanner();
    scanner.clear_fragment_cache();

    // Default in-CI sweep: deterministic token/edge coverage plus bounded
    // seeded synthetic inputs. The full detector/corpus binary already runs near
    // the memory ceiling before this tail; `KEYHOG_PARITY_N` and
    // `KEYHOG_PARITY_CORPUS_N` widen the sweep for dedicated parity runs.
    let n: usize = std::env::var("KEYHOG_PARITY_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PARITY_N);
    let corpus_cap: usize = std::env::var("KEYHOG_PARITY_CORPUS_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_CORPUS_CAP);

    let deterministic_cases = deterministic_cases();
    let mut checked = assert_corpus(scanner, &deterministic_cases, "deterministic");
    checked += synthetic(scanner, n);

    if corpus_cap > 0 {
        // 16 KiB-concatenated chunks (the target size class) + raw small files.
        let root = corpus_dir().expect("corpus cap requested but mirror corpus is unavailable");
        let files = corpus_files(&root, corpus_cap);
        checked += assert_corpus(scanner, &files, "mirror-small");
        let mut chunks_16k: Vec<Vec<u8>> = Vec::new();
        let mut cur = Vec::new();
        for f in &files {
            cur.extend_from_slice(f);
            cur.push(b'\n');
            if cur.len() >= 16 * 1024 {
                chunks_16k.push(std::mem::take(&mut cur));
            }
        }
        if !cur.is_empty() {
            chunks_16k.push(cur);
        }
        checked += assert_corpus(scanner, &chunks_16k, "mirror-16k");
    }

    // Restore this scanner's overrides to "follow env" (instance-local; with
    // per-scanner tuning there is no cross-test global to leak, but keep the
    // pairing explicit).
    keyhog_scanner::testing::set_phase2_anchor_mode(scanner, None);
    keyhog_scanner::testing::set_phase2_homoglyph_gate(scanner, None);
    keyhog_scanner::testing::set_phase2_hs(scanner, None);
    eprintln!("phase2_anchor_parity: {checked} inputs checked, optimized ≡ baseline");
    assert!(
        checked >= n + TOKENS.len(),
        "expected random sweep plus deterministic token coverage, ran {checked}"
    );
}
