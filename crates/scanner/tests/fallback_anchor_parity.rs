//! Differential parity gate: the shared-anchor fallback path must produce a
//! finding set IDENTICAL to the legacy whole-chunk path, on every input. Any
//! divergence is an unsound literal extraction (a dropped or extra match) and a
//! recall bug — the gate fails loudly with the offending input.
//!
//! Scans each input twice in one process via `set_fallback_anchor_mode`
//! (forcing anchored on, then off) and compares the canonical
//! `(detector_id, credential)` multisets. Runs over a large seeded-synthetic
//! corpus that stresses the cursor-equivalence edges (adjacent/overlapping
//! tokens, offset 0, end-of-buffer, repeats, homoglyph noise, assignment
//! shapes, private-key blocks) plus the real mirror corpus when present.
//!
//! Run the big sweep:
//!   KEYHOG_PARITY_N=200000 cargo test --profile release-fast -p keyhog-scanner \
//!     --test fallback_anchor_parity -- --ignored --nocapture

mod support;
use support::paths::{corpus_dir, detector_dir};

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{
    set_fallback_anchor_mode, set_fallback_homoglyph_gate, CompiledScanner, ScanBackend,
};
use std::path::PathBuf;

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

/// Representative secret shapes that route through the keyword/fallback path
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

fn chunk_of(bytes: &[u8], label: &str) -> Chunk {
    Chunk {
        data: String::from_utf8_lossy(bytes).into_owned().into(),
        metadata: ChunkMetadata {
            source_type: "fallback-parity".into(),
            path: Some(label.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

/// Canonical, order-independent representation of a finding set. Includes the
/// source location so a missed/extra match at a DIFFERENT offset (same
/// detector+credential) is still caught — recall is per-location.
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

fn scan_both(scanner: &CompiledScanner, chunk: &Chunk) -> (Vec<Key>, Vec<Key>) {
    // Clear the cross-chunk fragment-reassembly cache between the two scans:
    // it persists on the scanner across calls, so scanning the SAME chunk twice
    // back-to-back would let the first scan's reassembly state perturb the
    // second (a test-only hazard — in production each chunk is scanned once and
    // the cache evolves identically for a fixed anchor setting).
    // Shipping config: shared-anchor localization ON + homoglyph ASCII-gate ON.
    set_fallback_anchor_mode(Some(true));
    set_fallback_homoglyph_gate(Some(true));
    scanner.clear_fragment_cache();
    let optimized =
        scanner.scan_chunks_with_backend(std::slice::from_ref(chunk), ScanBackend::CpuFallback);
    // Fully-unoptimized baseline: every fallback pattern runs the legacy
    // whole-chunk path, including every homoglyph variant on every chunk.
    set_fallback_anchor_mode(Some(false));
    set_fallback_homoglyph_gate(Some(false));
    scanner.clear_fragment_cache();
    let baseline =
        scanner.scan_chunks_with_backend(std::slice::from_ref(chunk), ScanBackend::CpuFallback);
    (canonical(&optimized), canonical(&baseline))
}

fn assert_corpus(scanner: &CompiledScanner, files: &[Vec<u8>], tag: &str) -> usize {
    let mut checked = 0;
    for (i, f) in files.iter().enumerate() {
        let chunk = chunk_of(f, &format!("{tag}-{i}"));
        let (anchored, whole) = scan_both(scanner, &chunk);
        if anchored != whole {
            report_divergence(&anchored, &whole, f);
            panic!("PARITY VIOLATION on {tag}-{i}: anchored != whole-chunk fallback");
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
        let (anchored, whole) = scan_both(scanner, &chunk);
        if anchored != whole {
            report_divergence(&anchored, &whole, &bytes);
            panic!("PARITY VIOLATION on synthetic input #{i}");
        }
        checked += 1;
    }
    checked
}

fn collect_files(root: &PathBuf, limit: usize) -> Vec<Vec<u8>> {
    let mut files = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
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

/// Isolated fallback-pass diff on the mirror-16k chunks: compares ONLY
/// `scan_fallback_patterns` output (no reassembly/decode), so it names the
/// exact detector whose raw match set diverges.
#[test]
#[ignore = "diagnostic; run with --ignored --nocapture"]
fn fallback_only_diff_mirror() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let Some(root) = corpus_dir() else {
        eprintln!("no corpus; skipping");
        return;
    };
    let files = collect_files(&root, 6000);
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
        set_fallback_anchor_mode(Some(true));
        let a = scanner.debug_scan_fallback_only(&chunk);
        set_fallback_anchor_mode(Some(false));
        let w = scanner.debug_scan_fallback_only(&chunk);
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
    set_fallback_anchor_mode(None);
    eprintln!("fallback-only diff: {diverged} diverging chunks");
}

#[test]
fn fallback_anchor_parity_default() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Default in-CI sweep: enough synthetic inputs to cover the cursor edges,
    // plus the mirror corpus when available. The `KEYHOG_PARITY_N` env scales
    // this to the 100k+ exhaustive sweep on demand.
    let n: usize = std::env::var("KEYHOG_PARITY_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);

    let mut checked = synthetic(&scanner, n);

    if let Some(root) = corpus_dir() {
        // 16 KiB-concatenated chunks (the target size class) + raw small files.
        let files = collect_files(&root, 6000);
        checked += assert_corpus(&scanner, &files, "mirror-small");
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
        checked += assert_corpus(&scanner, &chunks_16k, "mirror-16k");
    }

    // Restore the env-driven defaults for any later test in the binary.
    set_fallback_anchor_mode(None);
    set_fallback_homoglyph_gate(None);
    eprintln!("fallback_anchor_parity: {checked} inputs checked, optimized ≡ baseline");
    assert!(
        checked >= n,
        "expected at least {n} parity checks, ran {checked}"
    );
}
