//! Differential gate for the phase-2 prefix-literal skip gate: skipping an
//! always-active phase-2 batch whose patterns ALL provably require a prefix
//! literal that is absent from the chunk must NEVER change the finding set.
//! Scans each input with the gate ON vs OFF and asserts identical findings.
//!
//! The gate's whole reason to exist is the decode-recursion sub-chunks (most
//! carry no credential prefix at all), so the generators deliberately include
//! base64/hex-encoded secrets that only surface through decode-through — those
//! decoded sub-chunks are exactly where the gate skips the most work, and where
//! an unsound gate would silently drop recall.
//!
//! Big sweep:
//!   KEYHOG_GATE_PARITY_N=200000 cargo test --profile release-fast \
//!     -p keyhog-scanner --test phase2_prefix_gate_parity -- --nocapture

use super::support;
use support::paths::{corpus_dir, corpus_files, detector_dir};

use base64::Engine;
use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};

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

// Real-shaped secrets across literal-prefix detectors (the gateable homoglyph
// majority), no-literal shape detectors (asana-style, ungateable), site-specific
// confirmed detectors, and a private-key block (multiline). The point is to make
// the prefix gate decide "skip" on most chunks while still firing on these.
const TOKENS: &[&str] = &[
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB",
    "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789cd",
    "xoxb-1234567890-ABCDEFGHIJKLMNOPQRSTUVWX",
    "sk_live_0123456789abcdefABCDEFxyz0",
    "AKIAIOSFODNN7EXAMPLE",
    "glpat-abcdefghij1234567890ABCD",
    "key=AbCdEf0123456789AbCdEf0123 visualcrossing",
    "api_key=\"0123456789abcdef0123456789abcdef\" api.nasa.gov",
    "1/1234567890123456/abcdef0123456789abcdef0123456789",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj3aQ\n-----END RSA PRIVATE KEY-----",
    "plain text with no credential at all just words here",
];
// Filler that contains NONE of the credential prefixes, so a chunk of pure
// filler is exactly the "gate skips everything" case the optimization targets.
const FILLER: &[u8] =
    b"the quick brown fox jumps over lazy dogs 0123456789 path config value name index size\n";

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

fn gen(rng: &mut Lcg) -> Vec<u8> {
    let mut b = Vec::new();
    for _ in 0..rng.below(60) {
        b.push(FILLER[rng.below(FILLER.len())]);
    }
    let n_tokens = rng.below(3);
    for _ in 0..n_tokens {
        let tok = TOKENS[rng.below(TOKENS.len())];
        // 40% of the time, embed the secret base64-encoded inside an assignment
        // so it ONLY surfaces through decode-recursion (the gate's hot path).
        if rng.below(10) < 4 {
            b.extend_from_slice(b"data = \"");
            b.extend_from_slice(b64(tok).as_bytes());
            b.extend_from_slice(b"\"\n");
        } else {
            b.extend_from_slice(tok.as_bytes());
            b.push(b'\n');
        }
        for _ in 0..rng.below(40) {
            b.push(FILLER[rng.below(FILLER.len())]);
        }
    }
    b
}

fn chunk_of(bytes: &[u8], label: &str) -> Chunk {
    Chunk {
        data: String::from_utf8_lossy(bytes).into_owned().into(),
        metadata: ChunkMetadata {
            source_type: "gate".into(),
            path: Some(label.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

fn canonical(m: &[Vec<RawMatch>]) -> Vec<(String, String, String)> {
    let mut v: Vec<_> = m
        .iter()
        .flatten()
        .map(|x| {
            (
                x.detector_id.to_string(),
                x.credential.to_string(),
                format!("{:?}", x.location),
            )
        })
        .collect();
    v.sort();
    v
}

fn scan_both(
    s: &CompiledScanner,
    c: &Chunk,
) -> (Vec<(String, String, String)>, Vec<(String, String, String)>) {
    // The prefix gate lives in the legacy RegexSet prefilter path; force HS off
    // so this gate is actually exercised (the HS engine bypasses it).
    keyhog_scanner::testing::set_phase2_hs(&s, Some(false));
    keyhog_scanner::testing::set_phase2_prefix_gate(&s, Some(true));
    s.clear_fragment_cache();
    let on = canonical(&[s.scan_with_backend(c, ScanBackend::CpuFallback)]);
    keyhog_scanner::testing::set_phase2_prefix_gate(&s, Some(false));
    s.clear_fragment_cache();
    let off = canonical(&[s.scan_with_backend(c, ScanBackend::CpuFallback)]);
    (on, off)
}

fn diff_panic(label: &str, on: &[(String, String, String)], off: &[(String, String, String)]) {
    use std::collections::BTreeSet;
    let a: BTreeSet<_> = on.iter().collect();
    let o: BTreeSet<_> = off.iter().collect();
    eprintln!("PREFIX-GATE DIVERGENCE {label}");
    for x in o.difference(&a) {
        eprintln!("  MISSING with gate (RECALL LOSS!): {x:?}");
    }
    for x in a.difference(&o) {
        eprintln!("  EXTRA with gate: {x:?}");
    }
    panic!("phase-2 prefix gate changed findings on {label}");
}

#[test]
fn phase2_prefix_gate_parity_default() {
    let _telemetry_guard = super::super::telemetry_serial::lock();
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let n: usize = std::env::var("KEYHOG_GATE_PARITY_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);

    let mut rng = Lcg(0x5eed_face_d00d_1234);
    let mut checked = 0usize;
    for i in 0..n {
        let b = gen(&mut rng);
        let c = chunk_of(&b, &format!("syn-{i}"));
        let (on, off) = scan_both(&scanner, &c);
        if on != off {
            eprintln!(
                "input: {:?}",
                String::from_utf8_lossy(&b[..b.len().min(220)])
            );
            diff_panic(&format!("syn-{i}"), &on, &off);
        }
        checked += 1;
    }

    if let Some(root) = corpus_dir() {
        let files = corpus_files(&root, 6000);
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        let mut cur = Vec::new();
        for f in &files {
            cur.extend_from_slice(f);
            cur.push(b'\n');
            if cur.len() >= 16 * 1024 {
                chunks.push(std::mem::take(&mut cur));
            }
        }
        if !cur.is_empty() {
            chunks.push(cur);
        }
        for (i, c) in chunks.iter().enumerate() {
            let ch = chunk_of(c, &format!("corpus-{i}"));
            let (on, off) = scan_both(&scanner, &ch);
            if on != off {
                diff_panic(&format!("corpus-{i}"), &on, &off);
            }
            checked += 1;
        }
    }

    keyhog_scanner::testing::set_phase2_prefix_gate(&scanner, None);
    eprintln!("phase2_prefix_gate_parity: {checked} inputs, gate-on ≡ gate-off");
    assert!(checked >= n);
}
