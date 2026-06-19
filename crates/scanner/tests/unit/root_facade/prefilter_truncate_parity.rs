//! Differential gate for the prefilter `{N,}`→`{N}` truncation: replacing the
//! always-active prefilter RegexSet with its truncated-at-first-unbounded-repeat
//! SUPERSET (kept on the lazy-DFA) must NEVER change the finding set. The
//! truncated set may mark MORE patterns active, but extraction runs the FULL
//! pattern and filters the extras, so findings are identical. Scans each input
//! with truncation ON vs OFF and asserts equality.
//!
//! Big sweep:
//!   KEYHOG_GATE_PARITY_N=200000 cargo test --profile release-fast \
//!     -p keyhog-scanner --test prefilter_truncate_parity -- --nocapture

use super::support;
use support::paths::{corpus_dir, detector_dir};

use base64::Engine;
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

// Secrets across literal-prefix (homoglyph plain), no-literal shape, and
// site-specific detectors, plus a private key. Some embedded base64/hex so the
// decode sub-chunk phase-2 path (where the prefilter also runs) is exercised.
const TOKENS: &[&str] = &[
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB",
    "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789cd",
    "xoxb-1234567890-ABCDEFGHIJKLMNOPQRSTUVWX",
    "sk_live_0123456789abcdefABCDEFxyz0",
    "AKIAIOSFODNN7EXAMPLE",
    "glpat-abcdefghij1234567890ABCD",
    "AIzaSyA1234567890abcdefABCDEF_ghijklmno",
    "key=AbCdEf0123456789AbCdEf0123 visualcrossing",
    "1/1234567890123456/abcdef0123456789abcdef0123456789",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj3aQ\n-----END RSA PRIVATE KEY-----",
];
const FILLER: &[u8] =
    b"the quick brown fox token secret key api password value config path index name 0123\n";

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

fn gen(rng: &mut Lcg) -> Vec<u8> {
    let mut b = Vec::new();
    for _ in 0..rng.below(70) {
        b.push(FILLER[rng.below(FILLER.len())]);
    }
    for _ in 0..rng.below(3) {
        let tok = TOKENS[rng.below(TOKENS.len())];
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
            source_type: "trunc".into(),
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
    // Truncation is a legacy RegexSet-prefilter lever; force HS off so it runs.
    keyhog_scanner::testing::set_phase2_hs(&s, Some(false));
    keyhog_scanner::testing::set_prefilter_truncate(&s, Some(true));
    s.clear_fragment_cache();
    let on =
        canonical(&s.scan_chunks_with_backend(std::slice::from_ref(c), ScanBackend::CpuFallback));
    keyhog_scanner::testing::set_prefilter_truncate(&s, Some(false));
    s.clear_fragment_cache();
    let off =
        canonical(&s.scan_chunks_with_backend(std::slice::from_ref(c), ScanBackend::CpuFallback));
    (on, off)
}

fn diff_panic(label: &str, on: &[(String, String, String)], off: &[(String, String, String)]) {
    use std::collections::BTreeSet;
    let a: BTreeSet<_> = on.iter().collect();
    let o: BTreeSet<_> = off.iter().collect();
    eprintln!("PREFILTER-TRUNCATE DIVERGENCE {label}");
    for x in o.difference(&a) {
        eprintln!("  MISSING with truncation (RECALL LOSS!): {x:?}");
    }
    for x in a.difference(&o) {
        eprintln!("  EXTRA with truncation: {x:?}");
    }
    panic!("prefilter truncation changed findings on {label}");
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

#[test]
fn prefilter_truncate_parity_default() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let n: usize = std::env::var("KEYHOG_GATE_PARITY_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);

    let mut rng = Lcg(0x7c0de_5eed_1234);
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
        let files = collect_files(&root, 6000);
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

    keyhog_scanner::testing::set_prefilter_truncate(&scanner, None);
    eprintln!("prefilter_truncate_parity: {checked} inputs, truncate-on ≡ truncate-off");
    assert!(checked >= n);
}
