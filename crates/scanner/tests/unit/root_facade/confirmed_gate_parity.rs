//! Differential gate for the confirmed-pass suffix gate: skipping a triggered
//! pattern whose required suffix literal is absent must NEVER change the finding
//! set. Scans each corpus chunk + generated inputs with the gate on vs off and
//! asserts identical findings.
//!
//! Run the big sweep:
//!   KEYHOG_GATE_PARITY_N=200000 cargo test --profile release-fast -p keyhog-scanner \
//!     --test confirmed_gate_parity -- --nocapture

use super::support;
use support::paths::{corpus_dir, corpus_files, detector_dir};

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::telemetry::{with_scan_telemetry, ScanTelemetry};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::Arc;

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

// Tokens that exercise site-specific suffix-gated detectors plus generic ones.
const TOKENS: &[&str] = &[
    "key=AbCdEf0123456789AbCdEf0123 visualcrossing",
    "api_key=\"0123456789abcdef0123456789abcdef\" api.nasa.gov",
    "API_KEY: 0123456789ABCDEFGHIJ weatherapi",
    "apikey=0123456789abcdef0123456789abcdef openai.com",
    "key=plainvaluewithnositename1234567890",
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB",
    "sk_live_0123456789abcdefABCDEFxyz0",
    "AKIAIOSFODNN7EXAMPLE",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj3\n-----END RSA PRIVATE KEY-----",
];
const FILLER: &[u8] =
    b"abcdefghijklmnopqrstuvwxyz 0123456789 \n\t=:;\"' config value path token secret key api\n";

fn gen(rng: &mut Lcg) -> Vec<u8> {
    let mut b = Vec::new();
    for _ in 0..rng.below(40) {
        b.push(FILLER[rng.below(FILLER.len())]);
    }
    for _ in 0..(rng.below(3) + 1) {
        b.extend_from_slice(TOKENS[rng.below(TOKENS.len())].as_bytes());
        b.push(b'\n');
        for _ in 0..rng.below(30) {
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
    keyhog_scanner::testing::set_confirmed_suffix_gate(&s, Some(true));
    s.clear_fragment_cache();
    let on_trace = Arc::new(ScanTelemetry::new());
    let on = with_scan_telemetry(&on_trace, || {
        canonical(&[s.scan_with_backend(c, ScanBackend::CpuFallback)])
    });
    keyhog_scanner::testing::set_confirmed_suffix_gate(&s, Some(false));
    s.clear_fragment_cache();
    let off_trace = Arc::new(ScanTelemetry::new());
    let off = with_scan_telemetry(&off_trace, || {
        canonical(&[s.scan_with_backend(c, ScanBackend::CpuFallback)])
    });
    (on, off)
}

#[test]
fn confirmed_gate_parity_default() {
    let _telemetry_guard = super::super::telemetry_serial::lock();
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let n: usize = std::env::var("KEYHOG_GATE_PARITY_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);

    let mut rng = Lcg(0xdead_beef_1234_5678);
    let mut checked = 0;
    for i in 0..n {
        let b = gen(&mut rng);
        let c = chunk_of(&b, &format!("syn-{i}"));
        let (on, off) = scan_both(&scanner, &c);
        if on != off {
            eprintln!(
                "GATE DIVERGENCE syn-{i}: {:?}",
                String::from_utf8_lossy(&b[..b.len().min(200)])
            );
            use std::collections::BTreeSet;
            let a: BTreeSet<_> = on.iter().collect();
            let o: BTreeSet<_> = off.iter().collect();
            for x in o.difference(&a) {
                eprintln!("  MISSING with gate (recall loss!): {x:?}");
            }
            for x in a.difference(&o) {
                eprintln!("  EXTRA with gate: {x:?}");
            }
            panic!("confirmed suffix gate changed findings on syn-{i}");
        }
        checked += 1;
    }
    if let Some(root) = corpus_dir() {
        let files = corpus_files(&root, 6000);
        let mut chunks = files.clone();
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
                eprintln!("GATE DIVERGENCE corpus-{i}");
                use std::collections::BTreeSet;
                let a: BTreeSet<_> = on.iter().collect();
                let o: BTreeSet<_> = off.iter().collect();
                for x in o.difference(&a) {
                    eprintln!("  MISSING with gate: {x:?}");
                }
                for x in a.difference(&o) {
                    eprintln!("  EXTRA with gate: {x:?}");
                }
                panic!("confirmed suffix gate changed findings on corpus-{i}");
            }
            checked += 1;
        }
    }
    keyhog_scanner::testing::set_confirmed_suffix_gate(&scanner, None);
    eprintln!("confirmed_gate_parity: {checked} inputs, gate-on ≡ gate-off");
    assert!(checked >= n);
}
