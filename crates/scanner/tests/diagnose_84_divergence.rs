//! Focused diagnostic for task #84 — SIMD↔CpuFallback divergence on
//! prefix-storm inputs. Reproduces the proptest minimal-failing-input
//! and dumps the symmetric difference of credential findings so we can
//! see *which* credentials each backend misses.
//!
//! Run with: `cargo test --release --test diagnose_84_divergence -- --nocapture`
//!
//! Not gated on the divergence — this test PASSES even when the
//! divergence reproduces, because it's an investigation tool, not a
//! contract. The contract is in `gpu_proptest_invariants::p1b_…`.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

#[test]
fn diagnose_84_dump_simd_vs_cpu_diffs_on_known_seed() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    // Minimal failing seed lifted from the
    // gpu_proptest_invariants.proptest-regressions file (cc 5b3e2404…).
    // Heavy random ASCII followed by 4 KEY-line credentials.
    let input = "\n'\ny<\njQ\n]T\n\nn&oF\n-\n~\ni\n\ny\n\nP\n\n\nWK/\n\n\n\n\n\n\n\n\n\naBu!\n)\n\n\n[\n\"W5$~6'7k\npS\n\n\nt\n\n.\n\n\n\n\n\n\n<6f\n\nk\n\n%@\n\n\n\n\n\n2CE)\n1Z,\n-3\n\nc\nB\n\n\nK \nC\n>\n>\n\nkt\n8\n=\n\"C\n\nxa\nF\n\nI\"\n\n*\nt\nx{=\nn\n&\n\n[n$\n\n\n\n5f\nLt}\n8d\nu\n:K\n2z\n\n\n\"xNQ\n\n(\np-\n\nK\n\n.U\n6\n\n&\n*8\nI%\ns^\n1\n\na\n,\n\n|,\nd \nr<K.\n'\ny\ngg0 q\nH>\nWO\n\n\nq\n^\n\n\nc\n\nk\n\n+ \nu&\n+=#w\n\no\n]&\n\n1\n\nu`ig~!y\n\n\n\nZ>>\n\n\n\nflzF3r\nV5S\nB\nQ\nse[ ]\n\n^KEdB\n\nIb\n&x]\nY(\ng\nCz\nl\n(\"\n\nJ$\n\nY\nxC/\n\nn\n\"\n\n8\n?YO\n\n-\nNm\n\n\n)\nK\n\n\n\nd\nu\n\nC\n\n\n\n}A\njO:\n\n\n$;^\nJ\n\n\n0\nS\n\n\n~]\n[\ni|AfML~uD6\n=>\n%$\"\n3I\nx\nK\n\n\n\nq_jxm\nv\n\ni\ne\n\n3#\n\n\nG\n\nHZ\"Kw\ng%:vr\n/c\n-Tw<\ne\n\nz\nU#h7\"\n7\nI\"\n\n|1[\nRN\n\n\n\nS\n\nt\n#\no\n@io \n\n\n)t\n`F|\n\"S\nS\n\n5\n\n4{3\n;\n]L\n\nazP\n\nt\n*l\nh\ny)%<\nO\n\n\n\nx\n|X\n+\n*\n\n\ns\n\n|\n\n\n\n\n\\\n\n\n\n\n\n\nvUl72\n]:U\n{\n\n2s\nKFECU\n-}PJt\n\n\n\n9\nd\n\no\nUE{\n\n$\nr\n\n\n~\n\nr'w\nn\n\n\n;|\n\n@\n\n\n\n\n\n\nca\n\n\nd\n\nY# \n\nE\n\n\nA'\n\ny!,;6d)\n~\nu\n\nz?\n,\n\n1\n-\n\n*\n\n\nH\n\n\nf\n\n\n}\nRH\n<V9%,J\n\n\n\n@4\no8P]XO+\n\n\nSZ\nx~,\nr\nm\n\n\n\n'\nT\n\nq\n3+\nP\n\n2zf\n\n\nu\n\n\n\nLIc}\n\nZ$ \n\nDR\n4U]I\nKEY = \"gho_52455D4244AE411B43B445CCCCB\";\n\nKEY = \"ASIA15AED5E23EADBECBEDE22E54B2\";\n\nKEY = \"ghu_1335B1242D22CC233E415AE5351ED53C534BB\";\n\nKEY = \"xoxb-113C135A23A123EC3EBB3DD35B45415\";\n";

    let chunk = Chunk {
        data: input.into(),
        metadata: ChunkMetadata {
            source_type: "diagnose_84".into(),
            path: Some("seed.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    };

    let simd = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let cpu = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::CpuFallback);

    // Group findings by (detector, credential) so detector attribution
    // is visible too. The proptest only compares (credential, path,
    // offset) — if detectors differ but credentials match, the
    // proptest passes but the underlying engines still disagreed.
    let key = |chunks: &[Vec<keyhog_core::RawMatch>]| -> BTreeSet<(String, String, usize)> {
        chunks
            .iter()
            .flatten()
            .map(|m| {
                (
                    m.detector_id.as_ref().to_string(),
                    m.credential.as_ref().to_string(),
                    m.location.offset,
                )
            })
            .collect()
    };
    let simd_set = key(&simd);
    let cpu_set = key(&cpu);

    let only_simd: Vec<_> = simd_set.difference(&cpu_set).cloned().collect();
    let only_cpu: Vec<_> = cpu_set.difference(&simd_set).cloned().collect();

    println!(
        "diagnose_84: SIMD={} CPU={} common={} only-SIMD={} only-CPU={}",
        simd_set.len(),
        cpu_set.len(),
        simd_set.intersection(&cpu_set).count(),
        only_simd.len(),
        only_cpu.len()
    );
    println!("\n=== only in SIMD ({}): ===", only_simd.len());
    for (det, cred, off) in only_simd.iter().take(20) {
        println!("  [{det}] offset={off} cred={cred:?}");
    }
    println!("\n=== only in CpuFallback ({}): ===", only_cpu.len());
    for (det, cred, off) in only_cpu.iter().take(20) {
        println!("  [{det}] offset={off} cred={cred:?}");
    }
}
