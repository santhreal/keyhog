//! Focused diagnostic for task #84 - SIMD↔CpuFallback divergence on
//! prefix-storm inputs. Reproduces the proptest minimal-failing-input
//! and dumps the symmetric difference of credential findings so we can
//! see *which* credentials each backend misses.
//!
//! Run with: `cargo test --release --test diagnose_84_divergence -- --nocapture`
//!
//! Not gated on the divergence - this test PASSES even when the
//! divergence reproduces, because it's an investigation tool, not a
//! contract. The contract is in `gpu_proptest_invariants::p1b_…`.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::collections::BTreeSet;
#[test]
fn diagnose_84_dump_simd_vs_cpu_diffs_on_known_seed() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    // Minimal failing seed lifted from the
    // gpu_proptest_invariants.proptest-regressions file (cc 5b3e2404…).
    // Heavy random ASCII followed by 4 KEY-line credentials.
    // Shrunken seed from the proptest P1b regression file (cc 80c8e2…).
    let input = "\nnI\nN\n\n\n)\n\nZ\np\nZcg6D$\n\n\n-\n\n\nI.FZ\"o\n\n\n(\n\neqe\nqb\n\n*\n\n\n\n \n\nTr\nQ\nd\n>u\nM\nUz5\n\nN\n5{\n\n\n\nt>\n\n\nR\n\n_ro%T\n\n\n=\n\n\ng\n\n\nU^<.\n\n\n\n\n\n2;D<_\n*\n>r!\n3\n\nH1J\n|\n\n\"C\n\nO\nF\n/6\n\n\n*K\n52n\n\n\nFQ\n#v\nK\n\n\nd\nmC\n\n\n\n\n9\n\n2mEg&aP\n&\n1\n:HN\n\nK]]Pt0I'\ny\nBG}{\n\nc?\n\nm,\n\n@\n\n,\nyT`\n\n\n\n}\n\n\nBH\n\nO\np\n\n\nj\n\n\n\n\n-.Y\n4\n]TtZ)\n\n*\n9\n^\nJ\n\nhx\n\n\n/\n9V\n\n7\n\nx-\nK\n\ns[\nR\n\n;\ndH\nX\nxRi\n%\n}rZ\nKi@\n\n\n.w&\n\"\\1\n\n^0\n`\n\n\n\nG\n\n4*x9\n\nC\n\num\nzx\n\n\nz5\n\nw\n&|:\nc\n\n\nd\n.\n\nnn\n/\nX\nuIs\n=E\nk\n\n\n\n;\n3S4 .W/V\n\n.X\nXS\n\n5$\nO\n\n\n\n^F\n\nK\n\n\nM\n8\n\n\nQ\ny\nG,\n=\n 7+V\nm\nPK\n^\n\n\nFr\n\n\n\n\\\nH}\ngGRsKcY5S\n9\nR\n1\nZ\nI/\nP\nWw4\n\n\ns\n\na\n\n\n\"\n\n:\n\n\n\nku\n\n\n`H\n\n\n\n\n\n/k\n\n\nF\n\n;\n\nK\n\n\nr\n\nAE\n_fO\n\no\n\n>\n1\n-y\n\nA{5\n\n\n\n\nc<?XJ\n&5\n\n\n\n\n\ny\n\n4\n\n6Sd\n9T=SP\n.by\nm!\n4+r\nn\n\n\nRvYH\n}0*|\n\nv\n\nDyo=`{\n\n\n\n\n\nXd\nK\n\nKQ\n\noO\n\nm\n4r\n*\n\n\n\n\n\n\n\n\n\n3P.i\n\nA\n\n\\!\n\n $)\n!3;(E[\np\n\nlD-\n77:o\n77\n\n\n.45N\n\n)+\n5Y!6$f\n\nYF\nK\n2\n\n\n\nL\n\n\n\nma\n\nT\n\ne\nU\n9\n\ns\nT2}\nz\n\n\n-\n\n\nz\n5\n\n@\n\n6Q\nQ\n0\n<$\ncTz;F\n\n\n\n\n8S\n\n\nfo_\n\n\n\nY\nO\n3I\n\n\n\n\n=Y\n^\nh\nz_\n\n\nt\n\\2\ns:6-\n\n,\n\nKu1*\nFM3\n\n>\n\n^fF\n\n\n!\n%:5f&d\n)B\n\n2\nu(+5\n$W\n\n\n_\n\n\n\n\n\nT^\nG \n\nSf}\n\n\napp\n;\na_:\n\nL\n_\n\n\n\n\nT|\nDL\n\nG\n\n}Y\n\n\n\n\n}\n\n\n1\n$9\n_\n <[\n\nk%\n\n\nV\nI6hZuD\n!n;\n>^7\nN1\n\n\n\nek`\nc-\n\n.)<\n\n,\n+rW\n_c\n\n(\n\nB:FQRX\n\ns\n\n\n+8\n@2\n\ne\n\nq\n\n$\nL[\nNj\n\n|e\n4I\n\\\n8T)\n<\nM-\n\n\nA_\n\n\n_leQ2i7\nM\nql!\n~\n\n|u}xD\nZI\n9\nI\nv\n\n\nd\n\nI\n0<m9\nd\"\n\nKH\n\n\n\n:\n?\n\n\\0\n\n%\n\nj\n\n\n'\nT\n-\n\n>ZQv30+l\nXL\n|*L\n\n\n\nv\n\n\nk-JS}<\n\n'\n+\na\n*\n<\nUP\nKEY = \"ASIA3A5D52AEE3\";\n\nKEY = \"AKIAE3D154BBAA4CE41B4E\";\n\nKEY = \"sk_live_13E332A242AAB1EBD3124DA33BA543B2A5EDBD4\";\n";

    let chunk = Chunk {
        data: input.into(),
        metadata: ChunkMetadata {
            source_type: "diagnose_84".into(),
            path: Some("seed.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    };

    scanner.clear_fragment_cache();
    let simd = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    scanner.clear_fragment_cache();
    let cpu = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::CpuFallback);

    // Group findings by (detector, credential) so detector attribution
    // is visible too. The proptest only compares (credential, path,
    // offset) - if detectors differ but credentials match, the
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

    // Now run the same comparison 5 times in a row on the SAME scanner
    // (the proptest re-uses one scanner across 64 cases) to surface
    // any cross-case state leak. If the first pass is clean but later
    // passes diverge, the bug is in residual scanner state - not in
    // the engine logic itself.
    for round in 1..=5 {
        scanner.clear_fragment_cache();
        let simd = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
        scanner.clear_fragment_cache();
        let cpu = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::CpuFallback);
        let s = key(&simd);
        let c = key(&cpu);
        let only_s = s.difference(&c).count();
        let only_c = c.difference(&s).count();
        println!(
            "round {round}: SIMD={} CPU={} common={} only-SIMD={only_s} only-CPU={only_c}",
            s.len(),
            c.len(),
            s.intersection(&c).count()
        );
        if only_s > 0 || only_c > 0 {
            println!("  DIVERGENCE first appeared in round {round}");
            for (det, cred, off) in s.difference(&c).take(10) {
                println!("    SIMD-only: [{det}] off={off} cred={cred:?}");
            }
            for (det, cred, off) in c.difference(&s).take(10) {
                println!("    CPU-only : [{det}] off={off} cred={cred:?}");
            }
            break;
        }
    }
}
