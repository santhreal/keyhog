//! Regression for the former SIMD↔CpuFallback divergence on prefix-storm
//! inputs. The minimized hostile seed is retained as evidence, and every run
//! now requires exact complete-finding parity rather than printing a diagnostic
//! while passing on divergence.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
#[test]
fn prefix_storm_seed_has_exact_repeatable_cpu_backend_parity() {
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

    let canonical = |chunks: &[Vec<keyhog_core::RawMatch>]| {
        let mut findings = chunks.iter().flatten().cloned().collect::<Vec<_>>();
        findings.sort();
        findings
    };

    // Reuse the same scanner so residual per-scan state cannot hide behind a
    // fresh compile. Full RawMatch equality also preserves multiplicity.
    for round in 0..5 {
        scanner.clear_fragment_cache();
        let simd = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
        scanner.clear_fragment_cache();
        let cpu = scanner.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::CpuFallback);
        let simd = canonical(&simd);
        let cpu = canonical(&cpu);
        assert_eq!(
            simd, cpu,
            "prefix-storm round {round} diverged between SimdCpu and CpuFallback"
        );
    }
}
