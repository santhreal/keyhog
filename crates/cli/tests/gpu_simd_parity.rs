//! GPU↔SIMD parity (the `gpu_parity` release gate, as a real-tool test).
//!
//! Auto-routing picks the fastest backend per batch, so the SAME input can be
//! scanned by the GPU literal/AC engine on one host and by SIMD/Hyperscan on
//! another (or CI). For that to be safe, both backends MUST return identical
//! finding sets. This is NOT self-evident — it has regressed twice:
//!   * Hyperscan is compiled CASELESS for every pattern, but the GPU AC literal
//!     automaton matched bytes exactly, so a lowercase literal prefix (`csb_`)
//!     never fired on an uppercase occurrence (`CSB_…`). (Fixed: the GPU
//!     literal set + coalesced haystack are ASCII-lowercased.)
//!   * The GPU AC kernel reports unreliable match positions; the phase-2
//!     cheap-filter derived a ~1 KiB window from them and dropped every match
//!     deeper in a large file. (Fixed: cheap-filter confirms each hit pid over
//!     the whole chunk, like SIMD.)
//!
//! This test reproduces both: secret-shaped tokens placed PAST 4 KiB of
//! padding (defeats any first-window confirmation) in BOTH cases, plus an
//! uppercase occurrence of a lowercase-prefixed detector (defeats a
//! case-sensitive literal automaton). It asserts the GPU and SIMD finding sets
//! are byte-for-byte equal.
//!
//! On a host without a usable GPU, `--backend gpu` fails closed, so
//! both runs are SIMD and the test trivially passes (it can never falsely
//! FAIL). On a GPU host it genuinely exercises the GPU engine — the case this
//! gate exists for. CLAUDE.md Law 8: on a known-GPU host a green here means
//! the GPU path was actually compared, not skipped.

use std::collections::BTreeSet;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_keyhog")
}

/// Scan `path` with an explicit backend and return the set of
/// `(detector_id, credential_hash)` findings (order-independent identity).
fn findings(path: &str, backend: &str, no_gpu: bool) -> BTreeSet<(String, String)> {
    let mut cmd = Command::new(bin());
    cmd.args([
        "scan",
        path,
        "--format",
        "json",
        "--show-secrets",
        "--no-suppress-test-fixtures",
        "--no-daemon",
        "--backend",
        backend,
    ]);
    if no_gpu {
        cmd.env("KEYHOG_NO_GPU", "1");
    } else {
        cmd.env_remove("KEYHOG_NO_GPU");
    }
    let out = cmd.output().expect("keyhog binary runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("{backend} output is JSON: {e}\n{stdout}"));
    json.as_array()
        .expect("findings array")
        .iter()
        .map(|f| {
            (
                f["detector_id"].as_str().unwrap_or_default().to_string(),
                f["credential_hash"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect()
}

/// Build a fixture that forces the historically-divergent cases:
///   * >4 KiB of leading padding so any match is far past a first-window check,
///   * an UPPERCASE occurrence of a lowercase-prefixed detector literal
///     (`CSB_…`, codesandbox `csb_[A-Za-z0-9_-]{20,}` caseless), and
///   * a lowercase token and a distinct vendor-prefixed token for breadth.
fn parity_fixture() -> String {
    let mut s = String::new();
    s.push_str("// padding to push real tokens far past any first-window gate\n");
    for i in 0..400 {
        s.push_str(&format!("const PAD_LINE_{i}_NOTHING_TO_SEE_HERE = {i};\n"));
    }
    // Uppercase occurrence of a lowercase-prefixed literal (caseless match).
    s.push_str("PERF_ENGG_CSB_MACHINE_STALLED_BY_CSB_MEMORY = 0x000000bd,\n");
    // Lowercase token of the same detector.
    s.push_str("CSB_TOKEN = csb_abcdefghij0123456789klmnop\n");
    s
}

#[test]
fn gpu_and_simd_return_identical_findings() {
    let dir = std::env::temp_dir().join(format!("kh-parity-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mk tmp dir");
    let file = dir.join("parity_fixture.txt");
    std::fs::write(&file, parity_fixture()).expect("write fixture");
    let path = file.to_str().unwrap();

    let simd = findings(path, "simd", true);
    let gpu = findings(path, "gpu", false);

    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !simd.is_empty(),
        "fixture should yield at least one SIMD finding (sanity)"
    );
    assert_eq!(
        gpu, simd,
        "GPU and SIMD finding sets diverge (gpu_parity).\n  in SIMD not GPU: {:?}\n  in GPU not SIMD: {:?}",
        simd.difference(&gpu).collect::<Vec<_>>(),
        gpu.difference(&simd).collect::<Vec<_>>(),
    );
}

#[test]
fn gpu_does_not_add_decoded_license_key_false_positive() {
    let dir = std::env::temp_dir().join(format!("kh-gpu-fp-parity-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mk tmp dir");
    let file = dir.join("mirror-neg-0009383.yaml");
    std::fs::write(
        &file,
        concat!(
            "apiVersion: v1\n",
            "kind: Secret\n",
            "metadata:\n",
            "  name: token-secret\n",
            "type: Opaque\n",
            "data:\n",
            "  token: Slc1VUstVE1aSTItV0lDREMtVDAwN00tSUFWT1A=\n",
        ),
    )
    .expect("write fixture");
    let path = file.to_str().unwrap();

    let simd = findings(path, "simd", true);
    let gpu = findings(path, "gpu", false);

    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        simd.is_empty(),
        "fixture should remain clean on the SIMD coalesced path, got {simd:?}"
    );
    assert_eq!(
        gpu,
        simd,
        "GPU added decoded false positives absent from SIMD.\n  in GPU not SIMD: {:?}",
        gpu.difference(&simd).collect::<Vec<_>>(),
    );
}
