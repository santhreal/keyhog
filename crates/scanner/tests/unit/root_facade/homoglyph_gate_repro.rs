//! Isolate the stripe-secret-key parity miss across the four optimization
//! corners (anchor x homoglyph-gate).
use super::support;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use support::paths::detector_dir;

fn chunk(s: &str) -> Chunk {
    Chunk {
        data: s.to_string().into(),
        metadata: ChunkMetadata {
            source_type: "t".into(),
            path: Some("t".into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

#[test]
#[ignore = "diagnostic"]
fn stripe_corners() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let input = "{\n  \"STRIPE_RESTRICTED_KEY\": \"rk_live_2S2FrlCUpmb2ou955jvUlPSH\",\n  \"ttl\": 3600\n}\n";
    for (a, g) in [(true, true), (true, false), (false, true), (false, false)] {
        keyhog_scanner::testing::set_phase2_anchor_mode(&scanner, Some(a));
        keyhog_scanner::testing::set_phase2_homoglyph_gate(&scanner, Some(g));
        scanner.clear_fragment_cache();
        let r = scanner.scan_chunks_with_backend(
            std::slice::from_ref(&chunk(input)),
            ScanBackend::CpuFallback,
        );
        let dets: Vec<String> = r
            .iter()
            .flatten()
            .map(|m| format!("{}:{}", m.detector_id, m.credential))
            .collect();
        eprintln!("anchor={a} gate={g} -> {} findings: {:?}", dets.len(), dets);
    }
    // Also show fallback-only (no confirmed/ac_map) for gate on vs off.
    keyhog_scanner::testing::set_phase2_anchor_mode(&scanner, None);
    keyhog_scanner::testing::set_phase2_homoglyph_gate(&scanner, Some(true));
    let fb_on = scanner.debug_scan_phase2_only(&chunk(input));
    keyhog_scanner::testing::set_phase2_homoglyph_gate(&scanner, Some(false));
    let fb_off = scanner.debug_scan_phase2_only(&chunk(input));
    eprintln!(
        "phase2-only gate=on: {:?}",
        fb_on
            .iter()
            .map(|m| m.detector_id.to_string())
            .collect::<Vec<_>>()
    );
    eprintln!(
        "phase2-only gate=off: {:?}",
        fb_off
            .iter()
            .map(|m| m.detector_id.to_string())
            .collect::<Vec<_>>()
    );
    keyhog_scanner::testing::set_phase2_homoglyph_gate(&scanner, None);
}
