use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

fn scanner() -> CompiledScanner {
    let mut detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    detectors.retain(|detector| detector.id == "stripe-secret-key");
    assert_eq!(
        detectors.len(),
        1,
        "test must load exactly the shipped Stripe secret-key detector"
    );
    CompiledScanner::compile(detectors).expect("compile Stripe scanner")
}

#[test]
fn stripe_hot_and_confirmed_paths_share_nonzero_base_offset() {
    let secret = concat!("sk_li", "ve_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD");
    let text = format!("STRIPE_SECRET_KEY={secret}\n");
    let local_offset = text.find(secret).expect("secret present");
    let base_offset = 4096usize;
    let base_line = 23usize;
    let matches = scanner().scan(&Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "stripe-direct-prefix-dedup".into(),
            path: Some("windowed-stripe.env".into()),
            base_offset,
            base_line,
            ..Default::default()
        },
    });

    let stripe: Vec<_> = matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == "stripe-secret-key")
        .collect();
    assert_eq!(
        stripe.len(),
        1,
        "Stripe hot-prefix and confirmed regex lanes must not emit duplicate same-start findings; matches={:?}",
        matches
            .iter()
            .map(|m| (
                m.detector_id.as_ref(),
                m.credential.as_ref(),
                m.location.offset,
                m.location.line
            ))
            .collect::<Vec<_>>()
    );
    assert_eq!(stripe[0].location.offset, base_offset + local_offset);
    assert_eq!(stripe[0].location.line, Some(base_line + 1));
}

#[test]
fn stripe_direct_prefix_duplicates_are_owned_by_scan_state() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let scan_state =
        std::fs::read_to_string(src.join("scan_state.rs")).expect("scan_state source readable");
    let process =
        std::fs::read_to_string(src.join("engine/process.rs")).expect("process source readable");
    let hot_patterns = std::fs::read_to_string(src.join("engine/hot_patterns.rs"))
        .expect("hot_patterns source readable");

    assert!(
        scan_state.contains("claimed_match_identities: HashSet<OwnedMatchIdentity>")
            && scan_state.contains("struct OwnedMatchIdentity")
            && scan_state.contains("fn push_match(")
            && scan_state.contains("fn replace_claimed_match_if_better(")
            && scan_state.contains("OwnedMatchIdentity::from(&m)")
            && scan_state.contains("self.claimed_match_identities.remove(&displaced)")
            && scan_state.contains("self.claimed_match_identities.insert(identity)"),
        "ScanState must own canonical same-identity suppression state instead of detector-local filters"
    );
    assert!(
        process.contains("scan_state.push_match(raw_match, self.config.max_matches_per_chunk)")
            && process.contains("crate::telemetry::record_match_found();"),
        "process_match must claim canonical match identities at the shared emission bottleneck"
    );
    assert!(
        !hot_patterns.contains("chunk.metadata.base_offset,\n                    keyword_nearby")
            && !hot_patterns.contains("chunk.metadata.base_line,\n                    0,"),
        "hot-pattern process_match calls must pass extraction-local offsets; build_raw_match owns chunk base offsets"
    );
}
