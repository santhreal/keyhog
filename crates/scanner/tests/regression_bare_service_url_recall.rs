//! Regression: service-owned URL credentials must be credential-sufficient.
//!
//! Several RPC/storage detectors already declared the URL itself as the
//! credential, but only reported it when a service-specific variable name was
//! present. That made the same credential disappear from target-spec
//! sufficiency probes. The bare routes stay constrained to service-owned host
//! and path shapes so generic URL tokens do not become detector claims.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::OnceLock;

const ARBITRUM_URL: &str = "https://arb-mainnet.g.alchemy.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz";
const AVALANCHE_URL: &str = "https://api.avax.network/Kp4Qx7Rm2Sn5Tb8Vw3Yz";
const ZKSYNC_URL: &str = "http://1BqNk6h5cxHl.bNCrdjL7jUs5wZUxXEQuOAzaIjtptWbqn0_EKXlEvmjYD4Oq.zksync.gmhaenthcnqggidysvuwbqwodugreafnero/t7S1VhmjZmLSpyxdlyuXJlFA21JpVQXbYQ5TFtWLODfccxyk7HngYKls7-r9ErqEoJ68fwDTalxhIisyCNIgyJ";
const SUPABASE_STORAGE_URL: &str = "https://kj6shbgqc5b-yh9f14qphbef4toqnydt3md4k-h16s40wfz9aqcukpb4seba53rhc298ircp621odxitx4wa6kvttwvh.supabase.co/storage45289v31847774vvv7v298";
const SUPABASE_REALTIME_URL: &str = "wss://ipg2a9-ngmylpjv4aehcd1-1j-uwny4tclky1o-0g116jav27ks54kvji44iytbjq.supabase.co:realtime2329865///951463v449/4v2510//047/95/2332/34v170/";

fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
        CompiledScanner::compile(detectors).expect("compile scanner")
    })
}

fn matches_for(body: &str) -> Vec<(String, String)> {
    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata {
            source_type: "service-url-regression".into(),
            path: Some("notes/sufficiency-probe.txt".into()),
            ..Default::default()
        },
    };
    scanner().clear_fragment_cache();
    scanner()
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .map(|m| (m.detector_id.to_string(), m.credential.as_str().to_string()))
        .collect()
}

fn detector_caught(matches: &[(String, String)], detector_id: &str, credential: &str) -> bool {
    matches
        .iter()
        .any(|(id, found)| id == detector_id && found == credential)
}

fn detector_fired(matches: &[(String, String)], detector_id: &str) -> bool {
    matches.iter().any(|(id, _)| id == detector_id)
}

#[test]
fn bare_service_owned_urls_surface_under_their_detector() {
    for (detector_id, credential) in [
        ("arbitrum-api-credentials", ARBITRUM_URL),
        ("avalanche-api-credentials", AVALANCHE_URL),
        ("zksync-api-credentials", ZKSYNC_URL),
        ("supabase-storage-credentials", SUPABASE_STORAGE_URL),
        ("supabase-realtime-credentials", SUPABASE_REALTIME_URL),
    ] {
        let matches = matches_for(credential);
        assert!(
            detector_caught(&matches, detector_id, credential),
            "bare service URL must surface under {detector_id}; matches={matches:?}"
        );
    }
}

#[test]
fn generic_url_neighbors_do_not_claim_service_detectors() {
    for (detector_id, body) in [
        (
            "arbitrum-api-credentials",
            "https://rpc.example.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        ),
        (
            "avalanche-api-credentials",
            "https://api.example.com/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        ),
        (
            "zksync-api-credentials",
            "https://rpc.example.com/324/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        ),
        (
            "supabase-storage-credentials",
            "https://example.supabase.co/functions/v1/upload",
        ),
        (
            "supabase-realtime-credentials",
            "wss://example.supabase.co/functions/v1/socket",
        ),
    ] {
        let matches = matches_for(body);
        assert!(
            !detector_fired(&matches, detector_id),
            "generic URL neighbor must not fire {detector_id}; matches={matches:?}"
        );
    }
}
