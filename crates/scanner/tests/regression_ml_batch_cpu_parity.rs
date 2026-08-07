//! ML confidence batches remain deterministic CPU work across the parallel threshold.
#![cfg(feature = "ml")]

use keyhog_scanner::testing::{ml_score_batch_for_test, ml_score_batch_serial_for_test};
use keyhog_scanner::ScannerConfig;

/// A backend route must not change confidence scores when a batch crosses the
/// CPU parallelism threshold. This also pins empty-candidate handling and row order.
#[test]
fn cpu_batch_scoring_matches_the_serial_reference_at_threshold_boundaries() {
    let config = ScannerConfig::default();
    let owned: Vec<(String, String)> = (0..129)
        .map(|index| {
            if index == 0 {
                (String::new(), "EMPTY=".to_string())
            } else {
                (
                    format!("ghp_{index:03}ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"),
                    format!("GITHUB_TOKEN_{index}="),
                )
            }
        })
        .collect();

    for count in [0, 1, 63, 64, 65, 129] {
        let inputs: Vec<(&str, &str)> = owned[..count]
            .iter()
            .map(|(text, context)| (text.as_str(), context.as_str()))
            .collect();
        let expected = ml_score_batch_serial_for_test(&inputs, &config);
        let actual = ml_score_batch_for_test(&inputs, &config);
        assert_eq!(actual, expected, "CPU batch score drift at count {count}");
        assert_eq!(actual.len(), count);
        if count != 0 {
            assert_eq!(actual[0], 0.0, "empty candidate policy changed");
        }
    }
}
