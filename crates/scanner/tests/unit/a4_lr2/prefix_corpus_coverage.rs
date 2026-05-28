use keyhog_scanner::compiler::extract_inner_literals;

#[test]
fn prefix_corpus_coverage() {
    let mut promoted = 0usize;
    for (_, toml_str) in keyhog_core::embedded_detector_tomls() {
        let Ok(detectors) = keyhog_core::load_detectors_from_str(toml_str) else { continue };
        for d in &detectors {
            for p in &d.patterns {
                if !keyhog_scanner::compiler::extract_literal_prefixes(&p.regex).is_empty() {
                    continue;
                }
                if !extract_inner_literals(&p.regex).is_empty() {
                    promoted += 1;
                }
            }
        }
    }
    assert!(promoted >= 3, "expected >=3 inner-literal promotions, got {promoted}");
}
