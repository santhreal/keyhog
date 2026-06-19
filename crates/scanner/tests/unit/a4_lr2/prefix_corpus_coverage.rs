use keyhog_scanner::testing::extract_inner_literals;

#[test]
fn prefix_corpus_coverage() {
    let mut promoted = 0usize;
    for d in
        keyhog_core::load_embedded_detectors_or_fail().expect("embedded detector corpus must load")
    {
        for p in &d.patterns {
            if !keyhog_scanner::testing::extract_literal_prefixes(&p.regex).is_empty() {
                continue;
            }
            if !extract_inner_literals(&p.regex).is_empty() {
                promoted += 1;
            }
        }
    }
    assert!(
        promoted >= 3,
        "expected >=3 inner-literal promotions, got {promoted}"
    );
}
