use keyhog_core::Chunk;
use keyhog_scanner::testing::scan_coalesced_phase2_with_admission_for_test;
use keyhog_scanner::CompiledScanner;

#[test]
fn complete_negative_rows_return_exact_empty_results() {
    let scanner = CompiledScanner::compile(Vec::new()).expect("compile empty detector plan");
    let chunks = [
        Chunk::from("ordinary source text"),
        Chunk::from("another file"),
    ];
    let admitted = [false, false];
    let complete = [true, true];

    let results = scan_coalesced_phase2_with_admission_for_test(
        &scanner,
        &chunks,
        vec![None, None],
        Some(&admitted),
        Some(&complete),
    );

    assert_eq!(results, [Vec::new(), Vec::new()]);
}
