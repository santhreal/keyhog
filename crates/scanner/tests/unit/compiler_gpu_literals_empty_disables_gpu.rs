//! Empty literal in AC set disables GPU literal preparation.

use keyhog_scanner::testing::build_gpu_literals;

#[test]
fn compiler_gpu_literals_empty_disables_gpu() {
    let literals = vec!["ghp_".into(), String::new()];
    assert!(
        build_gpu_literals(&literals).is_none(),
        "empty literal must disable GPU literal set"
    );
}
