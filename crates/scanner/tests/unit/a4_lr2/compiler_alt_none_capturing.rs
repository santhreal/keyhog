#[test]
fn compiler_alt_none_capturing() {
    assert!(keyhog_scanner::testing::rewrite_alternation_prefix(
        "(FLWSECK_(?:TEST|LIVE)-[a-f0-9]{32,64}-X)",
        "FLWSECK_TEST-",
        "FLW[SСＳ]ECK_TEST-"
    )
    .is_none());
}
