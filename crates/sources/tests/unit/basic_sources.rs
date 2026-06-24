use keyhog_core::Source;

#[cfg(feature = "web")]
#[test]
fn web_source_empty_urls_produce_no_chunks() {
    let source = keyhog_sources::WebSource::new(vec![]);
    let chunks: Vec<_> = source.chunks().collect();

    assert_eq!(source.name(), "web");
    assert!(chunks.is_empty());
}

#[cfg(feature = "web")]
#[test]
fn web_source_from_url_is_constructible() {
    let source = keyhog_sources::WebSource::new(vec!["https://example.com/app.js".to_string()]);
    assert_eq!(source.name(), "web");
}
