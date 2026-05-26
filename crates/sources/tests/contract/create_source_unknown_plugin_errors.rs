//! create_source must error on unknown plugin names.

#[test]
fn create_source_unknown_plugin_errors() {
    match keyhog_sources::create_source("not-a-real-plugin", None) {
        Err(err) => assert!(
            err.to_string().contains("unknown source plugin"),
            "got {err}"
        ),
        Ok(_) => panic!("unknown plugin must return Err"),
    }
}
