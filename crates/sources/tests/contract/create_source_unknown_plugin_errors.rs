//! create_source must error on unknown plugin names.

#[test]
fn create_source_unknown_plugin_errors() {
    match keyhog_sources::create_source("not-a-real-plugin", None) {
        Err(keyhog_core::SourceError::UnknownSource { name }) => {
            assert_eq!(name, "not-a-real-plugin")
        }
        Err(err) => panic!("unknown plugin returned the wrong error: {err}"),
        Ok(_) => panic!("unknown plugin must return Err"),
    }
}

#[test]
fn retired_source_aliases_name_the_canonical_replacement() {
    for (name, replacement) in [
        ("github_org", "github-org"),
        ("gitlab_group", "gitlab-group"),
        ("bitbucket_workspace", "bitbucket-workspace"),
        ("azure_blob", "azure-blob"),
        ("url", "web"),
    ] {
        match keyhog_sources::create_source(name, Some("unused")) {
            Err(keyhog_core::SourceError::DeprecatedSourceName {
                name: actual,
                replacement: actual_replacement,
            }) => {
                assert_eq!(actual, name);
                assert_eq!(actual_replacement, replacement);
            }
            Err(err) => panic!("alias {name} returned the wrong error: {err}"),
            Ok(_) => panic!("alias {name} was silently accepted"),
        }
    }
}
