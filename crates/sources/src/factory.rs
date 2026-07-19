/// Create a source instance from a name and optional parameters.
/// This allows the CLI to remain agnostic of specific source implementations.
pub fn create_source(
    name: &str,
    params: Option<&str>,
) -> Result<Box<dyn keyhog_core::Source>, keyhog_core::SourceError> {
    create_source_with_http_config(name, params, crate::http::HttpClientConfig::default())
}

/// Create a source while applying the shared outbound HTTP policy to
/// network-backed source implementations.
pub fn create_source_with_http_config(
    name: &str,
    params: Option<&str>,
    http: crate::http::HttpClientConfig,
) -> Result<Box<dyn keyhog_core::Source>, keyhog_core::SourceError> {
    create_source_with_http_config_limits_and_policy(
        name,
        params,
        http,
        crate::SourceLimits::default(),
        true,
    )
}

/// Create a source while applying shared HTTP policy and source byte/count
/// limits to network/container implementations.
pub fn create_source_with_http_config_and_limits(
    name: &str,
    params: Option<&str>,
    http: crate::http::HttpClientConfig,
    limits: crate::SourceLimits,
) -> Result<Box<dyn keyhog_core::Source>, keyhog_core::SourceError> {
    create_source_with_http_config_limits_and_policy(name, params, http, limits, true)
}

/// Create a source while applying shared HTTP policy, source byte/count limits,
/// and the source-owned default-exclude policy to implementations that perform
/// filesystem scanning after remote retrieval.
pub fn create_source_with_http_config_limits_and_policy(
    name: &str,
    params: Option<&str>,
    http: crate::http::HttpClientConfig,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
) -> Result<Box<dyn keyhog_core::Source>, keyhog_core::SourceError> {
    let _ = (&http, &limits, respect_default_excludes); // LAW10: feature-disabled builds still return loud source errors; this is compile hygiene only.
    match name {
        "slack" => {
            if let Some(token) = params {
                #[cfg(feature = "slack")]
                return Ok(Box::new(
                    crate::slack::SlackSource::new(token)
                        .with_http_config(http)
                        .with_limits(limits),
                ));
                #[cfg(not(feature = "slack"))]
                {
                    let _ = token; // LAW10: unused-binding marker; no runtime effect, not a fallback
                    return Err(feature_unavailable("slack", "slack"));
                }
            }
            Err(invalid_configuration("slack", "a token is required"))
        }
        "docker" => {
            if let Some(image) = params {
                #[cfg(feature = "docker")]
                return Ok(Box::new(
                    crate::docker::DockerImageSource::new(image)
                        .with_limits(limits)
                        .with_default_excludes(respect_default_excludes),
                ));
                #[cfg(not(feature = "docker"))]
                {
                    let _ = image; // LAW10: unused-binding marker; no runtime effect, not a fallback
                    return Err(feature_unavailable("docker", "docker"));
                }
            }
            Err(invalid_configuration("docker", "an image name is required"))
        }
        "github_org" => Err(deprecated_source_name("github_org", "github-org")),
        "github-org" => {
            if let Some(params) = params {
                #[cfg(feature = "github")]
                {
                    let fields = source_param_fields(params);
                    let org = required_source_param("github-org", &fields, 0, "ORG")?;
                    let token = required_source_param("github-org", &fields, 1, "TOKEN")?;
                    return Ok(Box::new(
                        crate::github_org::GitHubOrgSource::new(org.to_string(), token.to_string())
                            .with_http_config(http)
                            .with_limits(limits)
                            .with_default_excludes(respect_default_excludes),
                    ));
                }
                #[cfg(not(feature = "github"))]
                {
                    let _ = params; // LAW10: unused-binding marker; feature-disabled path returns a loud source error
                    return Err(feature_unavailable("github-org", "github"));
                }
            }
            Err(invalid_configuration(
                "github-org",
                "ORG and TOKEN parameters are required",
            ))
        }
        "s3" => {
            if let Some(bucket) = params {
                #[cfg(feature = "s3")]
                {
                    let fields = source_param_fields(bucket);
                    let bucket = required_source_param("s3", &fields, 0, "BUCKET")?;
                    let mut source = crate::s3::S3Source::new(bucket)
                        .with_http_config(http)
                        .with_limits(limits);
                    if let Some(prefix) = optional_source_param(&fields, 1) {
                        source = source.with_prefix(prefix);
                    }
                    if let Some(endpoint) = optional_source_param(&fields, 2) {
                        source = source.with_endpoint(endpoint);
                    }
                    if parse_bool_source_param("s3", optional_source_param(&fields, 3))? {
                        source = source.with_allow_credential_forward(true);
                    }
                    if let Some(max_objects) = optional_usize_source_param("s3", &fields, 4)? {
                        source = source.with_max_objects(max_objects);
                    }
                    return Ok(Box::new(source));
                }
                #[cfg(not(feature = "s3"))]
                {
                    let _ = bucket; // LAW10: unused-binding marker; no runtime effect, not a fallback
                    return Err(feature_unavailable("s3", "s3"));
                }
            }
            Err(invalid_configuration("s3", "a bucket name is required"))
        }
        "gcs" => {
            if let Some(bucket) = params {
                #[cfg(feature = "gcs")]
                {
                    let fields = source_param_fields(bucket);
                    let bucket = required_source_param("gcs", &fields, 0, "BUCKET")?;
                    let mut source = crate::gcs::GcsSource::new(bucket)
                        .with_http_config(http)
                        .with_limits(limits);
                    if let Some(prefix) = optional_source_param(&fields, 1) {
                        source = source.with_prefix(prefix);
                    }
                    if let Some(endpoint) = optional_source_param(&fields, 2) {
                        source = source.with_endpoint(endpoint);
                    }
                    if parse_bool_source_param("gcs", optional_source_param(&fields, 3))? {
                        source = source.with_allow_token_forward(true);
                    }
                    if let Some(max_objects) = optional_usize_source_param("gcs", &fields, 4)? {
                        source = source.with_max_objects(max_objects);
                    }
                    return Ok(Box::new(source));
                }
                #[cfg(not(feature = "gcs"))]
                {
                    let _ = bucket; // LAW10: unused-binding marker; no runtime effect, not a fallback
                    return Err(feature_unavailable("gcs", "gcs"));
                }
            }
            Err(invalid_configuration("gcs", "a bucket name is required"))
        }
        "azure_blob" => Err(deprecated_source_name("azure_blob", "azure-blob")),
        "azure-blob" => {
            if let Some(container_url) = params {
                #[cfg(feature = "azure")]
                {
                    let fields = source_param_fields(container_url);
                    let container_url =
                        required_source_param("azure-blob", &fields, 0, "CONTAINER_URL")?;
                    let mut source = crate::cloud::azure_blob::AzureBlobSource::new(container_url)
                        .with_http_config(http)
                        .with_limits(limits);
                    if let Some(prefix) = optional_source_param(&fields, 1) {
                        source = source.with_prefix(prefix);
                    }
                    if let Some(max_objects) =
                        optional_usize_source_param("azure-blob", &fields, 2)?
                    {
                        source = source.with_max_objects(max_objects);
                    }
                    return Ok(Box::new(source));
                }
                #[cfg(not(feature = "azure"))]
                {
                    let _ = container_url; // LAW10: unused-binding marker; no runtime effect, not a fallback
                    return Err(feature_unavailable("azure-blob", "azure"));
                }
            }
            Err(invalid_configuration(
                "azure-blob",
                "a container URL is required",
            ))
        }
        "url" => Err(deprecated_source_name("url", "web")),
        "web" => {
            if let Some(params) = params {
                #[cfg(feature = "web")]
                {
                    let mut fields = source_param_fields(params);
                    let allow_autoroute_loopback_calibration = match fields.first().copied() {
                        Some(raw) if raw.starts_with("autoroute_loopback_calibration=") => {
                            let value = raw.trim_start_matches("autoroute_loopback_calibration=");
                            fields.remove(0);
                            parse_bool_source_param("web", Some(value))?
                        }
                        _ => false,
                    };
                    let urls: Vec<String> = fields
                        .into_iter()
                        .map(str::trim)
                        .filter(|line| !line.is_empty())
                        .map(ToOwned::to_owned)
                        .collect();
                    if urls.is_empty() {
                        return Err(invalid_configuration(
                            "web",
                            "at least one URL parameter is required",
                        ));
                    }
                    return Ok(Box::new(
                        crate::web::WebSource::new(urls)
                            .with_http_config(http)
                            .with_limits(limits)
                            .with_autoroute_loopback_calibration(
                                allow_autoroute_loopback_calibration,
                            ),
                    ));
                }
                #[cfg(not(feature = "web"))]
                {
                    let _ = params; // LAW10: unused-binding marker; feature-disabled path returns a loud source error
                    return Err(feature_unavailable("web", "web"));
                }
            }
            Err(invalid_configuration(
                "web",
                "at least one URL parameter is required",
            ))
        }
        "gitlab_group" => Err(deprecated_source_name("gitlab_group", "gitlab-group")),
        "gitlab-group" => {
            if let Some(params) = params {
                #[cfg(feature = "gitlab")]
                return Ok(Box::new(crate::gitlab_group::source_from_params(
                    params,
                    http,
                    limits,
                    respect_default_excludes,
                )?));
                #[cfg(not(feature = "gitlab"))]
                {
                    let _ = params; // LAW10: unused-binding marker; feature-disabled path returns a loud source error
                    return Err(feature_unavailable("gitlab-group", "gitlab"));
                }
            }
            Err(invalid_configuration(
                "gitlab-group",
                "GROUP and TOKEN parameters are required; ENDPOINT is optional",
            ))
        }
        "bitbucket_workspace" => Err(deprecated_source_name(
            "bitbucket_workspace",
            "bitbucket-workspace",
        )),
        "bitbucket-workspace" => {
            if let Some(params) = params {
                #[cfg(feature = "bitbucket")]
                return Ok(Box::new(crate::bitbucket_workspace::source_from_params(
                    params,
                    http,
                    limits,
                    respect_default_excludes,
                )?));
                #[cfg(not(feature = "bitbucket"))]
                {
                    let _ = params; // LAW10: unused-binding marker; feature-disabled path returns a loud source error
                    return Err(feature_unavailable("bitbucket-workspace", "bitbucket"));
                }
            }
            Err(invalid_configuration(
                "bitbucket-workspace",
                "WORKSPACE, USERNAME, and APP_PASSWORD parameters are required; ENDPOINT is optional",
            ))
        }
        _ => Err(keyhog_core::SourceError::UnknownSource {
            name: name.to_owned(),
        }),
    }
}

fn feature_unavailable(source: &str, feature: &str) -> keyhog_core::SourceError {
    keyhog_core::SourceError::FeatureUnavailable {
        source_name: source.to_owned(),
        feature: feature.to_owned(),
    }
}

fn invalid_configuration(source: &str, detail: impl Into<String>) -> keyhog_core::SourceError {
    keyhog_core::SourceError::InvalidConfiguration {
        source_name: source.to_owned(),
        detail: detail.into(),
    }
}

fn deprecated_source_name(name: &str, replacement: &str) -> keyhog_core::SourceError {
    keyhog_core::SourceError::DeprecatedSourceName {
        name: name.to_owned(),
        replacement: replacement.to_owned(),
    }
}

#[cfg(any(
    feature = "github",
    feature = "s3",
    feature = "gcs",
    feature = "azure",
    feature = "web"
))]
fn source_param_fields(params: &str) -> Vec<&str> {
    params.split('\n').collect()
}

#[cfg(any(feature = "github", feature = "s3", feature = "gcs", feature = "azure"))]
fn required_source_param<'a>(
    source: &str,
    fields: &'a [&'a str],
    index: usize,
    label: &str,
) -> Result<&'a str, keyhog_core::SourceError> {
    optional_source_param(fields, index).ok_or_else(|| {
        invalid_configuration(source, format!("a non-empty {label} parameter is required"))
    })
}

#[cfg(any(feature = "github", feature = "s3", feature = "gcs", feature = "azure"))]
fn optional_source_param<'a>(fields: &'a [&'a str], index: usize) -> Option<&'a str> {
    fields
        .get(index)
        .map(|raw| raw.trim())
        .filter(|raw| !raw.is_empty())
}

#[cfg(any(feature = "web", feature = "s3", feature = "gcs"))]
fn parse_bool_source_param(
    source: &str,
    raw: Option<&str>,
) -> Result<bool, keyhog_core::SourceError> {
    match raw.map(str::trim) {
        None | Some("") | Some("false") | Some("0") | Some("no") | Some("off") => Ok(false),
        Some("true") | Some("1") | Some("yes") | Some("on") => Ok(true),
        Some(value) => Err(invalid_configuration(
            source,
            format!("boolean parameter must be true/false, got {value:?}"),
        )),
    }
}

#[cfg(any(feature = "s3", feature = "gcs", feature = "azure"))]
fn optional_usize_source_param(
    source: &str,
    fields: &[&str],
    index: usize,
) -> Result<Option<usize>, keyhog_core::SourceError> {
    optional_source_param(fields, index)
        .map(|value| {
            value.parse::<usize>().map_err(|error| {
                invalid_configuration(
                    source,
                    format!(
                        "numeric parameter must be a non-negative integer, got {value:?}: {error}"
                    ),
                )
            })
        })
        .transpose()
}
