use crate::args::ScanArgs;

use super::{parse_config_byte_size, schema::LimitsSection};

fn merge_limit_bytes(
    errors: &mut Vec<String>,
    field: &str,
    value: Option<String>,
    target: &mut Option<usize>,
) {
    if let Some(raw) = value {
        let parsed = parse_config_byte_size(errors, field, &raw);
        if target.is_none() {
            if let Some(bytes) = parsed {
                *target = Some(bytes);
            }
        }
    }
}

#[cfg(any(
    not(feature = "web"),
    not(feature = "s3"),
    not(feature = "gcs"),
    not(feature = "azure"),
    not(feature = "docker"),
    not(feature = "git"),
    not(feature = "binary")
))]
fn disabled_limit_feature_error(errors: &mut Vec<String>, field: &str, feature: &str) {
    errors.push(format!(
        "- [limits].{field}: this key requires the `{feature}` feature in this keyhog build"
    ));
}

pub(super) fn apply_limits_section(
    args: &mut ScanArgs,
    config_errors: &mut Vec<String>,
    limits: LimitsSection,
) {
    merge_limit_bytes(
        config_errors,
        "[limits].stdin_bytes",
        limits.stdin_bytes,
        &mut args.limits.limit_stdin_bytes,
    );

    #[cfg(feature = "web")]
    merge_limit_bytes(
        config_errors,
        "[limits].web_response_bytes",
        limits.web_response_bytes,
        &mut args.limits.limit_web_response_bytes,
    );
    #[cfg(not(feature = "web"))]
    if limits.web_response_bytes.is_some() {
        disabled_limit_feature_error(config_errors, "web_response_bytes", "web");
    }

    #[cfg(feature = "s3")]
    merge_limit_bytes(
        config_errors,
        "[limits].s3_object_bytes",
        limits.s3_object_bytes,
        &mut args.limits.limit_s3_object_bytes,
    );
    #[cfg(not(feature = "s3"))]
    if limits.s3_object_bytes.is_some() {
        disabled_limit_feature_error(config_errors, "s3_object_bytes", "s3");
    }

    #[cfg(feature = "gcs")]
    merge_limit_bytes(
        config_errors,
        "[limits].gcs_object_bytes",
        limits.gcs_object_bytes,
        &mut args.limits.limit_gcs_object_bytes,
    );
    #[cfg(not(feature = "gcs"))]
    if limits.gcs_object_bytes.is_some() {
        disabled_limit_feature_error(config_errors, "gcs_object_bytes", "gcs");
    }

    #[cfg(feature = "azure")]
    merge_limit_bytes(
        config_errors,
        "[limits].azure_blob_bytes",
        limits.azure_blob_bytes,
        &mut args.limits.limit_azure_blob_bytes,
    );
    #[cfg(not(feature = "azure"))]
    if limits.azure_blob_bytes.is_some() {
        disabled_limit_feature_error(config_errors, "azure_blob_bytes", "azure");
    }

    #[cfg(feature = "docker")]
    {
        merge_limit_bytes(
            config_errors,
            "[limits].docker_tar_entry_bytes",
            limits.docker_tar_entry_bytes,
            &mut args.limits.limit_docker_tar_entry_bytes,
        );
        merge_limit_bytes(
            config_errors,
            "[limits].docker_image_config_bytes",
            limits.docker_image_config_bytes,
            &mut args.limits.limit_docker_image_config_bytes,
        );
        merge_limit_bytes(
            config_errors,
            "[limits].docker_tar_total_bytes",
            limits.docker_tar_total_bytes,
            &mut args.limits.limit_docker_tar_total_bytes,
        );
    }
    #[cfg(not(feature = "docker"))]
    {
        if limits.docker_tar_entry_bytes.is_some() {
            disabled_limit_feature_error(config_errors, "docker_tar_entry_bytes", "docker");
        }
        if limits.docker_image_config_bytes.is_some() {
            disabled_limit_feature_error(config_errors, "docker_image_config_bytes", "docker");
        }
        if limits.docker_tar_total_bytes.is_some() {
            disabled_limit_feature_error(config_errors, "docker_tar_total_bytes", "docker");
        }
    }

    #[cfg(feature = "git")]
    {
        merge_limit_bytes(
            config_errors,
            "[limits].git_line_bytes",
            limits.git_line_bytes,
            &mut args.limits.limit_git_line_bytes,
        );
        merge_limit_bytes(
            config_errors,
            "[limits].git_total_bytes",
            limits.git_total_bytes,
            &mut args.limits.limit_git_total_bytes,
        );
        merge_limit_bytes(
            config_errors,
            "[limits].git_blob_bytes",
            limits.git_blob_bytes,
            &mut args.limits.limit_git_blob_bytes,
        );
        if let Some(count) = limits.git_chunks {
            if count == 0 {
                config_errors.push("- [limits].git_chunks = 0: use a positive integer".to_string());
            } else if args.limits.limit_git_chunks.is_none() {
                args.limits.limit_git_chunks = Some(count);
            }
        }
    }
    #[cfg(not(feature = "git"))]
    {
        if limits.git_line_bytes.is_some() {
            disabled_limit_feature_error(config_errors, "git_line_bytes", "git");
        }
        if limits.git_total_bytes.is_some() {
            disabled_limit_feature_error(config_errors, "git_total_bytes", "git");
        }
        if limits.git_blob_bytes.is_some() {
            disabled_limit_feature_error(config_errors, "git_blob_bytes", "git");
        }
        if limits.git_chunks.is_some() {
            disabled_limit_feature_error(config_errors, "git_chunks", "git");
        }
    }

    #[cfg(feature = "binary")]
    {
        merge_limit_bytes(
            config_errors,
            "[limits].binary_read_bytes",
            limits.binary_read_bytes,
            &mut args.limits.limit_binary_read_bytes,
        );
        merge_limit_bytes(
            config_errors,
            "[limits].binary_decompiled_bytes",
            limits.binary_decompiled_bytes,
            &mut args.limits.limit_binary_decompiled_bytes,
        );
    }
    #[cfg(not(feature = "binary"))]
    {
        if limits.binary_read_bytes.is_some() {
            disabled_limit_feature_error(config_errors, "binary_read_bytes", "binary");
        }
        if limits.binary_decompiled_bytes.is_some() {
            disabled_limit_feature_error(config_errors, "binary_decompiled_bytes", "binary");
        }
    }
}
