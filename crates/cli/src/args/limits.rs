//! `keyhog scan` source-limit arguments.

use clap::Args;
use keyhog_sources::SourceLimits;

#[derive(Args, Clone, Debug, Default)]
pub struct SourceLimitArgs {
    /// Maximum bytes accepted from --stdin before failing closed.
    #[arg(long, value_name = "SIZE", value_parser = crate::value_parsers::parse_byte_size)]
    pub limit_stdin_bytes: Option<usize>,

    /// Maximum HTTP response bytes scanned by --url.
    #[cfg(feature = "web")]
    #[arg(long, value_name = "SIZE", value_parser = crate::value_parsers::parse_byte_size)]
    pub limit_web_response_bytes: Option<usize>,

    /// Maximum bytes downloaded for one S3 object.
    #[cfg(feature = "s3")]
    #[arg(long, value_name = "SIZE", value_parser = crate::value_parsers::parse_byte_size)]
    pub limit_s3_object_bytes: Option<usize>,

    /// Maximum bytes downloaded for one GCS object.
    #[cfg(feature = "gcs")]
    #[arg(long, value_name = "SIZE", value_parser = crate::value_parsers::parse_byte_size)]
    pub limit_gcs_object_bytes: Option<usize>,

    /// Maximum bytes downloaded for one Azure blob.
    #[cfg(feature = "azure")]
    #[arg(long, value_name = "SIZE", value_parser = crate::value_parsers::parse_byte_size)]
    pub limit_azure_blob_bytes: Option<usize>,

    /// Maximum bytes allowed for one Docker tar entry.
    #[cfg(feature = "docker")]
    #[arg(long, value_name = "SIZE", value_parser = crate::value_parsers::parse_byte_size)]
    pub limit_docker_tar_entry_bytes: Option<usize>,

    /// Maximum bytes accepted for Docker/OCI image config and manifest JSON.
    #[cfg(feature = "docker")]
    #[arg(long, value_name = "SIZE", value_parser = crate::value_parsers::parse_byte_size)]
    pub limit_docker_image_config_bytes: Option<usize>,

    /// Maximum cumulative bytes allowed while unpacking a Docker/OCI layer tar.
    #[cfg(feature = "docker")]
    #[arg(long, value_name = "SIZE", value_parser = crate::value_parsers::parse_byte_size)]
    pub limit_docker_tar_total_bytes: Option<usize>,

    /// Maximum bytes buffered for one line of git stdout.
    #[cfg(feature = "git")]
    #[arg(long, value_name = "SIZE", value_parser = crate::value_parsers::parse_byte_size)]
    pub limit_git_line_bytes: Option<usize>,

    /// Maximum aggregate bytes emitted by a git blob-history scan.
    #[cfg(feature = "git")]
    #[arg(long, value_name = "SIZE", value_parser = crate::value_parsers::parse_byte_size)]
    pub limit_git_total_bytes: Option<usize>,

    /// Maximum bytes read from one git blob.
    #[cfg(feature = "git")]
    #[arg(long, value_name = "SIZE", value_parser = crate::value_parsers::parse_byte_size)]
    pub limit_git_blob_bytes: Option<usize>,

    /// Maximum chunk count emitted by a git blob-history scan.
    #[cfg(feature = "git")]
    #[arg(long, value_name = "N", value_parser = crate::value_parsers::parse_positive_limit_count)]
    pub limit_git_chunks: Option<usize>,

    /// Maximum bytes read for binary strings extraction.
    #[cfg(feature = "binary")]
    #[arg(long, value_name = "SIZE", value_parser = crate::value_parsers::parse_byte_size)]
    pub limit_binary_read_bytes: Option<usize>,

    /// Maximum Ghidra decompiled-output bytes accepted for parsing.
    #[cfg(feature = "binary")]
    #[arg(long, value_name = "SIZE", value_parser = crate::value_parsers::parse_byte_size)]
    pub limit_binary_decompiled_bytes: Option<usize>,
}

impl SourceLimitArgs {
    pub fn to_source_limits(&self) -> SourceLimits {
        let mut limits = SourceLimits::default();
        if let Some(value) = self.limit_stdin_bytes {
            limits.stdin_bytes = value;
        }
        #[cfg(feature = "web")]
        if let Some(value) = self.limit_web_response_bytes {
            limits.web_response_bytes = value;
        }
        #[cfg(feature = "s3")]
        if let Some(value) = self.limit_s3_object_bytes {
            limits.s3_object_bytes = value as u64;
        }
        #[cfg(feature = "gcs")]
        if let Some(value) = self.limit_gcs_object_bytes {
            limits.gcs_object_bytes = value as u64;
        }
        #[cfg(feature = "azure")]
        if let Some(value) = self.limit_azure_blob_bytes {
            limits.azure_blob_bytes = value as u64;
        }
        #[cfg(feature = "docker")]
        if let Some(value) = self.limit_docker_tar_entry_bytes {
            limits.docker_tar_entry_bytes = value as u64;
        }
        #[cfg(feature = "docker")]
        if let Some(value) = self.limit_docker_image_config_bytes {
            limits.docker_image_config_bytes = value as u64;
        }
        #[cfg(feature = "docker")]
        if let Some(value) = self.limit_docker_tar_total_bytes {
            limits.docker_tar_total_bytes = value as u64;
        }
        #[cfg(feature = "git")]
        if let Some(value) = self.limit_git_line_bytes {
            limits.git_line_bytes = value;
        }
        #[cfg(feature = "git")]
        if let Some(value) = self.limit_git_total_bytes {
            limits.git_total_bytes = value;
        }
        #[cfg(feature = "git")]
        if let Some(value) = self.limit_git_blob_bytes {
            limits.git_blob_bytes = value as u64;
        }
        #[cfg(feature = "git")]
        if let Some(value) = self.limit_git_chunks {
            limits.git_chunk_count = value;
        }
        #[cfg(feature = "binary")]
        if let Some(value) = self.limit_binary_read_bytes {
            limits.binary_read_bytes = value;
        }
        #[cfg(feature = "binary")]
        if let Some(value) = self.limit_binary_decompiled_bytes {
            limits.binary_decompiled_bytes = value as u64;
        }
        limits
    }
}
