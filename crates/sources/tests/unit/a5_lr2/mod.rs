// LR2-A5
#[cfg(feature = "github")]
mod gh_clone_https_ok;
#[cfg(feature = "github")]
mod gh_clone_ssh_bad;
#[cfg(feature = "github")]
mod gh_repo_name_ok;
#[cfg(feature = "github")]
mod gh_repo_traversal_bad;
#[cfg(any(
    feature = "azure",
    feature = "web",
    feature = "slack",
    feature = "s3",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket",
    feature = "gcs"
))]
mod http_proxy_flag_overrides_env;
#[cfg(any(
    feature = "azure",
    feature = "web",
    feature = "slack",
    feature = "s3",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket",
    feature = "gcs"
))]
mod http_proxy_off_preserved;
mod http_ua_has_version;
mod http_ua_suffix;
mod read_compressed_empty;
mod read_decode_utf16_le;
mod read_decode_utf16_no_bom_none;
mod read_looks_binary_clean;
mod read_looks_binary_dense;
mod read_safe_cap_refuses_huge;
mod read_slice_empty;
mod read_slice_single;
mod read_slice_two_windows;
mod sources_cap_oracle_01;
mod sources_cap_oracle_02;
mod sources_cap_oracle_03;
mod sources_cap_oracle_04;
mod sources_cap_oracle_05;
mod sources_cap_oracle_06;
mod sources_cap_oracle_07;
mod sources_cap_oracle_08;
mod sources_cap_oracle_09;
mod sources_cap_oracle_10;
mod sources_cap_oracle_11;
mod sources_cap_oracle_12;
mod sources_cap_oracle_13;
mod sources_cap_oracle_14;
mod sources_cap_oracle_15;
mod sources_cap_oracle_16;
mod sources_cap_oracle_17;
mod sources_cap_oracle_18;
mod sources_cap_oracle_19;
mod sources_cap_oracle_20;
mod sources_cap_oracle_21;
mod sources_cap_oracle_22;
mod sources_cap_oracle_23;
mod sources_cap_oracle_24;
mod sources_cap_oracle_25;
mod sources_cap_oracle_26;
mod sources_cap_oracle_27;
mod sources_cap_oracle_28;
mod sources_cap_oracle_29;
mod sources_cap_oracle_30;
mod sources_cap_oracle_31;
mod sources_cap_oracle_32;
mod sources_cap_oracle_33;
mod sources_cap_oracle_34;
mod sources_cap_oracle_35;
mod sources_cap_oracle_36;
mod sources_cap_oracle_37;
mod sources_cap_oracle_38;
mod sources_cap_oracle_39;
mod sources_cap_oracle_40;
mod web_accepts_example;
mod web_redact_path_at;
mod web_redact_userinfo;
mod web_rejects_ipv4_mapped;
mod web_rejects_loopback;
mod web_rejects_metadata;
