//! Operational constants metadata registry and validation (Row 113).
//!
//! Every Tier-A operational constant affecting throughput, memory, batching,
//! concurrency, or accelerator eligibility is cataloged here with its
//! documented default, TOML key, CLI flag, unit, and validated range.

use std::fmt;

/// Physical unit of an operational configuration knob.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationalUnit {
    /// Byte count (e.g. "128KB", "8MB").
    Bytes,
    /// Integer count / quantity.
    Count,
    /// Milliseconds.
    Milliseconds,
    /// Seconds.
    Seconds,
}

impl fmt::Display for OperationalUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes => write!(f, "bytes"),
            Self::Count => write!(f, "count"),
            Self::Milliseconds => write!(f, "ms"),
            Self::Seconds => write!(f, "seconds"),
        }
    }
}

/// Descriptor for a Tier-A operational performance knob.
#[derive(Clone, Debug)]
pub struct OperationalKnob {
    /// Configuration path in `.keyhog.toml` (e.g. `[scan].fused_batch`).
    pub toml_key: &'static str,
    /// CLI flag name (e.g. `--fused-batch`), if meaningful.
    pub cli_flag: Option<&'static str>,
    /// Documented default value as human-readable string.
    pub default_str: &'static str,
    /// Numeric default value (in base unit, e.g. bytes or count).
    pub default_val: u64,
    /// Physical unit.
    pub unit: OperationalUnit,
    /// Minimum allowed value (inclusive).
    pub min_val: u64,
    /// Maximum allowed value (inclusive).
    pub max_val: u64,
    /// Short description of the setting.
    pub description: &'static str,
}

impl OperationalKnob {
    /// Validate a raw integer value against this knob's bounds.
    pub fn validate_val(&self, val: u64) -> Result<(), String> {
        if val < self.min_val || val > self.max_val {
            Err(format!(
                "{}: value {} is out of valid range ({}..={}{})",
                self.toml_key, val, self.min_val, self.max_val, self.unit
            ))
        } else {
            Ok(())
        }
    }

    /// Resolve 3-layer precedence: Default overridden by TOML overridden by CLI.
    pub fn resolve_precedence(
        &self,
        toml_override: Option<u64>,
        cli_override: Option<u64>,
    ) -> Result<u64, String> {
        if let Some(cli) = cli_override {
            self.validate_val(cli)?;
            Ok(cli)
        } else if let Some(toml) = toml_override {
            self.validate_val(toml)?;
            Ok(toml)
        } else {
            Ok(self.default_val)
        }
    }

    /// Enumerate all registered Tier-A operational performance constants.
    pub fn enumerate_all() -> &'static [Self] {
        &OPERATIONAL_KNOBS
    }
}

/// Static registry of all operational performance constants.
static OPERATIONAL_KNOBS: [OperationalKnob; 11] = [
    OperationalKnob {
        toml_key: "[scan].window_overlap",
        cli_flag: Some("--window-overlap"),
        default_str: "128KB",
        default_val: 131_072,
        unit: OperationalUnit::Bytes,
        min_val: 1_024,
        max_val: 1_048_575,
        description: "Streaming window overlap size in bytes",
    },
    OperationalKnob {
        toml_key: "[scan].fused_batch",
        cli_flag: Some("--fused-batch"),
        default_str: "1024",
        default_val: 1024,
        unit: OperationalUnit::Count,
        min_val: 1,
        max_val: 65_536,
        description: "Fused filesystem pipeline chunk batch size",
    },
    OperationalKnob {
        toml_key: "[scan].fused_depth",
        cli_flag: Some("--fused-depth"),
        default_str: "0",
        default_val: 0,
        unit: OperationalUnit::Count,
        min_val: 0,
        max_val: 256,
        description: "Fused filesystem pipeline channel depth (0 = auto/rendezvous)",
    },
    OperationalKnob {
        toml_key: "[scan].gpu_batch_input_limit",
        cli_flag: Some("--gpu-batch-input-limit"),
        default_str: "8MB",
        default_val: 8_388_480,
        unit: OperationalUnit::Bytes,
        min_val: 65_536,
        max_val: 2_147_483_648,
        description: "GPU region-presence batch byte budget",
    },
    OperationalKnob {
        toml_key: "[tuning].chunk_lane_threshold",
        cli_flag: Some("--chunk-lane-threshold"),
        default_str: "4096",
        default_val: 4096,
        unit: OperationalUnit::Bytes,
        min_val: 1,
        max_val: 1_048_576,
        description: "Maximum chunk size grouped into sequential work lanes",
    },
    OperationalKnob {
        toml_key: "[tuning].hs_shard_target",
        cli_flag: Some("--hs-shard-target"),
        default_str: "320",
        default_val: 320,
        unit: OperationalUnit::Count,
        min_val: 1,
        max_val: 65_536,
        description: "Target pattern count per Hyperscan shard database",
    },
    OperationalKnob {
        toml_key: "[tuning].hs_prefilter_max_len",
        cli_flag: Some("--hs-prefilter-max-len"),
        default_str: "4096",
        default_val: 4096,
        unit: OperationalUnit::Bytes,
        min_val: 1,
        max_val: 1_048_576,
        description: "Maximum chunk length for Hyperscan prefilter routing",
    },
    OperationalKnob {
        toml_key: "decode_size_limit",
        cli_flag: Some("--decode-size-limit"),
        default_str: "512KB",
        default_val: 524_288,
        unit: OperationalUnit::Bytes,
        min_val: 1_024,
        max_val: 67_108_864,
        description: "Maximum chunk size admitted to recursive decode",
    },
    OperationalKnob {
        toml_key: "max_file_size",
        cli_flag: Some("--max-file-size"),
        default_str: "100MB",
        default_val: 104_857_600,
        unit: OperationalUnit::Bytes,
        min_val: 1_024,
        max_val: 1_099_511_627_776,
        description: "Maximum file size scanned without skipping",
    },
    OperationalKnob {
        toml_key: "regex_dfa_limit",
        cli_flag: Some("--regex-dfa-limit"),
        default_str: "10MB",
        default_val: 10_485_760,
        unit: OperationalUnit::Bytes,
        min_val: 65_536,
        max_val: 1_073_741_824,
        description: "Per-regex lazy DFA cache byte limit",
    },
    OperationalKnob {
        toml_key: "[scan].per_chunk_timeout_ms",
        cli_flag: Some("--per-chunk-timeout-ms"),
        default_str: "0",
        default_val: 0,
        unit: OperationalUnit::Milliseconds,
        min_val: 0,
        max_val: 3_600_000,
        description: "Hard deadline per chunk scan in milliseconds (0 = no deadline)",
    },
];
