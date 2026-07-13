use super::ResolvedScanConfig;

/// Process-wide scanner settings that must be installed before hardware probes
/// or detector compilation. Keeping this transition in one object prevents the
/// scan, watch, and scan-system entry points from hashing one configuration
/// while executing another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResolvedEngineRuntimeSettings {
    gpu_policy: keyhog_scanner::gpu::GpuRuntimePolicy,
    regex_dfa_limit: Option<usize>,
    gpu_batch_input_limit: Option<usize>,
    profile: bool,
    perf_trace: bool,
}

impl From<&ResolvedScanConfig> for ResolvedEngineRuntimeSettings {
    fn from(config: &ResolvedScanConfig) -> Self {
        Self {
            gpu_policy: config.gpu_runtime_policy,
            regex_dfa_limit: config.regex_dfa_limit,
            gpu_batch_input_limit: config.gpu_batch_input_limit,
            profile: config.scanner.profile,
            perf_trace: config.scanner.perf_trace,
        }
    }
}

impl ResolvedEngineRuntimeSettings {
    /// Publish the resolved values before any global reader can cache hardware
    /// or sizing state. `None` selects the documented engine default.
    pub(crate) fn apply(self) {
        keyhog_scanner::gpu::set_gpu_runtime_policy(self.gpu_policy);
        keyhog_scanner::set_regex_dfa_limit(self.regex_dfa_limit.unwrap_or(0));
        keyhog_scanner::set_gpu_batch_input_limit(self.gpu_batch_input_limit.unwrap_or(0));
        keyhog_scanner::set_profile_enabled(self.profile);
        keyhog_scanner::set_perf_trace_enabled(self.perf_trace);
    }
}
