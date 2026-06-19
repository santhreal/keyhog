//! GPU backend state checks owned separately from runtime-degrade reporting.

use super::CompiledScanner;

impl CompiledScanner {
    /// True when literals, backend handle, and compiled matcher are all present.
    pub(crate) fn gpu_stack_usable(&self) -> bool {
        self.gpu_literals.is_some() && self.gpu_backend.is_some() && self.gpu_matcher().is_some()
    }
}
