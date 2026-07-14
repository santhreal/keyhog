//! GPU backend state checks owned separately from runtime-degrade reporting.

use super::CompiledScanner;

impl CompiledScanner {
    /// True when literals, backend handle, and compiled matcher are all present.
    pub(crate) fn gpu_stack_usable_for(&self, backend: crate::hw_probe::ScanBackend) -> bool {
        self.gpu_literals.is_some()
            && self.gpu_backends.get(backend).is_some()
            && self.gpu_matcher().is_some()
    }
}
