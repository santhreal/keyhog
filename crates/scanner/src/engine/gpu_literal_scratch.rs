//! Thread-local scratch owner for GPU literal-set presence dispatch.

use std::cell::RefCell;

thread_local! {
    static GPU_LITERAL_SCAN_SCRATCH: RefCell<vyre_libs::scan::dispatch_io::ScanDispatchScratch> =
        RefCell::new(vyre_libs::scan::dispatch_io::ScanDispatchScratch::default());
}

struct ZeroGpuLiteralScratch<'a> {
    scratch: &'a mut vyre_libs::scan::dispatch_io::ScanDispatchScratch,
}

impl<'a> ZeroGpuLiteralScratch<'a> {
    fn new(scratch: &'a mut vyre_libs::scan::dispatch_io::ScanDispatchScratch) -> Self {
        Self { scratch }
    }

    fn as_mut(&mut self) -> &mut vyre_libs::scan::dispatch_io::ScanDispatchScratch {
        &mut *self.scratch
    }
}

impl Drop for ZeroGpuLiteralScratch<'_> {
    fn drop(&mut self) {
        zero_scan_dispatch_scratch(self.scratch);
    }
}

/// Single owner for zeroing-then-clearing a VYRE `ScanDispatchScratch`'s
/// upload/readback buffers before it is released back to its thread-local.
/// Shared by every GPU dispatch scratch guard so the zeroed-field set cannot
/// drift between owners.
pub(in crate::engine) fn zero_scan_dispatch_scratch(
    scratch: &mut vyre_libs::scan::dispatch_io::ScanDispatchScratch,
) {
    scratch.haystack_bytes.fill(0);
    scratch.haystack_bytes.clear();
    scratch.hit_bytes.fill(0);
    scratch.hit_bytes.clear();
}

fn with_gpu_literal_scratch<R>(
    f: impl FnOnce(
        &mut vyre_libs::scan::dispatch_io::ScanDispatchScratch,
    ) -> std::result::Result<R, String>,
) -> std::result::Result<R, String> {
    GPU_LITERAL_SCAN_SCRATCH
        .try_with(|cell| {
            let mut scratch = cell.try_borrow_mut().map_err(|_| {
                "gpu literal-set scratch already borrowed on this thread; recursive GPU trigger \
                 dispatch is unsupported"
                    .to_string()
            })?;
            let mut zero_on_drop = ZeroGpuLiteralScratch::new(&mut scratch);
            f(zero_on_drop.as_mut())
        })
        .map_err(|_| "gpu literal-set scratch unavailable during thread shutdown".to_string())?
}

pub(super) fn scan_gpu_literal_presence_with_scratch(
    matcher: &vyre_libs::scan::GpuLiteralSet,
    backend: &dyn vyre::VyreBackend,
    haystack: &[u8],
) -> std::result::Result<Vec<u32>, String> {
    with_gpu_literal_scratch(|scratch| {
        matcher
            .scan_presence_with_scratch(backend, haystack, scratch)
            .map_err(|error| error.to_string())
    })
}

#[cfg(feature = "gpu")]
pub(super) fn scan_gpu_literal_presence_by_region_with_scratch(
    matcher: &vyre_libs::scan::GpuLiteralSet,
    backend: &dyn vyre::VyreBackend,
    haystack: &[u8],
    region_starts: &[u32],
) -> std::result::Result<Vec<u32>, String> {
    with_gpu_literal_scratch(|scratch| {
        matcher
            .scan_presence_by_region_with_scratch(backend, haystack, region_starts, 0, scratch)
            .map_err(|error| error.to_string())
    })
}
