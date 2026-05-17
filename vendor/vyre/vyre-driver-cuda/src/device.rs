//! CUDA device probing and capability snapshots.

use cudarc::driver::{result, sys::CUdevice_attribute, CudaContext};

/// Queried physical limits and capabilities of a CUDA GPU.
#[derive(Debug, Clone)]
pub struct CudaDeviceCaps {
    /// The device vendor name.
    pub name: String,
    /// The physical device index.
    pub ordinal: usize,
    /// Hardware compute capability (major, minor).
    pub compute_capability: (u32, u32),
    /// Overall VRAM capacity in bytes.
    pub total_memory: u64,
    /// Maximum number of threads executable in one block.
    pub max_threads_per_block: i32,
    /// Maximum dimensions for a thread block (x, y, z).
    pub max_block_dim: [i32; 3],
    /// Maximum dimensions for a dispatch grid (x, y, z).
    pub max_grid_dim: [i32; 3],
    /// Shared memory available per thread block in bytes.
    pub shared_memory_per_block: i32,
    /// Number of threads in a hardware warp.
    pub warp_size: i32,
    /// Whether the device supports cooperative grid launches (megakernel prerequisite).
    pub cooperative_launch: bool,
    /// Whether the device can run multiple kernels concurrently from different streams.
    pub concurrent_kernels: bool,
    /// Number of independent async copy engines available.
    pub async_engine_count: i32,
    /// Maximum 32-bit registers usable by a single thread block. Required
    /// for occupancy-aware workgroup sizing (I4) — when ptxas reports a
    /// kernel's per-thread register pressure, this caps the largest block
    /// the driver can launch without spill.
    pub max_registers_per_block: i32,
    /// Maximum 32-bit registers available per streaming multiprocessor.
    /// Combined with kernel register pressure this gives the per-SM block
    /// concurrency limit for the I4 occupancy estimator.
    pub max_registers_per_sm: i32,
    /// Maximum threads resident on a streaming multiprocessor.
    /// `max_threads_per_sm / workgroup_size` is the upper bound on
    /// concurrent blocks per SM before register or shared-memory limits
    /// kick in.
    pub max_threads_per_sm: i32,
}

impl CudaDeviceCaps {
    /// Return the number of CUDA devices visible to the CUDA driver.
    ///
    /// # Errors
    ///
    /// Returns an error when the CUDA driver cannot initialize or report its
    /// visible device count.
    pub fn visible_device_count() -> Result<usize, String> {
        result::init().map_err(|e| {
            format!(
                "CUDA driver init failed: {e}. Fix: verify `nvidia-smi` succeeds and libcuda.so from the NVIDIA driver is visible to this process."
            )
        })?;
        let count = result::device::get_count()
            .map_err(|e| {
                format!(
                    "CUDA device-count query failed: {e}. Fix: repair CUDA driver/device visibility; a GPU-required host must not report zero devices."
                )
            })?;
        usize::try_from(count)
            .map_err(|_| format!("CUDA device-count query returned negative value {count}"))
    }

    /// Probe every CUDA device visible to the process.
    ///
    /// # Errors
    ///
    /// Returns an actionable error when any visible device cannot be probed.
    pub fn probe_all() -> Result<Vec<Self>, String> {
        let device_count = Self::visible_device_count()?;
        (0..device_count).map(Self::probe).collect()
    }

    /// Probe the device using the raw CUDA driver API.
    ///
    /// # Errors
    ///
    /// Returns an error when the CUDA driver cannot initialize, the ordinal is
    /// out of range, or a required device attribute cannot be queried.
    pub fn probe(ordinal: usize) -> Result<Self, String> {
        let device_count = Self::visible_device_count()?;
        if ordinal >= device_count {
            return Err(format!(
                "CUDA device ordinal {ordinal} is out of range for {device_count} visible device(s). Fix: select a CUDA device ordinal reported by `nvidia-smi`."
            ));
        }

        let ctx = CudaContext::new(ordinal).map_err(|e| {
            format!(
                "CUDA context init failed for ordinal {ordinal}: {e}. Fix: choose a visible `nvidia-smi -L` ordinal and ensure no exclusive-process compute mode blocks context creation."
            )
        })?;
        let dev = ctx.cu_device();

        let attr = |name: &str, attrib| {
            // SAFETY: cuDeviceGetCount / cuDeviceGet operate on raw pointers we own on
            // the current thread; the call returns CUresult and is wrapped in cuda_check.
            unsafe { result::device::get_attribute(dev, attrib) }
                .map_err(|e| format!("CUDA attribute query `{name}` failed: {e}"))
        };

        // SAFETY: cuDeviceGetCount / cuDeviceGet operate on raw pointers we own on
        // the current thread; the call returns CUresult and is wrapped in cuda_check.
        let total_memory = unsafe { result::device::total_mem(dev) }
            .map_err(|e| format!("CUDA total-memory query failed: {e}"))?;
        let name = result::device::get_name(dev)
            .map_err(|e| format!("CUDA device-name query failed: {e}"))?;
        let major = attr(
            "compute_capability_major",
            CUdevice_attribute::CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR,
        )?;
        let minor = attr(
            "compute_capability_minor",
            CUdevice_attribute::CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR,
        )?;
        let max_threads_per_block = attr(
            "max_threads_per_block",
            CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_THREADS_PER_BLOCK,
        )?;
        let max_block_dim_x = attr(
            "max_block_dim_x",
            CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_X,
        )?;
        let max_block_dim_y = attr(
            "max_block_dim_y",
            CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_Y,
        )?;
        let max_block_dim_z = attr(
            "max_block_dim_z",
            CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_Z,
        )?;
        let max_grid_dim_x = attr(
            "max_grid_dim_x",
            CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_X,
        )?;
        let max_grid_dim_y = attr(
            "max_grid_dim_y",
            CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_Y,
        )?;
        let max_grid_dim_z = attr(
            "max_grid_dim_z",
            CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_Z,
        )?;
        let shared_memory_per_block = attr(
            "shared_memory_per_block",
            CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_BLOCK,
        )?;
        let warp_size = attr(
            "warp_size",
            CUdevice_attribute::CU_DEVICE_ATTRIBUTE_WARP_SIZE,
        )?;
        let cooperative_launch = attr(
            "cooperative_launch",
            CUdevice_attribute::CU_DEVICE_ATTRIBUTE_COOPERATIVE_LAUNCH,
        )?;
        let concurrent_kernels = attr(
            "concurrent_kernels",
            CUdevice_attribute::CU_DEVICE_ATTRIBUTE_CONCURRENT_KERNELS,
        )?;
        let async_engine_count = attr(
            "async_engine_count",
            CUdevice_attribute::CU_DEVICE_ATTRIBUTE_ASYNC_ENGINE_COUNT,
        )?;
        let max_registers_per_block = attr(
            "max_registers_per_block",
            CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_REGISTERS_PER_BLOCK,
        )?;
        let max_registers_per_sm = attr(
            "max_registers_per_sm",
            CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_REGISTERS_PER_MULTIPROCESSOR,
        )?;
        let max_threads_per_sm = attr(
            "max_threads_per_sm",
            CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_THREADS_PER_MULTIPROCESSOR,
        )?;

        let caps = Self {
            name,
            ordinal,
            compute_capability: (major as u32, minor as u32),
            total_memory: total_memory as u64,
            max_threads_per_block,
            max_block_dim: [max_block_dim_x, max_block_dim_y, max_block_dim_z],
            max_grid_dim: [max_grid_dim_x, max_grid_dim_y, max_grid_dim_z],
            shared_memory_per_block,
            warp_size,
            cooperative_launch: cooperative_launch != 0,
            concurrent_kernels: concurrent_kernels != 0,
            async_engine_count,
            max_registers_per_block,
            max_registers_per_sm,
            max_threads_per_sm,
        };
        caps.validate_required_attributes()?;
        Ok(caps)
    }

    fn validate_required_attributes(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err(format!(
                "CUDA device ordinal {} returned an empty device name. Fix: repair CUDA driver probing before capability-dependent dispatch.",
                self.ordinal
            ));
        }
        if self.compute_capability.0 == 0 {
            return Err(format!(
                "CUDA device `{}` returned invalid compute capability {:?}. Fix: update the NVIDIA driver so CUDA attributes report a real SM target.",
                self.name, self.compute_capability
            ));
        }
        if self.total_memory == 0 {
            return Err(format!(
                "CUDA device `{}` reported zero total memory. Fix: repair CUDA device visibility; do not continue with bogus memory limits.",
                self.name
            ));
        }
        for (name, value) in [
            ("max_threads_per_block", self.max_threads_per_block),
            ("max_block_dim_x", self.max_block_dim[0]),
            ("max_block_dim_y", self.max_block_dim[1]),
            ("max_block_dim_z", self.max_block_dim[2]),
            ("max_grid_dim_x", self.max_grid_dim[0]),
            ("max_grid_dim_y", self.max_grid_dim[1]),
            ("max_grid_dim_z", self.max_grid_dim[2]),
            ("shared_memory_per_block", self.shared_memory_per_block),
            ("warp_size", self.warp_size),
            ("max_registers_per_block", self.max_registers_per_block),
            ("max_registers_per_sm", self.max_registers_per_sm),
            ("max_threads_per_sm", self.max_threads_per_sm),
        ] {
            if value <= 0 {
                return Err(format!(
                    "CUDA device `{}` reported invalid {name}={value}. Fix: repair CUDA capability probing before dispatch; zero/negative limits are a hard GPU configuration error.",
                    self.name
                ));
            }
        }
        Ok(())
    }

    /// Native CUDA SM number reported by the device compute capability.
    #[must_use]
    pub fn native_sm(&self) -> u32 {
        self.compute_capability.0 * 10 + self.compute_capability.1
    }

    /// PTX `.target sm_XX` selected for this device.
    ///
    /// The CUDA driver JIT accepts virtual PTX for the current architecture.
    /// Capping this value below the live device hides architecture-specific
    /// scheduling and invalidates cache keys across GPU generations.
    #[must_use]
    pub fn ptx_target_sm(&self) -> u32 {
        self.native_sm()
    }

    /// Shared memory available per CUDA thread block in bytes.
    #[must_use]
    pub fn shared_memory_per_block_bytes(&self) -> u32 {
        u32::try_from(self.shared_memory_per_block).unwrap_or(0)
    }

    /// Maximum threads per block as an unsigned launch-limit value.
    #[must_use]
    pub fn max_threads_per_block_u32(&self) -> u32 {
        u32::try_from(self.max_threads_per_block).unwrap_or(0)
    }

    /// Per-axis block limits as unsigned launch-limit values.
    #[must_use]
    pub fn max_block_dim_u32(&self) -> [u32; 3] {
        self.max_block_dim
            .map(|value| u32::try_from(value).unwrap_or(0))
    }

    /// Per-axis grid limits as unsigned launch-limit values.
    #[must_use]
    pub fn max_grid_dim_u32(&self) -> [u32; 3] {
        self.max_grid_dim
            .map(|value| u32::try_from(value).unwrap_or(0))
    }

    /// Warp width reported by the CUDA device.
    #[must_use]
    pub fn warp_size_u32(&self) -> Option<u32> {
        u32::try_from(self.warp_size)
            .ok()
            .filter(|value| *value > 0)
    }

    /// Whether this device generation has native fp16 instructions.
    #[must_use]
    pub fn hardware_supports_f16(&self) -> bool {
        self.compute_capability >= (5, 3)
    }

    /// Whether this device generation has native bf16 instructions.
    #[must_use]
    pub fn hardware_supports_bf16(&self) -> bool {
        self.compute_capability >= (8, 0)
    }

    /// Whether this device generation exposes NVIDIA tensor-core instructions.
    #[must_use]
    pub fn hardware_supports_tensor_cores(&self) -> bool {
        self.compute_capability >= (7, 0)
    }

    /// Project a CUDA device snapshot into the workspace-wide
    /// [`vyre_foundation::optimizer::AdapterCaps`] (audit P0 #60). All vyre
    /// backends consume the same typed capability shape so passes that
    /// adapt to subgroup-ops, indirect dispatch, max workgroup size, or
    /// shared-memory budget take a single typed input regardless of
    /// backend identity.
    ///
    /// Mapping notes:
    /// - `supports_subgroup_ops`: CUDA always supports warp shuffles
    ///   (`__shfl_*`) on every supported architecture (compute capability
    ///   ≥ 3.0), so this is `true`.
    /// - `supports_indirect_dispatch`: CUDA exposes
    ///   `cuLaunchKernelEx` and `cuLaunchCooperativeKernel` with
    ///   indirect launch parameters; `true` when cooperative launch is
    ///   reported (the megakernel prerequisite that exercises this).
    /// - `supports_specialization_constants`: CUDA does not expose
    ///   pipeline-creation specialization constants the way wgpu /
    ///   SPIR-V do — kernel parameters are runtime arguments instead of
    ///   compile-time overrides; surfaced as `false`.
    /// - `subgroup_size`: warp size (32 on every shipping NVIDIA GPU,
    ///   but probed live so future architectures stay correct).
    #[must_use]
    pub fn to_adapter_caps(&self) -> vyre_foundation::optimizer::AdapterCaps {
        self.to_device_profile().into()
    }

    /// Project the probed device into the neutral driver profile.
    #[must_use]
    pub fn to_device_profile(&self) -> vyre_driver::DeviceProfile {
        let subgroup = self.subgroup_caps();
        let profile = vyre_driver::DeviceProfile {
            backend: "cuda",
            supports_subgroup_ops: subgroup.supports_subgroup,
            supports_indirect_dispatch: self.cooperative_launch,
            supports_specialization_constants: false,
            supports_f16: self.hardware_supports_f16(),
            supports_bf16: self.hardware_supports_bf16(),
            supports_trap_propagation: true,
            supports_tensor_cores: self.hardware_supports_tensor_cores(),
            has_mul_high: true,
            has_dual_issue_fp32_int32: true,
            has_subgroup_shuffle: subgroup.supports_subgroup,
            has_shared_memory: self.shared_memory_per_block_bytes() > 0,
            max_native_int_width: 64,
            max_workgroup_size: self.max_block_dim_u32(),
            max_invocations_per_workgroup: self.max_threads_per_block_u32(),
            max_shared_memory_bytes: self.shared_memory_per_block_bytes(),
            max_storage_buffer_binding_size: self.total_memory,
            subgroup_size: subgroup.subgroup_size,
            compute_units: 0,
            regs_per_thread_max: 0,
            l1_cache_bytes: 0,
            l2_cache_bytes: 0,
            mem_bw_gbps: 0,
            ideal_unroll_depth: 0,
            ideal_vector_pack_bits: 0,
            ideal_workgroup_tile: [0, 0, 0],
            shared_memory_bank_count: 0,
            shared_memory_bank_width_bytes: 0,
        };
        vyre_driver::DeviceSignatureTable::builtins().map_or(profile, |table| {
            table.apply_generation_to_profile(self.native_sm(), profile)
        })
    }

    /// Project CUDA warp capabilities into the shared subgroup record.
    #[must_use]
    pub fn subgroup_caps(&self) -> vyre_driver::SubgroupCaps {
        self.warp_size_u32()
            .map(vyre_driver::SubgroupCaps::native)
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::CudaDeviceCaps;

    fn blackwell_caps() -> CudaDeviceCaps {
        CudaDeviceCaps {
            name: "NVIDIA GeForce RTX 5090".to_string(),
            ordinal: 0,
            compute_capability: (12, 0),
            total_memory: 32 * 1024 * 1024 * 1024,
            max_threads_per_block: 1024,
            max_block_dim: [1024, 1024, 64],
            max_grid_dim: [2_147_483_647, 65_535, 65_535],
            shared_memory_per_block: 128 * 1024,
            warp_size: 32,
            cooperative_launch: true,
            concurrent_kernels: true,
            async_engine_count: 2,
            // Blackwell SM_120: 65536 32-bit regs/block, 65536 regs/SM,
            // 2048 threads/SM. Real probed values may differ slightly per
            // driver revision; these are SM_120 spec floors.
            max_registers_per_block: 65_536,
            max_registers_per_sm: 65_536,
            max_threads_per_sm: 2048,
        }
    }

    #[test]
    fn cuda_profile_applies_builtin_sm_signature() {
        let profile = blackwell_caps().to_device_profile();

        assert_eq!(profile.compute_units, 170);
        assert_eq!(profile.ideal_unroll_depth, 8);
        assert_eq!(profile.ideal_vector_pack_bits, 128);
        assert_eq!(profile.ideal_workgroup_tile, [16, 16, 1]);
        assert_eq!(profile.shared_memory_bank_count, 32);
    }
}
