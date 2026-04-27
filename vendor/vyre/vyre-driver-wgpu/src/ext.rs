//! WGSL-specific dispatch helpers for the wgpu backend.
//!
//! Raw WGSL is a property of the wgpu implementation, not the substrate-neutral
//! [`vyre::VyreBackend`] contract.

use std::sync::Arc;

use crate::engine::record_and_readback::{record_and_readback, DispatchLabels, RecordAndReadback};
use crate::pipeline::{BufferBindingInfo, OutputBindingLayout, OutputLayout};
use crate::WgpuBackend;
use vyre_foundation::ir::{BufferAccess, DataType};

impl WgpuBackend {
    /// Dispatch a raw WGSL compute shader.
    ///
    /// # Errors
    ///
    /// Returns an actionable error when shader compilation, staging-buffer
    /// creation, command submission, or readback fails.
    pub fn dispatch_wgsl(
        &self,
        wgsl: &str,
        input: &[u8],
        output_size: usize,
        workgroup_size: u32,
    ) -> Result<Vec<u8>, String> {
        if workgroup_size == 0 {
            return Err("Fix: dispatch_wgsl workgroup_size must be greater than zero.".to_string());
        }
        let device_queue = self.current_device_queue();
        let (device, _queue) = &*device_queue;

        let pipeline = crate::runtime::compile_compute_pipeline(
            device,
            "vyre backend dispatch_wgsl",
            wgsl,
            "main",
        )
        .map_err(|error| error.to_string())?;

        let output_word_count = output_size
            .checked_add(3)
            .and_then(|n| n.checked_div(4))
            .unwrap_or(output_size)
            .max(1);
        let output_bytes = output_word_count.checked_mul(4).ok_or_else(|| {
            format!(
                "Fix: output_word_count {output_word_count} overflows usize bytes; reduce output_size"
            )
        })?;
        let input_len_u32 = u32::try_from(input.len()).map_err(|_| {
            format!(
                "Fix: input length {} exceeds u32 capacity; split the dispatch into u32-sized chunks",
                input.len()
            )
        })?;
        let output_len_u32 = u32::try_from(output_word_count).map_err(|_| {
            format!(
                "Fix: output_word_count {output_word_count} exceeds u32 capacity; reduce output_size"
            )
        })?;
        let params = [input_len_u32, output_len_u32, 0u32, 0u32];
        let params_bytes = bytemuck::try_cast_slice(&params).map_err(|error| {
            vyre::BackendError::new(format!(
                "WGSL dispatch params could not be viewed as bytes: {error}. Fix: keep dispatch parameter buffers aligned to u32."
            ))
            .into_message()
        })?;

        let workgroup_count = output_word_count
            .div_ceil(workgroup_size as usize)
            .max(1)
            .try_into()
            .unwrap_or(u32::MAX);
        let input_word_count = input.len().div_ceil(4).max(1);
        let buffer_bindings = [
            BufferBindingInfo {
                internal_trap: false,
                group: crate::lowering::bind_group_for(vyre::ir::MemoryKind::Readonly),
                binding: 0,
                name: Arc::from("input"),
                access: BufferAccess::ReadOnly,
                kind: vyre::ir::MemoryKind::Readonly,
                hints: vyre::ir::MemoryHints::default(),
                element: DataType::U32,
                count: u32::try_from(input_word_count).unwrap_or(u32::MAX),
                is_output: false,
                preserve_input_contents: false,
            },
            BufferBindingInfo {
                internal_trap: false,
                group: crate::lowering::bind_group_for(vyre::ir::MemoryKind::Global),
                binding: 1,
                name: Arc::from("output"),
                access: BufferAccess::ReadWrite,
                kind: vyre::ir::MemoryKind::Global,
                hints: vyre::ir::MemoryHints::default(),
                element: DataType::U32,
                count: u32::try_from(output_word_count).unwrap_or(u32::MAX),
                is_output: true,
                preserve_input_contents: false,
            },
            BufferBindingInfo {
                internal_trap: false,
                group: crate::lowering::bind_group_for(vyre::ir::MemoryKind::Uniform),
                binding: 2,
                name: Arc::from("params"),
                access: BufferAccess::Uniform,
                kind: vyre::ir::MemoryKind::Uniform,
                hints: vyre::ir::MemoryHints::default(),
                element: DataType::U32,
                count: 4,
                is_output: false,
                preserve_input_contents: false,
            },
        ];
        let max_group: u32 = buffer_bindings.iter().map(|b| b.group).max().unwrap_or(0);
        let bind_group_layouts: Vec<Arc<wgpu::BindGroupLayout>> = (0..=max_group)
            .map(|g| Arc::new(pipeline.get_bind_group_layout(g)))
            .collect();
        let inputs = [input, params_bytes];
        let output_bindings = [OutputBindingLayout {
            binding: 1,
            name: Arc::from("output"),
            layout: OutputLayout {
                full_size: output_bytes,
                read_size: output_size,
                copy_offset: 0,
                copy_size: output_bytes,
                trim_start: 0,
            },
            word_count: output_word_count,
        }];
        let outputs = record_and_readback(RecordAndReadback {
            device_queue: &device_queue,
            pool: self.dispatch_arena.pool(),
            pipeline: &pipeline,
            bind_group_layouts: &bind_group_layouts,
            buffer_bindings: &buffer_bindings,
            inputs: &inputs,
            output_bindings: &output_bindings,
            trap_tags: &[],
            workgroup_count: [workgroup_count, 1, 1],
            indirect: None,
            labels: DispatchLabels {
                readback: "vyre backend dispatch_wgsl readback",
                bind_group: "vyre backend dispatch_wgsl bind group",
                encoder: "vyre backend dispatch_wgsl",
                compute: "vyre backend dispatch_wgsl compute",
            },
            iterations: 1,
        })
        .map_err(|error| error.into_message())?;

        outputs
            .into_iter()
            .next()
            .ok_or_else(|| "WGSL dispatch produced no output. Fix: declare binding(1) as the output storage buffer.".to_string())
    }
}
