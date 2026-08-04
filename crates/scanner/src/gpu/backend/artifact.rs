//! Device artifact construction for the GPU boundary.
//!
//! Adapter acquisition stays in `acquisition`; this module owns the shader,
//! layout, pipeline, and immutable MoE weights uploaded after a real adapter is
//! known to be usable.

use crate::gpu::gpu_shader::moe_shader;
use wgpu::util::DeviceExt;

pub(super) struct MoeArtifacts {
    pub(super) pipeline: wgpu::ComputePipeline,
    pub(super) weights_buf: wgpu::Buffer,
    pub(super) bind_group_layout: wgpu::BindGroupLayout,
}

pub(super) fn load_moe_artifacts(
    device: &wgpu::Device,
    adapter_info: &wgpu::AdapterInfo,
    device_limits: &wgpu::Limits,
) -> Result<MoeArtifacts, String> {
    let all_weights = crate::ml_scorer::ml_weights::all_weights_slice();
    let weights_bytes = std::mem::size_of_val(all_weights) as u64;
    validate_weights_size(weights_bytes, adapter_info, device_limits)?;

    let compile_start = keyhog_profile::enabled().then(std::time::Instant::now);
    let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("moe_shader"),
        source: wgpu::ShaderSource::Wgsl(moe_shader().into()),
    });
    let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: Some("moe_bgl"),
        entries: &[
            bgl_entry(0, true),
            bgl_entry(1, true),
            bgl_entry(2, false),
            wgpu::BindGroupLayoutEntry {
                binding: 3,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Uniform,
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
        ],
    });
    let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: Some("moe_pipeline_layout"),
        bind_group_layouts: &[&bind_group_layout],
        push_constant_ranges: &[],
    });
    let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: Some("moe_pipeline"),
        layout: Some(&pipeline_layout),
        module: &shader,
        entry_point: Some("moe_forward"),
        compilation_options: Default::default(),
        cache: None,
    });
    if let Some(start) = compile_start {
        crate::gpu::evidence::record_compile(start.elapsed().as_nanos() as u64);
    }
    // The pipeline descriptor sets `cache: None`, so the compile above is a
    // guaranteed persistent-cache miss (counted inside `record_compile`);
    // driver-internal shader cache behavior is not observable through wgpu
    // and is reported as an explicit capability gap.
    crate::gpu::evidence::report_capability_unsupported(
        crate::gpu::evidence::BACKEND_WGPU,
        crate::gpu::evidence::capability::PIPELINE_CACHE,
    );
    let weights_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("weights"),
        contents: bytemuck::cast_slice(all_weights),
        usage: wgpu::BufferUsages::STORAGE,
    });
    // The weights upload is host-to-device traffic and device residency for
    // the process lifetime of the shared context.
    crate::gpu::evidence::record_upload(weights_bytes, None);
    crate::gpu::evidence::note_device_alloc(weights_bytes);

    Ok(MoeArtifacts {
        pipeline,
        weights_buf,
        bind_group_layout,
    })
}

pub(super) fn validate_weights_size(
    weights_bytes: u64,
    adapter_info: &wgpu::AdapterInfo,
    device_limits: &wgpu::Limits,
) -> Result<(), String> {
    let max_storage_binding = u64::from(device_limits.max_storage_buffer_binding_size);
    if weights_bytes > max_storage_binding {
        return Err(format!(
            "GPU adapter {} exposes max_storage_buffer_binding_size={max_storage_binding} B, too small for the {weights_bytes} B MoE weights buffer",
            adapter_info.name
        ));
    }
    Ok(())
}

fn bgl_entry(binding: u32, read_only: bool) -> wgpu::BindGroupLayoutEntry {
    wgpu::BindGroupLayoutEntry {
        binding,
        visibility: wgpu::ShaderStages::COMPUTE,
        ty: wgpu::BindingType::Buffer {
            ty: wgpu::BufferBindingType::Storage { read_only },
            has_dynamic_offset: false,
            min_binding_size: None,
        },
        count: None,
    }
}
