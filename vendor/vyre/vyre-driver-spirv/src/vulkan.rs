//! Vulkan compute dispatch for the SPIR-V backend.
//!
//! Uses `ash` to drive a minimal Vulkan 1.0 compute pipeline:
//! instance → physical device (with compute queue) → logical device →
//! shader module → descriptor set → compute pipeline → command buffer →
//! fence-wait submit.

use ash::vk;

use vyre_driver::BackendError;
use vyre_foundation::ir::{BufferAccess, Program};

/// Owned Vulkan compute context.
pub(crate) struct VulkanDevice {
    _instance: ash::Instance,
    device: ash::Device,
    physical_device: vk::PhysicalDevice,
    queue_family_index: u32,
    queue: vk::Queue,
    command_pool: vk::CommandPool,
    /// Memory type index that is host-visible and host-coherent.
    host_memory_type_index: u32,
    /// Device properties (for limits reporting).
    pub properties: vk::PhysicalDeviceProperties,
}

impl std::fmt::Debug for VulkanDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VulkanDevice")
            .field("physical_device", &self.physical_device)
            .field("queue_family_index", &self.queue_family_index)
            .finish_non_exhaustive()
    }
}

/// Cached probe: does a working Vulkan driver actually exist?
///
/// `libvulkan.so` may be present but the ICD layer can still segfault
/// inside `vkCreateInstance` when the Vulkan driver stack is nonfunctional. We
/// defensively run `vulkaninfo --summary` once per process; if it
/// fails we never call into `ash`, avoiding the SIGSEGV.
fn vulkan_works() -> bool {
    static PROBE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *PROBE.get_or_init(|| {
        std::process::Command::new("vulkaninfo")
            .arg("--summary")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
}

impl VulkanDevice {
    /// Acquire the first Vulkan physical device that exposes a compute queue.
    pub(crate) fn acquire() -> Result<Self, BackendError> {
        if !vulkan_works() {
            return Err(BackendError::new(
                "No working Vulkan driver detected (vulkaninfo --summary failed). Fix: install a Vulkan-capable GPU driver or run on a host with GPU access.".to_string(),
            ));
        }

        let entry = unsafe { ash::Entry::load() }.map_err(|e| {
            BackendError::new(format!(
                "Failed to load Vulkan loader: {e}. Fix: install a Vulkan loader (libvulkan1) and ensure ICD files are in /usr/share/vulkan/icd.d/."
            ))
        })?;

        let app_info = vk::ApplicationInfo {
            api_version: vk::API_VERSION_1_0,
            ..Default::default()
        };
        let create_info = vk::InstanceCreateInfo {
            p_application_info: &app_info,
            ..Default::default()
        };

        let instance = unsafe { entry.create_instance(&create_info, None) }.map_err(|e| {
            BackendError::new(format!(
                "Vulkan instance creation failed: {e}. Fix: verify the Vulkan loader and any validation layers are compatible."
            ))
        })?;

        let physical_devices = unsafe { instance.enumerate_physical_devices() }.map_err(|e| {
            BackendError::new(format!(
                "Vulkan physical device enumeration failed: {e}. Fix: ensure a Vulkan-capable GPU is present and drivers are installed."
            ))
        })?;

        let mut chosen = None;
        for pd in physical_devices {
            let props = unsafe { instance.get_physical_device_properties(pd) };
            let queue_families =
                unsafe { instance.get_physical_device_queue_family_properties(pd) };
            for (index, family) in queue_families.iter().enumerate() {
                if family.queue_flags.contains(vk::QueueFlags::COMPUTE) {
                    chosen = Some((pd, index as u32, props));
                    break;
                }
            }
            if chosen.is_some() {
                break;
            }
        }

        let (physical_device, queue_family_index, properties) = chosen.ok_or_else(|| {
            BackendError::new(
                "No Vulkan physical device with a compute queue was found. Fix: install a GPU with Vulkan support or enable a software implementation (lavapipe).".to_string(),
            )
        })?;

        let queue_priority = 1.0f32;
        let queue_create_info = vk::DeviceQueueCreateInfo {
            queue_family_index,
            queue_count: 1,
            p_queue_priorities: &queue_priority,
            ..Default::default()
        };

        let device_create_info = vk::DeviceCreateInfo {
            queue_create_info_count: 1,
            p_queue_create_infos: &queue_create_info,
            ..Default::default()
        };

        let device = unsafe {
            instance.create_device(physical_device, &device_create_info, None)
        }
        .map_err(|e| {
            BackendError::new(format!(
                "Vulkan logical device creation failed: {e}. Fix: check device limits and feature requirements."
            ))
        })?;

        let queue = unsafe { device.get_device_queue(queue_family_index, 0) };

        let command_pool = unsafe {
            device.create_command_pool(
                &vk::CommandPoolCreateInfo {
                    flags: vk::CommandPoolCreateFlags::RESET_COMMAND_BUFFER,
                    queue_family_index,
                    ..Default::default()
                },
                None,
            )
        }
        .map_err(|e| {
            BackendError::new(format!(
                "Vulkan command pool creation failed: {e}. Fix: verify queue family index is valid."
            ))
        })?;

        let memory_properties =
            unsafe { instance.get_physical_device_memory_properties(physical_device) };
        let host_memory_type_index = find_host_visible_memory_type(&memory_properties).ok_or_else(
            || {
                BackendError::new(
                    "No host-visible, host-coherent memory type found on Vulkan device. Fix: select a different physical device or implement explicit staging.".to_string(),
                )
            },
        )?;

        Ok(Self {
            _instance: instance,
            device,
            physical_device,
            queue_family_index,
            queue,
            command_pool,
            host_memory_type_index,
            properties,
        })
    }

    /// Create a buffer backed by host-visible memory.
    unsafe fn create_host_buffer(
        &self,
        size: vk::DeviceSize,
    ) -> Result<(vk::Buffer, vk::DeviceMemory), BackendError> {
        let buffer_info = vk::BufferCreateInfo {
            size,
            usage: vk::BufferUsageFlags::STORAGE_BUFFER
                | vk::BufferUsageFlags::TRANSFER_SRC
                | vk::BufferUsageFlags::TRANSFER_DST,
            sharing_mode: vk::SharingMode::EXCLUSIVE,
            ..Default::default()
        };
        let buffer = self
            .device
            .create_buffer(&buffer_info, None)
            .map_err(|e| BackendError::new(format!("Vulkan buffer creation failed: {e}. Fix: reduce buffer size or check device limits.")))?;

        let mem_requirements = self.device.get_buffer_memory_requirements(buffer);
        let alloc_info = vk::MemoryAllocateInfo {
            allocation_size: mem_requirements.size,
            memory_type_index: self.host_memory_type_index,
            ..Default::default()
        };
        let memory = self
            .device
            .allocate_memory(&alloc_info, None)
            .map_err(|e| BackendError::new(format!("Vulkan memory allocation failed: {e}. Fix: reduce buffer size or free unused allocations.")))?;

        self.device
            .bind_buffer_memory(buffer, memory, 0)
            .map_err(|e| {
                BackendError::new(format!(
                    "Vulkan buffer memory binding failed: {e}. Fix: verify alignment requirements."
                ))
            })?;

        Ok((buffer, memory))
    }

    /// Destroy a buffer and its memory.
    unsafe fn destroy_buffer(&self, buffer: vk::Buffer, memory: vk::DeviceMemory) {
        self.device.destroy_buffer(buffer, None);
        self.device.free_memory(memory, None);
    }

    /// Record a compute dispatch and wait for completion.
    unsafe fn dispatch_compute(
        &self,
        pipeline: vk::Pipeline,
        pipeline_layout: vk::PipelineLayout,
        descriptor_set: vk::DescriptorSet,
        workgroups: [u32; 3],
    ) -> Result<(), BackendError> {
        eprintln!(
            "DEBUG: dispatch_compute start, command_pool={:?}",
            self.command_pool
        );
        let alloc_info = vk::CommandBufferAllocateInfo {
            s_type: vk::StructureType::COMMAND_BUFFER_ALLOCATE_INFO,
            p_next: std::ptr::null(),
            command_pool: self.command_pool,
            level: vk::CommandBufferLevel::PRIMARY,
            command_buffer_count: 1,
            _marker: std::marker::PhantomData,
        };
        eprintln!("DEBUG: about to allocate command buffers");
        let mut cbs = self
            .device
            .allocate_command_buffers(&alloc_info)
            .map_err(|e| BackendError::new(format!("Vulkan command buffer allocation failed: {e}. Fix: reset or free existing command buffers.")))?;
        eprintln!(
            "DEBUG: allocate_command_buffers returned {} buffers",
            cbs.len()
        );
        let command_buffer = cbs.pop().ok_or_else(|| {
            BackendError::new(
                "Vulkan returned zero command buffers. Fix: check command pool state.".to_string(),
            )
        })?;
        eprintln!("DEBUG: command buffer allocated: {:?}", command_buffer);

        self.device
            .begin_command_buffer(
                command_buffer,
                &vk::CommandBufferBeginInfo {
                    flags: vk::CommandBufferUsageFlags::ONE_TIME_SUBMIT,
                    ..Default::default()
                },
            )
            .map_err(|e| {
                BackendError::new(format!(
                    "Vulkan command buffer begin failed: {e}. Fix: check command buffer state."
                ))
            })?;
        eprintln!("DEBUG: command buffer began");

        self.device
            .cmd_bind_pipeline(command_buffer, vk::PipelineBindPoint::COMPUTE, pipeline);
        eprintln!("DEBUG: pipeline bound");
        self.device.cmd_bind_descriptor_sets(
            command_buffer,
            vk::PipelineBindPoint::COMPUTE,
            pipeline_layout,
            0,
            &[descriptor_set],
            &[],
        );
        eprintln!("DEBUG: descriptor sets bound");
        self.device
            .cmd_dispatch(command_buffer, workgroups[0], workgroups[1], workgroups[2]);
        eprintln!("DEBUG: dispatch recorded");

        self.device
            .end_command_buffer(command_buffer)
            .map_err(|e| {
                BackendError::new(format!(
                    "Vulkan command buffer end failed: {e}. Fix: check recorded commands."
                ))
            })?;
        eprintln!("DEBUG: command buffer ended");

        let fence = self
            .device
            .create_fence(&vk::FenceCreateInfo::default(), None)
            .map_err(|e| {
                BackendError::new(format!(
                    "Vulkan fence creation failed: {e}. Fix: check device limits."
                ))
            })?;
        eprintln!("DEBUG: fence created");

        let submit_info = vk::SubmitInfo {
            command_buffer_count: 1,
            p_command_buffers: &command_buffer,
            ..Default::default()
        };
        self.device
            .queue_submit(self.queue, &[submit_info], fence)
            .map_err(|e| {
                BackendError::new(format!(
                    "Vulkan queue submit failed: {e}. Fix: verify queue and command buffer state."
                ))
            })?;
        eprintln!("DEBUG: queue submitted");

        self.device
            .wait_for_fences(&[fence], true, u64::MAX)
            .map_err(|e| {
                BackendError::new(format!(
                    "Vulkan fence wait failed: {e}. Fix: check for device loss."
                ))
            })?;
        eprintln!("DEBUG: fence waited");

        self.device.destroy_fence(fence, None);
        self.device
            .free_command_buffers(self.command_pool, &[command_buffer]);
        eprintln!("DEBUG: dispatch_compute end");

        Ok(())
    }
}

impl Drop for VulkanDevice {
    fn drop(&mut self) {
        unsafe {
            self.device.destroy_command_pool(self.command_pool, None);
            self.device.destroy_device(None);
        }
    }
}

fn find_host_visible_memory_type(props: &vk::PhysicalDeviceMemoryProperties) -> Option<u32> {
    for i in 0..props.memory_type_count {
        let ty = props.memory_types[i as usize];
        if ty
            .property_flags
            .contains(vk::MemoryPropertyFlags::HOST_VISIBLE)
            && ty
                .property_flags
                .contains(vk::MemoryPropertyFlags::HOST_COHERENT)
        {
            return Some(i);
        }
    }
    None
}

/// Build a SPIR-V shader module from raw words.
unsafe fn create_shader_module(
    device: &ash::Device,
    words: &[u32],
) -> Result<vk::ShaderModule, BackendError> {
    let code_size = words.len() * std::mem::size_of::<u32>();
    let create_info = vk::ShaderModuleCreateInfo {
        code_size,
        p_code: words.as_ptr(),
        ..Default::default()
    };
    device
        .create_shader_module(&create_info, None)
        .map_err(|e| BackendError::new(format!("Vulkan shader module creation failed: {e}. Fix: validate the SPIR-V binary with spirv-val before loading.")))
}

/// One binding slot used during dispatch.
struct DispatchBinding {
    buffer: vk::Buffer,
    memory: vk::DeviceMemory,
    byte_len: usize,
    binding: u32,
}

/// Run one compute dispatch on the Vulkan device.
///
/// # Safety
/// The Vulkan device must be valid. This function performs all Vulkan FFI calls.
pub(crate) unsafe fn dispatch_program(
    device: &VulkanDevice,
    program: &Program,
    spv_words: &[u32],
    inputs: &[Vec<u8>],
    config: &vyre_driver::DispatchConfig,
) -> Result<Vec<Vec<u8>>, BackendError> {
    let workgroup_size = config.workgroup_override.unwrap_or(program.workgroup_size);
    let workgroup_size = [
        workgroup_size[0].max(1),
        workgroup_size[1].max(1),
        workgroup_size[2].max(1),
    ];

    let grid = if let Some(grid) = config.grid_override {
        grid
    } else {
        infer_grid(program, workgroup_size)?
    };

    // Build bindings from program buffers.
    let mut dispatch_bindings: Vec<DispatchBinding> = Vec::new();
    let mut input_index = 0usize;
    let mut output_bindings: Vec<(u32, usize)> = Vec::new(); // (binding, index in dispatch_bindings)

    for buffer in program.buffers() {
        if buffer.access() == BufferAccess::Workgroup {
            continue;
        }

        let byte_len = if buffer.count() == 0 {
            if let Some(input) = inputs.get(input_index) {
                input.len()
            } else if buffer.is_output() {
                // Output buffer without input: size from element type.
                buffer.element().min_bytes().max(1)
            } else {
                return Err(BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: buffer `{}` has runtime size but no matching input was provided.",
                        buffer.name()
                    ),
                });
            }
        } else {
            let element_size = buffer.element().min_bytes().max(1);
            (buffer.count() as usize).saturating_mul(element_size)
        };

        let (vk_buffer, vk_memory) = device.create_host_buffer(byte_len as vk::DeviceSize)?;

        // If there is a matching input, upload it.
        if let Some(input) = inputs.get(input_index) {
            let ptr = device
                .device
                .map_memory(vk_memory, 0, vk::WHOLE_SIZE, vk::MemoryMapFlags::empty())
                .map_err(|e| {
                    BackendError::new(format!(
                        "Vulkan memory map failed: {e}. Fix: check memory type is host-visible."
                    ))
                })?;
            let slice = std::slice::from_raw_parts_mut(ptr as *mut u8, byte_len);
            let to_copy = input.len().min(byte_len);
            slice[..to_copy].copy_from_slice(&input[..to_copy]);
            device.device.unmap_memory(vk_memory);
            input_index += 1;
        }

        if buffer.is_output() || buffer.pipeline_live_out {
            output_bindings.push((buffer.binding(), dispatch_bindings.len()));
        }

        dispatch_bindings.push(DispatchBinding {
            buffer: vk_buffer,
            memory: vk_memory,
            byte_len,
            binding: buffer.binding(),
        });
    }

    if input_index != inputs.len() {
        return Err(BackendError::InvalidProgram {
            fix: format!(
                "Fix: received {} input buffers but only {} were consumed by Program buffer declarations.",
                inputs.len(),
                input_index
            ),
        });
    }

    eprintln!("DEBUG: creating shader module...");
    // Create shader module.
    let shader_module = create_shader_module(&device.device, spv_words)?;
    eprintln!("DEBUG: shader module created");

    // Descriptor set layout.
    let layout_bindings: Vec<vk::DescriptorSetLayoutBinding<'_>> = dispatch_bindings
        .iter()
        .map(|b| vk::DescriptorSetLayoutBinding {
            binding: b.binding,
            descriptor_type: vk::DescriptorType::STORAGE_BUFFER,
            descriptor_count: 1,
            stage_flags: vk::ShaderStageFlags::COMPUTE,
            p_immutable_samplers: std::ptr::null(),
            ..Default::default()
        })
        .collect();

    eprintln!("DEBUG: creating descriptor set layout...");
    let descriptor_set_layout = device
        .device
        .create_descriptor_set_layout(
            &vk::DescriptorSetLayoutCreateInfo {
                binding_count: layout_bindings.len() as u32,
                p_bindings: layout_bindings.as_ptr(),
                ..Default::default()
            },
            None,
        )
        .map_err(|e| {
            BackendError::new(format!(
                "Vulkan descriptor set layout creation failed: {e}. Fix: check binding limits."
            ))
        })?;
    eprintln!("DEBUG: descriptor set layout created");

    // Pipeline layout.
    eprintln!("DEBUG: creating pipeline layout...");
    let pipeline_layout = device
        .device
        .create_pipeline_layout(
            &vk::PipelineLayoutCreateInfo {
                set_layout_count: 1,
                p_set_layouts: &descriptor_set_layout,
                ..Default::default()
            },
            None,
        )
        .map_err(|e| {
            BackendError::new(format!(
                "Vulkan pipeline layout creation failed: {e}. Fix: check push constant limits."
            ))
        })?;
    eprintln!("DEBUG: pipeline layout created");

    // Compute pipeline.
    let pipeline_info = vk::ComputePipelineCreateInfo {
        stage: vk::PipelineShaderStageCreateInfo {
            stage: vk::ShaderStageFlags::COMPUTE,
            module: shader_module,
            p_name: b"main\0".as_ptr() as *const i8,
            ..Default::default()
        },
        layout: pipeline_layout,
        ..Default::default()
    };

    eprintln!("DEBUG: creating compute pipeline...");
    let pipeline = match device.device.create_compute_pipelines(
        vk::PipelineCache::null(),
        &[pipeline_info],
        None,
    ) {
        Ok(mut pipelines) => {
            eprintln!("DEBUG: compute pipeline created");
            pipelines.pop().ok_or_else(|| BackendError::new(
                "Vulkan returned zero compute pipelines. Fix: check shader module and pipeline layout compatibility.".to_string(),
            ))?
        }
        Err((_, e)) => {
            return Err(BackendError::new(format!(
                "Vulkan compute pipeline creation failed: {e:?}. Fix: validate SPIR-V entry point name is 'main' and pipeline layout matches shader bindings."
            )));
        }
    };

    eprintln!("DEBUG: creating descriptor pool...");
    // Descriptor pool.
    let pool_size = vk::DescriptorPoolSize {
        ty: vk::DescriptorType::STORAGE_BUFFER,
        descriptor_count: dispatch_bindings.len() as u32,
    };
    let descriptor_pool = device
        .device
        .create_descriptor_pool(
            &vk::DescriptorPoolCreateInfo {
                max_sets: 1,
                pool_size_count: 1,
                p_pool_sizes: &pool_size,
                ..Default::default()
            },
            None,
        )
        .map_err(|e| {
            BackendError::new(format!(
                "Vulkan descriptor pool creation failed: {e}. Fix: check pool sizes."
            ))
        })?;
    eprintln!("DEBUG: descriptor pool created");

    // Descriptor set.
    eprintln!("DEBUG: allocating descriptor set...");
    let descriptor_set = device
        .device
        .allocate_descriptor_sets(&vk::DescriptorSetAllocateInfo {
            descriptor_pool,
            descriptor_set_count: 1,
            p_set_layouts: &descriptor_set_layout,
            ..Default::default()
        })
        .map_err(|e| BackendError::new(format!("Vulkan descriptor set allocation failed: {e}. Fix: check descriptor pool capacity.")))?
        .pop()
        .ok_or_else(|| BackendError::new("Vulkan returned zero descriptor sets. Fix: check descriptor pool state.".to_string()))?;
    eprintln!("DEBUG: descriptor set allocated");

    // Write descriptor set.
    let buffer_infos: Vec<vk::DescriptorBufferInfo> = dispatch_bindings
        .iter()
        .map(|b| vk::DescriptorBufferInfo {
            buffer: b.buffer,
            offset: 0,
            range: vk::WHOLE_SIZE,
        })
        .collect();

    let write_bindings: Vec<vk::WriteDescriptorSet<'_>> = dispatch_bindings
        .iter()
        .zip(buffer_infos.iter())
        .map(|(b, info)| vk::WriteDescriptorSet {
            dst_set: descriptor_set,
            dst_binding: b.binding,
            dst_array_element: 0,
            descriptor_count: 1,
            descriptor_type: vk::DescriptorType::STORAGE_BUFFER,
            p_buffer_info: info,
            ..Default::default()
        })
        .collect();

    eprintln!("DEBUG: updating descriptor sets...");
    device.device.update_descriptor_sets(&write_bindings, &[]);
    eprintln!("DEBUG: descriptor sets updated");

    // Dispatch.
    eprintln!("DEBUG: dispatching compute...");
    device.dispatch_compute(pipeline, pipeline_layout, descriptor_set, grid)?;
    eprintln!("DEBUG: compute dispatched");

    // Read back outputs.
    let mut outputs = Vec::with_capacity(output_bindings.len());
    for (_binding, idx) in &output_bindings {
        let b = &dispatch_bindings[*idx];
        let ptr = device
            .device
            .map_memory(b.memory, 0, vk::WHOLE_SIZE, vk::MemoryMapFlags::empty())
            .map_err(|e| BackendError::new(format!("Vulkan memory map for readback failed: {e}. Fix: check memory type is host-visible.")))?;
        let slice = std::slice::from_raw_parts(ptr as *const u8, b.byte_len);
        outputs.push(slice.to_vec());
        device.device.unmap_memory(b.memory);
    }

    // Cleanup.
    device.device.destroy_descriptor_pool(descriptor_pool, None);
    device.device.destroy_pipeline(pipeline, None);
    device.device.destroy_pipeline_layout(pipeline_layout, None);
    device
        .device
        .destroy_descriptor_set_layout(descriptor_set_layout, None);
    device.device.destroy_shader_module(shader_module, None);
    for b in dispatch_bindings {
        device.destroy_buffer(b.buffer, b.memory);
    }

    Ok(outputs)
}

/// Infer the dispatch grid from the program's output buffer sizes.
fn infer_grid(program: &Program, workgroup_size: [u32; 3]) -> Result<[u32; 3], BackendError> {
    if workgroup_size[1] != 1 || workgroup_size[2] != 1 {
        return Err(BackendError::new(format!(
            "Fix: non-1D workgroup_size {:?} requires DispatchConfig::grid_override. Set grid_override explicitly.",
            workgroup_size
        )));
    }

    let max_count = program
        .buffers()
        .iter()
        .filter(|b| b.is_output())
        .map(|b| b.count())
        .max()
        .unwrap_or(1);

    let lanes = workgroup_size[0].max(1);
    let x = max_count.div_ceil(lanes).max(1);
    Ok([x, 1, 1])
}
