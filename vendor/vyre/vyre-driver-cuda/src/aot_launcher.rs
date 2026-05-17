//! CUDA-owned AOT launcher source emission.

use std::collections::BTreeMap;
use std::path::PathBuf;

use vyre_driver::aot::{AotLauncherFiles, AotLauncherRequest, LauncherDependency};

const CUDA_FFI: &str = include_str!("../templates/cuda_ffi.rs.tmpl");
const NCCL_FFI: &str = include_str!("../templates/nccl_ffi.rs.tmpl");

pub(crate) fn emit_launcher(request: &AotLauncherRequest<'_>) -> Result<AotLauncherFiles, String> {
    if request.include_ttt_loop {
        return Err(
            "PTX launcher TTT loop requested, but the CUDA launcher owns no TTT executor yet"
                .to_string(),
        );
    }

    let mut files = BTreeMap::new();
    files.insert(PathBuf::from("src/main.rs"), emit_main(request));
    files.insert(PathBuf::from("src/cuda_ffi.rs"), CUDA_FFI.to_string());
    if request.include_collectives {
        files.insert(PathBuf::from("src/nccl_ffi.rs"), NCCL_FFI.to_string());
    }

    Ok(AotLauncherFiles {
        dependencies: vec![LauncherDependency {
            name: "libc",
            spec: "\"0.2\"",
        }],
        files,
    })
}

fn emit_main(request: &AotLauncherRequest<'_>) -> String {
    let nccl_use = if request.include_collectives {
        "mod nccl_ffi;\nuse nccl_ffi as nccl;"
    } else {
        ""
    };
    let nccl_init = if request.include_collectives {
        r#"let world_size: i32 = std::env::var("WORLD_SIZE").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
        let rank: i32 = std::env::var("RANK").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
        let nccl_comm = if world_size > 1 {
            Some(nccl::init_world(rank, world_size)?)
        } else {
            None
        };"#
    } else {
        "let nccl_comm: Option<()> = None;"
    };
    let nccl_drop = if request.include_collectives {
        "if let Some(comm) = nccl_comm { nccl::destroy(comm)?; }"
    } else {
        "drop(nccl_comm);"
    };

    format!(
        r##"//! Auto-generated PTX launcher.
//!
//! Self-contained launcher. It reads `manifest.json`, `kernel.<ext>.lzma`,
//! and `weights.brotli`, allocates device buffers, and dispatches the embedded
//! PTX kernel through the CUDA driver API.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

mod artifact;
mod cuda_ffi;
use cuda_ffi as cuda;

{nccl_use}

fn main() -> ExitCode {{
    match run() {{
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {{
            eprintln!("launcher error: {{e}}");
            ExitCode::FAILURE
        }}
    }}
}}

fn run() -> Result<(), Box<dyn std::error::Error>> {{
    let bundle_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {{
            env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(PathBuf::from))
                .unwrap_or_else(|| PathBuf::from("."))
        }});

    let bundle = artifact::load_bundle(&bundle_dir)?;

    cuda::cu_init()?;
    let device = cuda::cu_device_get(0)?;
    let ctx = cuda::cu_ctx_create(device)?;
    let _ctx_guard = ctx;

    let module = cuda::cu_module_load_data(&bundle.kernel_bytes)?;
    let kernel = cuda::cu_module_get_function(module, &bundle.manifest.entry_point)?;

    let mut device_ptrs: Vec<u64> = Vec::with_capacity(bundle.manifest.buffers.len());
    for buf in &bundle.manifest.buffers {{
        let bytes = (buf.element_count as u64) * (buf.element_size_bytes as u64);
        let bytes = if bytes == 0 {{ DEFAULT_STREAMING_BUFFER_BYTES }} else {{ bytes }};
        let dptr = cuda::cu_mem_alloc(bytes)?;
        device_ptrs.push(dptr);
    }}

    if let Some(params_dptr) = device_ptrs.first().copied() {{
        cuda::cu_memcpy_h_to_d(params_dptr, &bundle.weight_bytes)?;
    }}

    {nccl_init}

    cuda::cu_launch_kernel(
        kernel,
        bundle.manifest.dispatch.grid_size,
        bundle.manifest.dispatch.workgroup_size,
        bundle.manifest.dispatch.dynamic_shared_bytes,
        &device_ptrs,
    )?;

    let metrics_idx = bundle
        .manifest
        .buffers
        .iter()
        .position(|b| b.name == "metrics");
    if let Some(idx) = metrics_idx {{
        if let Some(&dptr) = device_ptrs.get(idx) {{
            wait_for_completion(dptr)?;
        }}
    }}

    cuda::cu_stream_synchronize()?;

    if let Some(idx) = metrics_idx {{
        if let Some(&dptr) = device_ptrs.get(idx) {{
            print_final_metrics(dptr, &bundle.manifest)?;
        }}
    }}

    {nccl_drop}

    Ok(())
}}

const DEFAULT_STREAMING_BUFFER_BYTES: u64 = 1 << 24;
const METRIC_RECORD_WORDS: usize = 8;
const COMPLETION_IDLE_POLLS: u32 = 1000;
const COMPLETION_SPIN_POLLS: u32 = 64;
const COMPLETION_YIELD_POLLS: u32 = 256;
const COMPLETION_MIN_PARK: std::time::Duration = std::time::Duration::from_micros(2);
const COMPLETION_MAX_PARK: std::time::Duration = std::time::Duration::from_micros(50);

fn wait_for_completion(metrics_dptr: u64) -> Result<(), Box<dyn std::error::Error>> {{
    let mut last = 0u32;
    let mut idle_iters = 0u32;
    loop {{
        let mut buf = [0u32; 1];
        cuda::cu_memcpy_d_to_h(&mut buf, metrics_dptr)?;
        let cur = buf[0];
        if cur == last {{
            idle_iters += 1;
            if idle_iters > COMPLETION_IDLE_POLLS {{
                break;
            }}
        }} else {{
            idle_iters = 0;
            last = cur;
        }}
        if idle_iters <= COMPLETION_SPIN_POLLS {{
            std::hint::spin_loop();
        }} else if idle_iters <= COMPLETION_YIELD_POLLS {{
            std::thread::yield_now();
        }} else {{
            let shift = (idle_iters - COMPLETION_YIELD_POLLS).min(5);
            let park = COMPLETION_MIN_PARK
                .saturating_mul(1u32 << shift)
                .min(COMPLETION_MAX_PARK);
            std::thread::park_timeout(park);
        }}
    }}
    Ok(())
}}

fn print_final_metrics(
    metrics_dptr: u64,
    manifest: &artifact::Manifest,
) -> Result<(), Box<dyn std::error::Error>> {{
    let metrics_buf = manifest.buffers.iter().find(|b| b.name == "metrics");
    let ring_size = metrics_buf.map(|b| b.element_count as usize).unwrap_or(4096);
    let last_record_offset = ring_size.saturating_sub(METRIC_RECORD_WORDS) * 4;

    let mut record = [0u32; METRIC_RECORD_WORDS];
    cuda::cu_memcpy_d_to_h_offset(&mut record, metrics_dptr, last_record_offset as u64)?;

    let step = record[0];
    let loss = f32::from_bits(record[1]);
    let tokens = record[2];
    println!("FINAL step={{step}} loss={{loss:.6}} tokens={{tokens}}");
    Ok(())
}}
"##,
        nccl_use = nccl_use,
        nccl_init = nccl_init,
        nccl_drop = nccl_drop,
    )
}
