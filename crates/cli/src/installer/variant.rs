//! Install/update release variant selection.
//!
//! `install.sh`, `keyhog update`, and `keyhog repair` must agree on the
//! omitted-variant behavior: on Linux x86_64 hosts with an NVIDIA GPU, loadable
//! libcuda, and an installed CUDA toolkit, default to the CUDA asset; otherwise
//! use the platform's default non-CUDA release asset. Explicit variants are
//! strict.

use anyhow::{Result, anyhow};
use std::ffi::OsStr;
use std::path::Path;

pub(crate) fn wants_cuda_variant(explicit: Option<&str>) -> Result<bool> {
    match explicit {
        Some("cuda") => Ok(true),
        Some("cpu") => Ok(false),
        Some(other) => Err(anyhow!(
            "invalid release variant `{other}`. Use `--variant cuda` for the CUDA Linux build or \
             `--variant cpu` for the default non-CUDA release asset."
        )),
        None => Ok(default_wants_cuda_variant()),
    }
}

pub(crate) fn default_wants_cuda_variant() -> bool {
    default_wants_cuda_variant_for_host(
        std::env::consts::OS,
        std::env::consts::ARCH,
        nvidia_gpu_present(),
        libcuda_present(),
        cuda_toolkit_present(),
    )
}

pub(crate) fn default_wants_cuda_variant_for_host(
    os: &str,
    arch: &str,
    nvidia_gpu: bool,
    libcuda: bool,
    cuda_toolkit: bool,
) -> bool {
    os == "linux" && arch == "x86_64" && nvidia_gpu && libcuda && cuda_toolkit
}

fn nvidia_gpu_present() -> bool {
    let output = match std::process::Command::new("nvidia-smi").arg("-L").output() {
        Ok(output) => output,
        Err(_) => return false, // LAW10: failed optional host probe => no automatic CUDA asset; explicit `--variant cuda` still fails closed if unavailable.
    };
    output.status.success() && String::from_utf8_lossy(&output.stdout).contains("GPU ")
}

fn libcuda_present() -> bool {
    let ldconfig_has_cuda = match std::process::Command::new("ldconfig").arg("-p").output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).contains("libcuda.so")
        }
        _ => false,
    };
    ldconfig_has_cuda
        || [
            "/usr/lib/x86_64-linux-gnu/libcuda.so",
            "/usr/lib64/libcuda.so",
            "/usr/local/cuda/lib64/libcuda.so",
            "/opt/cuda/lib64/libcuda.so",
        ]
        .iter()
        .any(|path| Path::new(path).exists())
}

fn cuda_toolkit_present() -> bool {
    command_on_path("nvcc")
        || std::env::var_os("CUDA_HOME").is_some_and(|path| Path::new(&path).is_dir())
        || Path::new("/usr/local/cuda").is_dir()
        || Path::new("/opt/cuda").is_dir()
}

fn command_on_path(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(OsStr::new(name)).is_file())
}
