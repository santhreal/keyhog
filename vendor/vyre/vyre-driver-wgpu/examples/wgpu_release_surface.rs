fn main() {
    println!("WGPU backend type: {}", std::any::type_name::<vyre_driver_wgpu::WgpuBackend>());
    println!("Acquire with vyre_driver_wgpu::WgpuBackend::acquire() when validating the fallback backend.");
}
