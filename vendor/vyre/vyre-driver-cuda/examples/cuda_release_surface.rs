fn main() {
    println!("CUDA backend id: {}", vyre_driver_cuda::CUDA_BACKEND_ID);
    println!("CUDA caps type: {}", std::any::type_name::<vyre_driver_cuda::CudaDeviceCaps>());
    println!("Acquire with vyre_driver_cuda::CudaBackend::acquire() on a CUDA host.");
}
