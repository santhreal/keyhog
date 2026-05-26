use keyhog_scanner::gpu::gpu_available;
#[test]
fn gpu_available_is_boolean() {
    let _ = gpu_available();
}
