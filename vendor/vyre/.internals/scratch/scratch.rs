fn check_clone<T: Clone>() {}
fn main() { check_clone::<wgpu::Buffer>(); }
