fn main() {
    println!("vyre public API: {}", std::any::type_name::<vyre::MemoryOrdering>());
    println!("enable the CUDA release path with: cargo add vyre --features cuda");
    println!("enable the WGPU fallback path with: cargo add vyre --features wgpu");
}
