# io_uring DMA Bypass Implementation Plan

**Objective**: Implement zero-copy NVMe-to-GPU direct memory access (DMA) bypass within `vyre-pipeline`, eliminating CPU bounce buffers and adhering to the Compute 2.0 "CPU as Receptionist" constraint.

## Architecture

We are building a custom, high-throughput `io_uring` pipeline designed explicitly for GPU streaming. The CPU will only construct `sqe` (submission queue entries), while the actual data payload will DMA directly into host-pinned VRAM accessed by the Megakernel.

### Phase 1: `io_uring` Ring Setup
1. Define the `IoUringState` orchestrator within `vyre-pipeline::uring`.
2. Map a monolithic SQ (Submission Queue) and CQ (Completion Queue) via `mmap` wrapping raw `libc::syscall`. 
   *Do not use bloated third-party `tokio-uring` crates. Keep it 100% `no_std`/native-capable and auditable.*
3. Allocate a chunk of pinned memory visible to both host (`io_uring`) and GPU (`wgpu` MapMode).

### Phase 2: Direct-to-GPU Streaming
1. Instead of allocating standard page-aligned `Vec<u8>` on the CPU, the `io_uring` OP structures (`IORING_OP_READV` / `IORING_OP_READ_FIXED`) will use the mapped VRAM (`wgpu::Buffer` with `HOST_VISIBLE | HOST_SHARED`) as their `iovec` targets.
2. Create the `AsyncUringStream` struct that handles pushing chunked NVMe read commands into the SQ and reaping CQ events.

### Phase 3: The Megakernel Handshake
1. Once `io_uring` completes a read (CQ signals ready), we atomically increment the `tail_ptr` of the Megakernel ring buffer.
2. The `vyre-pipeline::GpuStream` bridges this: its `poll()` loop reaps `io_uring` completions and bumps the Megakernel atomic signals without copying bytes.

## Execution Requirements
* **Module Path**: `vyre-pipeline/src/uring/*`
* **Zero-Copy**: The bytes read from disk must never be touched or read by the CPU.
* **Rust safety**: Wrap the `libc` calls safely, maintaining memory stability and lifetimes of the I/O buffers.

**Action Item for Next Agent**: Start by building `vyre-pipeline/src/uring/ring.rs` with the core raw `io_uring_setup`, `io_uring_enter`, SQ, and CQ mmap routines.
