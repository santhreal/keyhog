# cross-backend comparison

Produced by `cargo run -p xtask -- bench-crossback <program>`. ms
values are wall-clock per call after 1000-dispatch warmup.
`VYRE_BENCH_GPU=1` enables the GPU dispatch columns.

| program | wgpu | spirv | ptx | metal | cpu-ref |
|---------|------|-------|-----|-------|---------|
| `xor-1k` | n/a | n/a | n/a | n/a | 0.011 |
