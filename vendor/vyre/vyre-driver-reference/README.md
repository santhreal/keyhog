# vyre-driver-reference

`vyre-driver-reference` registers the pure Rust `cpu-ref` backend adapter.
It keeps `vyre-reference` independent from the driver layer while still letting
registry-based callers acquire a deterministic fallback backend when this crate
is linked.
