# keyhog-scanner

High-performance secret detection engine with a portable CPU reference,
Hyperscan trigger matching, VYRE GPU region presence, entropy/BPE policy, and
decode-through scanning.

Part of the [KeyHog](https://github.com/santhsecurity/keyhog) secret scanner.

```rust
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

let detectors = keyhog_core::load_embedded_detectors_or_fail()?;
let scanner = CompiledScanner::compile(detectors)?;
let chunk = Chunk {
    data: "API_TOKEN=example".into(),
    metadata: ChunkMetadata::default(),
};

// Host-independent portable reference.
let reference = scanner.scan(&chunk);

// Explicit acceleration; unavailable requested backends fail loudly.
let accelerated = scanner.scan_with_backend(&chunk, ScanBackend::SimdCpu);
# Ok::<(), Box<dyn std::error::Error>>(())
```

`scan` and `scan_coalesced` never infer a backend from hardware. Use the
explicit-backend methods when embedding an execution policy. Persisted,
parity-checked automatic routing belongs to the `keyhog` CLI because its
decision identity includes the binary, detector/config digests, host, runtime
lifetime, and workload class.

Detector-specific candidate generation and policy are compiled from the
detector TOMLs embedded by `keyhog-core`; scanner configuration supplies the
operational defaults and explicit overrides. Every backend feeds the same
extraction, suppression, confidence, decode, and reporting contracts.

See the [main documentation](https://github.com/santhsecurity/keyhog) for the
detector schema, backend calibration, parity guarantees, and complete usage.
