# keyhog-scanner

High-performance secret detection engine with a portable CPU reference,
Hyperscan trigger matching, VYRE GPU region presence, entropy/BPE policy,
decode-through scanning, and bounded static recovery of embedded JavaScript
XOR and AES-256-CBC expressions.

Part of the [KeyHog](https://github.com/santhreal/keyhog) secret scanner.

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

If you construct `DetectorSpec` values in memory, `CompiledScanner::compile`
applies the same quality gate used by the TOML loader. Invalid fields or
duplicate detector IDs return a configuration error before matcher or backend
construction.

A detector that owns entropy fallback or sets `bpe_enabled = true` requires the
scanner `entropy` feature. Scanner construction returns an actionable
configuration error when the artifact cannot execute a declared mechanism. It
never compiles a weaker detector under the same detector identity.

Register custom decoders before you compile a scanner:

```rust,ignore
keyhog_scanner::decode::try_register_decoder(Box::new(MyDecoder))?;
let scanner = CompiledScanner::compile(detectors)?;
```

`CompiledScanner` snapshots the ordered decoder set. Later registrations apply
only to scanners compiled afterward. Your decoder inherits version `"1"` from
the `Decoder` trait. Override `version` and increment it whenever the same input
can produce different decoded chunks. Decoder names and versions form part of
the scanner and autoroute identity. Empty descriptors, whitespace, non-ASCII
descriptors, and duplicate names return `DecoderRegistrationError`.
The compatibility `register_decoder` function keeps its unit return type. If it
cannot register a decoder, the next scanner compilation returns that error.

For example, `max_len = 512` admits a 512-byte candidate and rejects a
513-byte candidate whole. Generic assignment, entropy fallback, and explicit
regex envelopes use the same compiled inclusive bound before entropy or BPE
work.

See the [main documentation](https://github.com/santhreal/keyhog) for the
detector schema, backend calibration, parity guarantees, and complete usage.
