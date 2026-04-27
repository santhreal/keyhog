# Vyre — Supported Targets

> What works, what is experimental, what requires explicit opt-in.
> This document is load-bearing — every CI job and every published
> crate derives its support matrix from it.

## Tier 1 — fully supported

| Target                            | Registration  | wgpu backend | conform runner | Notes                                |
| --------------------------------- | ------------- | ------------ | -------------- | ------------------------------------ |
| `x86_64-unknown-linux-gnu`        | `inventory`   | Vulkan       | yes            | Primary dev target                   |
| `aarch64-unknown-linux-gnu`       | `inventory`   | Vulkan       | yes            | ARM server / Raspberry Pi 5          |
| `x86_64-apple-darwin`             | `inventory`   | Metal        | yes            | Intel Mac, pre-Apple-Silicon         |
| `aarch64-apple-darwin`            | `inventory`   | Metal        | yes            | Apple Silicon Mac                    |
| `x86_64-pc-windows-msvc`          | `inventory`   | DX12/Vulkan  | yes            |                                      |

Tier 1 means: the crate compiles, all tests pass, `inventory`-based
backend and op registration works without a feature flag, and the wgpu
backend has a verified GPU path on the platform's native API.

## Tier 2 — explicit-registration required

| Target                            | Registration       | wgpu backend | Notes                                    |
| --------------------------------- | ------------------ | ------------ | ---------------------------------------- |
| `wasm32-unknown-unknown`          | `explicit_registration` feature | WebGPU | No linker sections — `inventory` is unavailable; use the macro table |
| `aarch64-apple-ios`               | `explicit_registration` feature | Metal  | Static linking + dead-stripping breaks `inventory`                  |
| `aarch64-apple-ios-sim`           | `explicit_registration` feature | Metal  | Same                                                                |
| `*-linux-musl` with static LTO    | `explicit_registration` feature | varies | `--gc-sections` can strip inventory slots                           |

On Tier 2 targets, the default `inventory`-based registration is
unavailable. The consumer crate must enable the `explicit_registration`
feature and call the `vyre::register!` macro at the top of its binary:

```rust
fn main() {
    vyre::register_backend!(vyre_wgpu::WGPU_BACKEND_REGISTRATION);
    vyre::register_backend!(vyre_reference::REFERENCE_BACKEND_REGISTRATION);
    // ... plus every primitive and pass registration required by the program ...
    vyre::register_primitives!(vyre_primitives::ALL_PRIMITIVES);
    vyre::register_passes!(vyre_core::optimizer::ALL_PASSES);
    // now the registry is populated; dispatch away.
    run().expect("dispatch ok");
}
```

The `register_backend!`, `register_primitives!`, and `register_passes!`
macros populate a `OnceLock<Vec<...>>` backing the same
`registered_backends()` / `registered_primitives()` / `registered_passes()`
public API that Tier 1 targets populate automatically via `inventory`.
From the consumer's perspective the API is identical — only the
registration wiring differs.

## Tier 3 — not supported, PRs welcome

- `*-windows-gnu` (MinGW): wgpu backend has known issues; no CI coverage.
- Android (`*-android`): `inventory` works but wgpu backend requires
  custom surface setup that Vyre does not ship.
- FreeBSD, OpenBSD, Solaris: likely work but no CI coverage.
- Bare-metal / `no_std` embedded: out of scope; Vyre requires the
  standard library for the IR graph and memory model.

A target is promoted from Tier 3 to Tier 2 by adding CI coverage and an
`explicit_registration` path if needed. A Tier 2 target is promoted to
Tier 1 by making the native registration mechanism work without a
feature flag.

## Feature-flag matrix

```
vyre-ir               default-features = ["inventory"]
                      feature "inventory"           — enable inventory::collect registration
                      feature "explicit_registration" — enable macro-based registration for Tier 2

vyre-primitives       follows vyre-ir feature flags
vyre-wgpu             default-features = ["inventory"]
vyre-conform          default-features = ["inventory"]
```

On Tier 1 you get `inventory`. On Tier 2 you disable default features
and enable `explicit_registration`. The two are mutually exclusive; a
build that enables both hits a compile-time `compile_error!` pointing
at this document.

## Why not always explicit_registration?

Tier 1 dominates real deployments and `inventory`-based registration
means a consumer who writes `vyre::execute(&program, &inputs)` gets
every linked backend and primitive for free — no boilerplate. Forcing
every consumer to enumerate registrations at main() is friction that
the 99% case does not need.

The explicit path exists so the 1% case (WASM, iOS, static LTO
deployment) is not blocked. It is a supported fallback, not a
placeholder.

## Verifying at build time

`vyre-ir/build.rs` emits a `compile_error!` if:

- The target is in the Tier 2 list AND `inventory` is enabled AND
  `explicit_registration` is not enabled — the consumer is about to
  get silently empty registries.
- Both `inventory` and `explicit_registration` features are enabled
  simultaneously — registration would happen twice.

The error message names the detected target, the active feature flags,
and the specific remediation (enable `explicit_registration`, disable
default features, etc.).
