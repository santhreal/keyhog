# Inventory Contract

This document standardizes the usage of `inventory::submit!` across the Vyre ecosystem.

## Policy
Registration at link time via `inventory` is the single source of truth for extensibility. Runtime discovery arrays and legacy static catalogs are deprecated. 

## Collections
The following `inventory` collections are officially supported:
1. `OpDefRegistration` - Defines dialect algorithms and hardware intrinsics.
2. `BackendRegistration` - Defines compute substrates (e.g. `wgsl`, `cuda`, `spirv`).
3. `PassRegistration` - Defines compiler transformation and optimization passes.
4. `ExtensionRegistration` - Defines opaque IR extensions (e.g., `ExtensionDataTypeId`).
5. `MigrationRegistration` - Defines protocol buffers / IR backward-compat migrations.

## Iteration Order
There are NO guarantees regarding iteration order when interacting with an inventory collection. Downstream systems and consumers MUST explicitly sort the iterator if deterministic behavior is strictly required.
