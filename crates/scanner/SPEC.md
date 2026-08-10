# keyhog-scanner SPEC

`keyhog-scanner` compiles detector specifications into executable matchers and scans text chunks for credential candidates. It combines literal prefiltering, regex fallback, entropy scoring, decode-through scanning, context scoring, and optional acceleration features.

## Guarantees

- Scanner input is bounded by configured chunk, decode, and match limits.
- Decode-through scanning tracks seen decoded payloads to prevent repeated expansion.
- Findings preserve detector identity, source location, severity, confidence, and credential hash.
- Optional acceleration backends must preserve the same match semantics as the default scanner path.

## Ordered GPU device routes

Multi-device GPU execution is an autoroute peer. Calibration enumerates one stable physical adapter set, rejects software, display-only, duplicate, or incompletely identified exposures, measures each device for the exact workload, proves complete-route finding parity, and persists the ordered identities, timings, integer weights, capacities, and resident budgets under an authenticated digest.

Normal scans validate the complete live census before and after all-or-nothing acquisition. Exact chunk shards are assigned as contiguous weighted ranges. Each device owns a bounded resident slot, devices execute concurrently, and retirement restores source order. A missing device, identity change, dispatch failure, recovery receipt, panic, or incomplete result invalidates the selected route; no sibling result is returned as a partial scan.

## Boundaries

This crate consumes `keyhog-core` types and does not enumerate files, git history, cloud sources, or verify live credentials.
