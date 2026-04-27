# vyre release process

## 0.6 playbook (quick-reference)

Operator with `cargo login <crates.io token>` runs:

```bash
# Pre-flight
cd libs/performance/matching/vyre
cargo build --workspace && cargo test --workspace && cargo clippy --workspace
bash scripts/check_no_string_wgsl.sh
bash scripts/check_public_api.sh

# Alpha: bump to 0.6.0-alpha.1 across all 11 crates + workspace deps,
# publish in dependency order with 5-min pause per crate
for crate in vyre-spec vyre-macros vyre-primitives vyre-foundation \
             vyre-driver vyre-driver-wgpu vyre-driver-spirv vyre-ops \
             vyre-reference vyre-libs vyre-core; do
    cargo publish -p $crate --locked
    sleep 300
done

# Smoke test on a fresh machine
cargo install vyre-driver-wgpu --version =0.6.0-alpha.1 --root /tmp/s
/tmp/s/bin/vyre --version && /tmp/s/bin/vyre demo

# 24-hour soak; monitor github issues + security@santh.dev
# On clean soak, bump versions to 0.6.0, repeat publish loop
```

Yank + fix recipe for security issues:

```bash
cargo yank --vers 0.6.0 <crate>
# fix + publish 0.6.1
```

Full topological ordering + rollback + 0.7 RFC kickoff below.

---



Every crate in the vyre workspace publishes to crates.io on every tagged release. This document is the single source of truth for cutting a release; any deviation is a CI or process bug, not a valid shortcut.

For conflicts between release docs, plans, audits, generated docs, and
internal archives, use [`docs/DOCUMENTATION_GOVERNANCE.md`](docs/DOCUMENTATION_GOVERNANCE.md).

## Topological publish order

Crates must be published in dependency order so that when `vyre-conform` pulls `vyre-reference` from crates.io (not path), the registry already has it.

1. `vyre-build-scan` — no internal deps.
2. `vyre-spec` — depends on nothing internal.
3. `vyre` — depends on `vyre-spec`, build-depends on `vyre-build-scan`.
4. `vyre-reference` — depends on `vyre`, `vyre-spec`.
5. `vyre-wgpu` — depends on `vyre`, `vyre-spec`.
6. `vyre-std` — depends on `vyre`, `vyre-spec`.
7. `vyre-sigstore` — depends on `vyre-spec` only.
8. `vyre-conform` — depends on every crate above.

## Pre-release checklist

1. `cargo check --workspace --all-targets --all-features` — zero errors, zero warnings.
2. `cargo test --workspace --release --all-features` — every test passes.
3. `cargo clippy --workspace --all-targets --all-features -- -D warnings` — clean.
4. `cargo +nightly udeps --workspace` — no unused deps.
5. `cargo deny check` — licenses + advisories + sources green.
6. `cargo public-api --all-features` — diff against `docs/public-api/*.txt` baselines zero unexpected.
7. `cargo semver-checks check-release` — every publishable crate passes.
8. `cargo bench -p vyre -p vyre-wgpu -p vyre-std -p vyre-conform` — runs, produces numbers.
9. `cargo test --test cert_hash_stable -p vyre-conform` — certificate determinism verified.
10. `cargo test gpu_parity -p vyre-wgpu` — GPU parity passes on the target GPU.
11. Every crate's `CHANGELOG.md` has an entry for the new version.
12. Workspace `Cargo.toml` version bumps are coherent (no crate on an older version than what it depends on).
13. `CITATION.cff` version field matches the tag.

## Publish

For each crate, in the order above:

```bash
cd <crate-dir>
cargo publish --dry-run
# inspect output, confirm no path-only deps escape
cargo publish
# wait for crates.io to index
sleep 60
```

A one-shot script exists at `scripts/publish-dryrun.sh` for the dry-run pass.

## Tag + release notes

After the last crate publishes:

```bash
git tag v0.4.0
git push origin v0.4.0
gh release create v0.4.0 \
    --title "vyre v0.4.0 — GPU IR with byte-identical conformance" \
    --notes-file docs/release/v0.4.0.md
```

Release notes are generated from the per-crate `CHANGELOG.md` entries for the new version. Never hand-write them separately from the changelogs.

## Rollback

If a crate publishes broken, **yank**, do not unpublish (crates.io does not permit unpublish after 72h). Cut a patch release the same day.

```bash
cargo yank --vers 0.4.0 <crate>
```

Fix forward; publish `0.4.1` with the correction.

## Post-release

1. Update the `README.md` banner at workspace root with the new version.
2. Update the user-facing install documentation.
3. Open issues for every finding surfaced during the release that didn't block ship.
4. Single Telegram ping to `@SanthCEObot` with the release URL.

## Publish DAG

```text
vyre-spec ─┬──> vyre-macros ─┐
           ├──> vyre-primitives ──> vyre-foundation ─┐
           │                                         ├──> vyre-driver ─┐
           │                                         │                  │
           │                                         │                  ├──> vyre-driver-wgpu ─┐
           │                                         │                  ├──> vyre-driver-spirv │
           │                                         │                  │                      │
           │                                         └──> vyre-intrinsics ─────┘                      │
           │                                                                                   │
           │                                         ┌──> vyre-reference <──────────────────────┘
           │                                         │
           │                                         ├──> vyre-runtime
           │                                         └──> vyre-libs
           │
           └──────────────────────────────────────────> vyre (meta shim — published last)
```

Publish order (left-to-right, same-column in any order):

1. **Foundation layer** — `vyre-spec`, `vyre-macros`
2. **Schema layer** — `vyre-primitives`, `vyre-foundation`
3. **Contract layer** — `vyre-driver`, `vyre-intrinsics`
4. **Backend layer** — `vyre-driver-wgpu`, `vyre-driver-spirv`, `vyre-driver-photonic`
5. **Runtime layer** — `vyre-reference`, `vyre-runtime`
6. **Library layer** — `vyre-libs`
7. **Meta shim** — `vyre`

Verify the DAG automatically from `Cargo.toml` metadata:

```sh
cargo xtask release-order
```

The `xtask` prints the publish order as a topological sort of the
crate graph; any deviation from the order above signals a dependency
cycle or a missing crate.

## Community / post-0.6 crates

These publish independently on their own cadence after 0.6.0:

- `vyre-pipeline-cache` — content-addressed SPIR-V blob store.
- `vyre-autodiff` — reverse-mode AD transform (roadmap R-1).
- `vyre-verify` — Kani theorem harness (roadmap R-2).
- `vyre-libs-llm` — FlashAttention-v2 + KV-cache + MoE (roadmap R-3).
- Community dialect packs under `vyre-libs-*` (e.g.
  `vyre-libs-quant`, `vyre-libs-sparse`, `vyre-libs-collective`).
- Community-registered backends following `vyre-driver-*` naming.

Every community crate must pin `vyre = "0.6"` or later and pass the
conformance-certificate gate (see `conform/`).
