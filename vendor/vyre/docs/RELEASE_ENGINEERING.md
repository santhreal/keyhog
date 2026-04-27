# Release Engineering — vyre + surgec

Closes #34 (A.10 release engineering). Complements `docs/GATE_CLOSURE.md`
(the per-release gate protocol) with the day-to-day shape of
shipping a version.

## Version discipline

- vyre core crates (`vyre-foundation`, `vyre-core`, `vyre-driver`,
  `vyre-driver-wgpu`, `vyre-driver-spirv`, `vyre-reference`,
  `vyre-spec`, `vyre-macros`, `vyre-intrinsics`, `vyre-primitives`,
  `vyre-libs`, `vyre-runtime`) move in **lock-step**. Every minor
  tag carries the same `version = "x.y.0"` across all of them. Patch
  versions can skew per-crate during emergency patch releases.
- `surgec` versions independently but **declares a tested vyre
  minor** in its Cargo.toml. Upgrading surgec to a new vyre minor
  is a new minor of surgec.
- Tier-3 dialect splits (`vyre-libs-nn`, `vyre-libs-crypto`, …)
  move on the vyre minor line.
- Tier-4 external packs (`vyre-libs-extern`, community authored)
  version independently per pack. The `ExternDialect` registration
  records the pack's minimum vyre minor.

## Publishing order

Each release pushes crates in dep-order so mid-publish breakage
doesn't leave downstream consumers linking a wedge-version:

```
1. vyre-foundation
2. vyre-macros
3. vyre-spec
4. vyre-primitives
5. vyre-driver
6. vyre-reference
7. vyre-intrinsics
8. vyre-driver-spirv
9. vyre-driver-wgpu
10. vyre-libs
11. vyre-runtime
12. vyre-core            (the `vyre` façade crate)
13. surgec
14. vyre-conform-spec
15. vyre-conform-runner  (optional — only if conform protocol changes)
```

`scripts/publish-release.sh` runs this sequence, dry-runs first,
waits 30 s between pushes (so crates.io indexers can see each one),
and stops on any `cargo publish` failure.

## Tag format

- Git tag: `vX.Y.Z` for core crates, `surgec-vX.Y.Z` for surgec.
- Release artifacts: `certs/CERTIFICATION-vX.Y.Z.json` (CONFORM
  C2-signed), `benches/results/vX.Y.Z/` (criterion HTML + the raw
  JSON the ≥1000× gate was measured against).

## Changelog protocol

`CHANGELOG.md` follows Keep-a-Changelog, one per crate:

- **Added / Changed / Deprecated / Removed / Fixed / Security** sections.
- Every item cross-references the audit or issue that drove it
  (`CRITIQUE_* Finding N`, `VISION V<n>`, `#<task>`). A reader
  tracing why a line of code moved must be one grep away from the
  source-of-truth rationale.
- Security-impacting changes (gate C1, C2, pocgen `dangerous-exploits`, …)
  go in the **Security** section and copy the `Fix:` hint from the
  fix commit so the changelog is actionable for downstream pinning
  decisions.

## Pre-flight checklist

1. `cargo xtask gate1` — zero-stub.
2. `cargo xtask lego-audit` — LAW 7 + cross-dialect reachthrough.
3. `cargo test --workspace` + `cargo test -p surgec --features gpu --tests` —
   includes VISION V7 region-chain + V10 arbitrary-compute E2E.
4. `cargo bench -p surgec --features gpu --bench vs_competition` —
   the ≥1000× gate. Fail here = E.2 yank protocol.
5. `cargo run -p vyre-conform-runner -- prove --out certs/…` — mint
   the cert. Sign with the release-engineer key (OsRng-seeded per
   CONFORM C2).
6. `cargo publish --dry-run -p <each crate>` in order.
7. `scripts/publish-release.sh` — real push.
8. Open the GitHub release with the certification JSON attached.
9. Post the notice in the user-facing channel.
10. Re-run `cargo xtask gate1` + the cert verify on a fresh machine
    to confirm reproducibility.

## Post-release

- The `0.6.0` tag stays published even if a patch ships shortly
  after. No retroactive rewriting of history.
- If a security finding lands post-release, the patch cadence is
  48 h from triage to crates.io push, with a CHANGELOG `Security`
  entry naming the CVE + affected versions.

## Open items

- `scripts/publish-release.sh` is scaffolded in `scripts/`; the
  dry-run + sleep-between-pushes ordering is the next sweep.
- `scripts/verify-release.sh` runs steps 3 + 4 + 5 against a
  user-supplied tag so downstream CI can pin to a verified artifact.
