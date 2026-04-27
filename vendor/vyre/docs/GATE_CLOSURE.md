# Gate Closure Mechanics — vyre 0.6 → 0.7

Closes tasks #47 (E.1 gate closure mechanics) and #48 (E.2 yank
0.5 from crates.io if gate cannot close).

## The gates

vyre's 0.6 → 0.7 release graduates from "conformance-certified
CPU/GPU parity" to "≥1000× competition gate proven per-cell."
Five gates must all close before the 0.7 tag lands:

| Gate | Owner | Measurable |
|---|---|---|
| **G1 — Zero-stub** | `cargo xtask gate1` | `clippy::todo/unimplemented/panic/expect/unwrap` deny passes across every `src/` tree. |
| **G2 — Conformance** | `vyre-conform-runner prove` | Certification artifact signed by OsRng-seeded Ed25519 (CONFORM C2) covers every registered op, with the hash-chain plus signature both verifying. |
| **G3 — Region chain** | `cargo test -p vyre-libs --test region_chain_invariant` | Every Tier-3 op's Region chain terminates at registered generators (VISION V7). |
| **G4 — ≥1000× competition** | `cargo bench -p surgec --features gpu --bench vs_competition` | Every matrix cell meets its threshold in `libs/tools/surgec/benches/thresholds.toml` (surgec BENCHMARK.md). |
| **G5 — LAW 7 organisation** | `cargo xtask lego-audit` + file-length gate | No file >500 LOC without a split-tracking entry, no cross-dialect reachthrough (VISION V5 guard), every dialect has a README. |

## Closure order

1. **G1** must be clean every commit. Hard CI gate since 0.5.
2. **G2** + **G3** run on every tag cut. Breakage blocks the tag.
3. **G4** runs on the release branch. A missed cell **blocks the tag** and triggers the E.2 path.
4. **G5** runs on every merge; regressions block merge.

## E.2 — Yank protocol if G4 cannot close

If G4 cannot close by the release deadline:

1. **Yank 0.5 from crates.io** with `cargo yank --version 0.5.0` on every vyre crate and on surgec. Yanking keeps existing consumers building but blocks new installs — the signal downstream authors need to stop building against a version whose claims are unvalidated.

2. **Publish a holding notice** at the top of each README pointing at the open cell and naming an owner + ETA. Example:

   ```
   > **0.5.0 has been yanked.** The ≥1000× competition gate did
   > not close on (rule_class=regex-backref-free, corpus=10GB,
   > gpu=rtx-4090). Owner: `@<handle>`. Tracking: issue #<n>.
   > New installs should wait on 0.6.0 (ETA <date>).
   ```

3. **Do not tag 0.7** until every gate is green or the user has explicitly waived the affected cell in writing. Signed-off waivers record which cells are known-degraded; the certification artifact lists them.

4. **Keep writing code.** The yank does not pause development — it only gates the *release*. Agents continue closing audit findings, landing optimisations, and growing the Tier-3 surface. The 0.7 tag cuts when the gates go green.

### Why yank instead of patch-release

A patch release shipping an un-certified ≥1000× claim would make every downstream author relying on the 0.5 number silently wrong. Yank is the cheapest honest signal. Downstream authors who already built against 0.5 keep working; nobody new adopts a version whose product claim is under audit.

## Verifying a gate snapshot

```bash
# G1
cargo xtask gate1

# G2
cargo run -p vyre-conform-runner -- prove --out certs/g2-<tag>.json
cargo run -p vyre-conform-runner -- verify certs/g2-<tag>.json \
    --pubkey <trusted.hex>

# G3
cargo test -p vyre-libs --test region_chain_invariant

# G4
cargo bench -p surgec --features gpu --bench vs_competition
./scripts/check-thresholds.py

# G5
cargo xtask lego-audit
./scripts/check-file-lengths.py
```

Every command must exit 0 against the release commit. CI mirrors this sequence on every tag cut.

## Open items

- `scripts/check-thresholds.py` and `scripts/check-file-lengths.py` are scaffolded; numbers land with #39 B.5.
- The cert-verification step currently hash-chain-only; the signature-half uses `verify_cert_signature_hex` landed 2026-04-23 (CONFORM C1). Next sweep wires it into the default verify path once every downstream cert has a real signature.
