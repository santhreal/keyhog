# Contributing

KeyHog is open source. The repo is at
[github.com/santhsecurity/keyhog](https://github.com/santhsecurity/keyhog).
Bug reports, feature requests, detector additions, and PRs are all
welcome.

## Quick paths

| What                              | How                                                     |
|-----------------------------------|---------------------------------------------------------|
| Report a bug                      | [Open an issue](https://github.com/santhsecurity/keyhog/issues/new) with a minimal reproducer. |
| Report a security issue           | Email `security@santh.dev` (PGP key in `SECURITY.md`). Don't open a public issue. |
| Add a detector                    | Add one detector TOML with its inline truth pair, then add its adversarial contract. |
| Fix an FP                         | Find the regex / shape gate that's firing. Tighten it. Add a negative test that would catch the regression. |
| Document something undocumented   | Edit the canonical page under `docs/src/`; the site rebuilds from that mdBook source. |

## Repo layout

```text
keyhog/
  crates/
    core/             # Detector spec, raw match types, severity, embed
    scanner/          # The scanner engine itself
    sources/          # Filesystem, git, web, docker, S3/GCS/Azure Blob, hosted-git backends
    verifier/         # Live credential verification
    cli/              # The `keyhog` binary, subcommand dispatch
  detectors/          # Embedded detector TOMLs: one secret type per file
  crates/cli/data/
    suppressions/     # Test-fixture suppression list, baked into the binary
  docs/               # This documentation (mdBook source)
  install.sh          # Linux/macOS install script
  install.ps1         # Windows install script
```

The Rust workspace is at the root; each `crates/` member is a standalone crate
with its own `Cargo.toml`. See [Architecture](./architecture.md) for crate
ownership and the end-to-end scan flow before moving code across boundaries.

## Building

```sh
git clone https://github.com/santhsecurity/keyhog
cd keyhog
cargo build --release -p keyhog
./target/release/keyhog --version
```

For development:

```sh
cargo build               # debug build
cargo test -p keyhog-scanner --lib
```

## Adding a detector

Detector truth has two layers. The compact positive/negative pair lives beside
the detector policy and protects every TOML edit. The separate contract adds
multiple envelopes, evasions, performance, and scale coverage. Both are
required; neither substitutes for the other.

1. **Write the detector TOML** at `detectors/<service>-<thing>.toml`.
   Use an existing detector as a template; the schema is documented
   in [Detectors](./detectors.md).

2. **Add the inline truth pair** in that same TOML:

   ```toml
   [[detector.tests]]
   test_positive = "SERVICE_API_KEY=<valid-shaped-test-value>"
   test_negative = "SERVICE_API_KEY=YOUR_API_KEY_HERE"
   ```

   Use synthetic or vendor-published test material, never a live credential.
   The positive must emit this detector's exact ID; the negative must remain
   silent through the production scan path.

3. **Write the adversarial contract** at
   `crates/scanner/tests/contracts/<id>.toml`.
   At minimum, include:
   - 2 positives (env-var shape, quoted shape)
   - 2 negatives (placeholder, EXAMPLE token in the body)
   - 2 evasions (real-world shapes you've seen in actual leaks:
     Bearer header, JSON body, URL query param, multi-line config)
   - A `perf` block with `fixture_bytes` + `max_microseconds`
   - A `scale` block with `fixture_bytes` + `min_findings` +
     `max_seconds`

4. **Run the detector truth gates locally:**

   ```sh
   cargo test -p keyhog-scanner --test detector_inline_test_truth
   cargo test -p keyhog-scanner --test contracts_runner
   ```

   Must pass before you push. CI re-runs it with strict env vars set,
   which exercise more aggressive adversarial corpus.

5. **Open a PR.** A maintainer reviews the detector for:
   - Service is real and not duplicated by an existing detector.
   - Keywords are short, distinctive, and unlikely to FP.
   - Regex captures the right group and rejects obvious placeholders.
   - Verify endpoint (if present) is read-only and won't trigger
     side-effects on the upstream service.

## Adding a suppression filter

If you find an FP cluster of 5+ findings that all share a shape, the
right fix is a new shape filter rather than 5 individual
suppressions. The flow:

1. **Reproduce.** Get the FPs into a `.envseal`-sealed corpus or a
   public sanitized fixture you can commit.

2. **Find the existing owner.** Search `crates/scanner/src/suppression/shape/`
   for the same operation before adding a helper. Extend the narrowest existing
   shape module; path, prose, public-identifier, canonical-shape, and randomness
   policy already have separate owners.

3. **Wire it through the shared policy boundary.** `suppression/api.rs` exposes
   the composed shape decisions and `adjudicate/` owns the final suppression
   verdict. Do not add an emission-path-only `looks_like_*` check: CPU, SIMD,
   GPU, generic, entropy, and fast-prefix paths must reach the same decision.

4. **Add a unit test.** Inputs that should trip the filter (5+
   variants), inputs that should not (3+ legitimate credentials).

5. **Run the contract gate.** New filters must not break any
   contract evasion. If they do, the contract is right and the
   filter is wrong. Tighten the filter.

## Style

- Rust edition 2021, MSRV 1.89.
- Run `cargo +stable fmt -- --check` and the relevant package's clippy target.
  Treat lints as bug leads; avoid behavior-free contortions for style-only
  findings.
- Split modules by responsibility, ownership, readability, and testability.
  File length is a prompt to inspect cohesion, not an architecture rule by
  itself.
- No `#[ignore]` on tests. A flaky test gets fixed or deleted, not
  silenced.
- No `todo!()` / `unimplemented!()` / `panic!("not implemented")` in
  shipped code paths.
- Comments explain WHY, not WHAT. Names carry WHAT.

## Tests

```sh
cargo test -p keyhog-core --lib          # detector spec / embed
cargo test -p keyhog-scanner --lib       # engine
cargo test -p keyhog --lib               # CLI / orchestrator
cargo test -p keyhog --test e2e_binary   # full-binary end-to-end
cargo test -p keyhog-scanner --test contracts_runner   # per-detector contract gate
cargo test -p keyhog-scanner property::scanner_fuzz    # proptest
```

Run the narrowest behavioral gate that proves the change, then the affected
package suite. Runtime depends on build profile, host, corpus, enabled features,
and cache warmth; command output is the timing evidence for that run.

## License

MIT. By contributing, you agree that your contributions are licensed
under the MIT license too.
