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
| Add a detector                    | Drop a TOML in `detectors/`, add a contract in `crates/scanner/tests/contracts/`. PR. |
| Fix an FP                         | Find the regex / shape gate that's firing. Tighten it. Add a negative test that would catch the regression. |
| Document something undocumented   | Edit `docs/src/*.md`. The site rebuilds on push to `main`. |

## Repo layout

```text
keyhog/
  crates/
    core/             # Detector spec, raw match types, severity, embed
    scanner/          # The scanner engine itself
    sources/          # Filesystem, git, web, docker, S3/GCS/Azure Blob, hosted-git backends
    verifier/         # Live credential verification
    cli/              # The `keyhog` binary, subcommand dispatch
  detectors/          # 922 embedded detector TOMLs
  crates/cli/data/
    suppressions/     # Test-fixture suppression list, baked into the binary
  docs/               # This documentation (mdBook source)
  install.sh          # Linux/macOS install script
  install.ps1         # Windows install script
```

The Rust workspace is at the root; each `crate/` member is a
standalone crate with its own `Cargo.toml`.

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

The contract gate enforces that every shipped detector catches what
it claims to catch. The flow:

1. **Write the detector TOML** at `detectors/<service>-<thing>.toml`.
   Use an existing detector as a template; the schema is documented
   in [Detectors](./detectors.md).

2. **Write the contract** at `crates/scanner/tests/contracts/<id>.toml`.
   At minimum, include:
   - 2 positives (env-var shape, quoted shape)
   - 2 negatives (placeholder, EXAMPLE token in the body)
   - 2 evasions (real-world shapes you've seen in actual leaks:
     Bearer header, JSON body, URL query param, multi-line config)
   - A `perf` block with `fixture_bytes` + `max_microseconds`
   - A `scale` block with `fixture_bytes` + `min_findings` +
     `max_seconds`

3. **Run the contract gate locally:**

   ```sh
   cargo test -p keyhog-scanner --test contracts_runner
   ```

   Must pass before you push. CI re-runs it with strict env vars set,
   which exercise more aggressive adversarial corpus.

4. **Open a PR.** A maintainer reviews the detector for:
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

2. **Write the filter.** Add to `crates/scanner/src/pipeline/postprocess/suppression.rs`
   alongside the existing `looks_like_*` functions. The function
   takes `&str` (the credential) or `Option<&str>` (the path) and
   returns `bool`.

3. **Wire it up.** Decide if it's Tier A (universal) or Tier B
   (generic / entropy only). See `should_suppress_named_detector_finding`
   for the existing wiring. Tier A is rare; default to Tier B unless
   the shape is structurally impossible for any service-anchored
   credential.

4. **Add a unit test.** Inputs that should trip the filter (5+
   variants), inputs that should not (3+ legitimate credentials).

5. **Run the contract gate.** New filters must not break any
   contract evasion. If they do, the contract is right and the
   filter is wrong. Tighten the filter.

## Style

- Rust edition 2021, MSRV 1.89.
- `cargo +stable fmt` + `cargo +stable clippy -- -D warnings`. CI
  enforces both.
- File-size cap: 500 lines per `.rs` file. Larger files get split.
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

The first four run in under 30 s. The contracts and property suites
take 1-2 minutes. CI runs all of them; locally, the first four are
the usual feedback loop.

## License

MIT. By contributing, you agree that your contributions are licensed
under the MIT license too.
