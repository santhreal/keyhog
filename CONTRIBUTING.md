# Contributing to keyhog

Thanks for considering a contribution. The most useful contributions
are the smallest: a false-positive report with a one-line snippet, a
detector regex tweak, a missing test case. The repo is laid out so a
new contributor can do real work after one read of this file.

Before opening a PR, please skim the [Code of Conduct](CODE_OF_CONDUCT.md)
and the project's anti-rigging law: a test must assert truth, not
shape; positive findings get a negative twin; every fix ships an
adversarial test alongside the proving test.

## Repo layout

- `crates/core/` - shared types, detector specs, hardening, the
  `Source` and `Reporter` traits.
- `crates/scanner/` - the engine: compiler, AC + Hyperscan + GPU
  backends, suppression, confidence, decoding, entropy.
- `crates/sources/` - filesystem, git, web, archive backends behind
  the `Source` trait.
- `crates/verifier/` - live credential probes (auth/identity
  endpoints) for `--verify`.
- `crates/cli/` - the `keyhog` binary, subcommands, args, daemon.
- `detectors/` - 919 TOML detector specs, the project's moat. No
  Rust code touched when you add one.
- `fuzz/` - cargo-fuzz harnesses, one target per parser/scanner sink.
- `ml/` - Python model training and Rust/Python feature-parity checks
  for the scanner's embedded MoE weights.
- `tests/`, `metrics/` - repo-level integration tests, corpus gates,
  and perf dashboards.
- `.github/actions/keyhog/` - the in-tree composite action
  consumers reference as
  `santhsecurity/keyhog/.github/actions/keyhog@<tag>`.

## How to add a new detector

No Rust code required. Detectors are TOML manifests under
`detectors/`. Copy the closest existing detector and edit:

```bash
cp detectors/stripe-secret-key.toml detectors/my-service-key.toml
$EDITOR detectors/my-service-key.toml
```

The required keys live under `[detector]` and one or more
`[[detector.patterns]]` blocks. Fields:

- `id` - unique kebab-case identifier, matches the filename.
- `name` - human-readable display name.
- `service` - lowercase vendor / protocol name.
- `severity` - `info | low | medium | high | critical`.
- `keywords` - case-aware substrings used to short-circuit the
  scan when none appear in a chunk. At least one is required.
- `[[detector.patterns]]` blocks - one or more, each with a
  `regex`, a one-line `description`, and a `group` for the
  match-group that captures the actual secret.
- `[detector.verify]` (optional) - if the service has a public
  status / identity endpoint that returns 200 on a live key and
  401/403 otherwise, fill this out and `--verify` will probe it.

Run the in-tree validation gate before committing:

```bash
cargo test -p keyhog-core --test all_tests detector_
```

Then add a per-detector contract under
`crates/scanner/tests/contracts/<detector-id>.toml` with at least one
`[[positive]]`, one `[[negative]]`, and one `[[evasion]]` entry, and
run the contract runner:

```bash
cargo test -p keyhog-scanner --test contracts_runner
```

Finally, dogfood the scanner on the repo itself. Zero new findings
are expected on a clean tree:

```bash
cargo run --release -- scan .
```

## How to add a new source backend

Source backends live in `crates/sources/src/`. Each implements
`keyhog_core::Source` (`crates/core/src/source.rs`).

1. Add a new module under `crates/sources/src/` and gate it behind
   a feature flag in `crates/sources/Cargo.toml` so consumers can
   opt in.
2. Implement `keyhog_core::Source` for your backend. The
   `filesystem` and `git` modules are the reference implementations.
3. Wire the backend into the CLI dispatch in
   `crates/cli/src/orchestrator/` so a subcommand or flag selects it.
4. Add adversarial tests under `crates/sources/tests/` covering
   the happy path and at least one failure mode (auth refusal,
   rate limit, malformed response).

## How to add a new output format

Reporters live in `crates/core/src/report/` and the dispatch lives
in `crates/cli/src/reporting.rs`. Each reporter implements the
`keyhog_core::Reporter` trait (`crates/core/src/report.rs`):

```rust
pub trait Reporter: Send {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError>;
    fn finish(&mut self) -> Result<(), ReportError>;
}
```

1. Add a new module under `crates/core/src/report/`. Pattern-match
   `text.rs`, `json.rs`, or `sarif.rs`.
2. Re-export the type from `crates/core/src/report.rs`.
3. Add the corresponding `OutputFormat` variant in
   `crates/cli/src/args/enums.rs`.
4. Wire it into `crates/cli/src/reporting.rs::write_findings`.
5. Add a golden-file test confirming the byte-exact output for a
   canonical finding.

## How to run tests

The workspace uses standard `cargo` commands. There is no
Makefile; the few one-off scripts live in `scripts/`. The most
commonly-used commands:

```bash
cargo test --workspace                      # full test suite
cargo test -p keyhog-scanner                # only the engine
cargo test -p keyhog-core --test all_tests  # core invariants
cargo clippy --workspace --all-targets      # advisory lint visibility (not a hard gate)
cargo build --release -p keyhog             # production binary
cargo run --release -- scan .               # dogfood
cargo bench -p keyhog-scanner               # microbenchmarks
```

For the multi-hour adversarial / corpus suites, see
`tests/README.md` or the workflows under `.github/workflows/`.

## Code style

We follow standard Rust conventions enforced by `cargo fmt` and
`cargo clippy`:

- Import ordering: `std`, external crates, internal `crate::`.
- Types `PascalCase`, fns + vars `snake_case`, consts
  `SCREAMING_SNAKE_CASE`.
- Booleans read as questions (`is_valid`, `has_findings`).
- Zero `unwrap()` / `expect()` in non-test code; propagate with `?`.
- Error messages lowercase, actionable, specific. Include the
  fix the user should try whenever possible.
- Public items have doc comments.
- Files cap at ~500 lines. Split when you cross it.

## PR checklist

Before opening a PR:

- [ ] `cargo test --workspace` passes.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is
      green.
- [ ] If you added a detector, you also added a positive fixture
      AND an adversarial (false-positive) fixture.
- [ ] If you fixed a bug, you added a test that fails before your
      patch and passes after.
- [ ] No stubs (`todo!()`, `unimplemented!()`, no-op loops,
      `// TODO` placeholders).
- [ ] New public items are documented.
- [ ] Commit messages explain *why*, not just *what*.

## Reporting a vulnerability

Do **not** open a public issue for a security report. Use GitHub's
private advisory flow at
[/security/advisories/new](https://github.com/santhsecurity/keyhog/security/advisories/new)
or email **security@santh.dev**.

## Contributors

keyhog is built by the Santh team and sharpened by community
contributions. Every merged PR earns a line here - thank you to
everyone who has sent a fix, a detector, or a test:

- [@Eraminel01](https://github.com/Eraminel01) (Edyard) - corrected the
  Anthropic API key detector shape
  ([#7](https://github.com/santhsecurity/keyhog/pull/7)).

New contributors: add yourself to this list in the same PR as your
change. One line, newest last: `[@handle](profile) - what you
improved ([#PR](link)).`
