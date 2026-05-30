# CLI surface bloat

`scan` carries 68 flags; the binary exposes 18 subcommands. Surface this large
is hard to keep coherent, document, and test. Candidates to consolidate.

## Flag convention inconsistency
- **CLI-01 · high · scan vs detectors** — output format flag is inconsistent: `scan --format <text|json|...>` but `detectors --json` (boolean). Unify on `--format` everywhere (or `--json` everywhere). Found by dogfood: `detectors --format json` → exit 2 "unexpected argument '--format'".
- **CLI-02 · med · scan** — both `--daemon` and `--no-daemon` exist as a clap conflict pair; combining them exits 2. Collapse to a single `--daemon[=auto|on|off]` or a default + one override.

## Subcommand overlap (3 live-scan modes)
- **CLI-03 · med · watch / daemon / tui** — three subcommands all do "scan-as-things-change / long-lived": `watch` (daemon mode), `daemon` (manage long-lived daemon), `tui` (live dashboard). Plus `scan --daemon`. Clarify the model: is `watch` just `daemon` + a path? Is `tui` a frontend over `daemon`? Collapse or document the distinction.
- **CLI-04 · low · update / repair / uninstall** — self-management trio (download/self-replace/reinstall/remove). Reasonable for a distributed binary, but audit whether `repair` is just `update --force` and whether this belongs in the core scanner binary vs an installer.
- **CLI-05 · low · scan-system vs scan** — `scan-system` (recursive system-wide, every mount + git history) is `scan` with a preset source set. Could be `scan --system` instead of a top-level subcommand.

## Source-flag sprawl on `scan`
- **CLI-06 · med · scan** — ~13 mutually-themed source flags live flat on `scan`: `--stdin --git-blobs --git-diff --git-history --git-staged --git-diff-path --github-org --github-token --s3-bucket --s3-prefix --s3-endpoint --docker-image --url`. Consider grouping under a `--source` dispatch (already exists as `--source <NAME>`) so the source backend owns its own flags (per Tier-A/Tier-B + crates-of-crates source model).
- **CLI-07 · low · scan** — preset flags `--fast/--deep/--lockdown` coexist with the individual knobs they set (`--decode-depth --min-confidence --no-decode --no-entropy --ml-threshold`). Document precedence (MC-02: presets currently early-return and drop overrides).

## Action item
- **CLI-08 · med** — add a snapshot test that asserts the help/flag surface per subcommand (so flag additions are deliberate and the count can't silently grow). Pairs with the test-expansion vector.
