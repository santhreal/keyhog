# keyhog

[![santh](https://img.shields.io/badge/santh-alpha-ffd60a?style=flat-square&labelColor=0a0a0a)](https://santh.dev/keyhog/)

Command-line interface, scan orchestrator, calibration driver, and Unix daemon for the [KeyHog](https://github.com/santhreal/keyhog) secret scanner.

```sh
cargo install --locked keyhog
keyhog scan .
```

## Public entry points

- `cli_main` parses command-line arguments, loads `.keyhog.toml` and `.keyhogignore`, and dispatches subcommands with typed exit codes.
- `args::command` builds the `clap::Command` model for help generation, shell completions, and CLI surface verification.
- `daemon` provides the Unix domain socket protocol, server, and warm-scanner client used by `keyhog daemon` and `keyhog guard`.

## Failure behavior

Exit codes separate clean scans (`0`), blocking findings (`1`), operator errors (`2`), system errors (`3`), health/self-test failures (`4`), live credentials (`10`), scanner panics (`11`), required GPU failures (`12`), incomplete coverage (`13`), and interrupts (`130`).

## Documentation

- [CLI reference](https://santhreal.github.io/keyhog/reference/cli.html)
- [Configuration reference](https://santhreal.github.io/keyhog/reference/configuration.html)
- [Exit codes](https://santhreal.github.io/keyhog/reference/exit-codes.html)
