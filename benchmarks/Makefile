# keyhog benchmarking framework - entrypoints.
#
# Every target is a thin wrapper over `python3 -m bench ...` so the logic
# lives in the tested package, not the Makefile. Paths resolve relative to
# this file so it works from any cwd.
#
#   make test              # pytest the bench package
#   make host              # print host hardware JSON
#   make mirror            # generate the 15k synthetic mirror corpus if absent
#   make creddata          # print Samsung/CredData corpus info
#   make kernel-info       # print perf corpus info
#   make run               # run SCANNER=keyhog CORPUS=mirror once
#   make bench             # run all SCANNERS over CORPUS -> results/<host>/
#   make leaderboard       # alias of bench (run SCANNERS over CORPUS into OUT)
#   make report            # render reports/ + inject the leaderboard into ../README.md
#   make report-check      # CI gate: fail if the README tables are stale
#   make keyhog            # build the release binary (run in background; cargo is slow)

BENCH_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
REPO_ROOT := $(abspath $(BENCH_DIR)/..)
PY        ?= python3

# keyhog release binary: honor KEYHOG_BIN, else the globally-configured
# cargo target-dir (see ~/.cargo/config.toml target-dir), else PATH.
CARGO_TARGET_DIR ?= /mnt/FlareTraining/santh-archive/cargo-target
KEYHOG_BIN       ?= $(CARGO_TARGET_DIR)/release/keyhog
SCANNER          ?= keyhog
SCANNERS         ?= keyhog,betterleaks,kingfisher,noseyparker,trufflehog,titus
CORPUS           ?= mirror
OUTPUT           ?= -
OUT              ?= results

export KEYHOG_BIN

.PHONY: help test host mirror creddata kernel-info run bench leaderboard report report-check keyhog clean

help:
	@grep -E '^#   make ' $(lastword $(MAKEFILE_LIST)) | sed 's/^#   /  /'

test:
	cd $(BENCH_DIR) && $(PY) -m pytest -q bench/tests

host:
	cd $(BENCH_DIR) && $(PY) -m bench host

mirror:
	cd $(BENCH_DIR) && $(PY) -m bench.corpora.mirror --ensure

creddata:
	cd $(BENCH_DIR) && $(PY) -m bench.corpora.creddata

kernel-info:
	cd $(BENCH_DIR) && $(PY) -m bench corpus kernel

run:
	cd $(BENCH_DIR) && $(PY) -m bench run "$(SCANNER)" "$(CORPUS)" --output "$(OUTPUT)"

bench leaderboard:
	cd $(BENCH_DIR) && $(PY) -m bench leaderboard --corpus "$(CORPUS)" --scanners "$(SCANNERS)" --out "$(OUT)"

report:
	cd $(BENCH_DIR) && $(PY) -m bench report --results "$(OUT)" --reports reports --corpus "$(CORPUS)" --inject

report-check:
	cd $(BENCH_DIR) && $(PY) -m bench report --results "$(OUT)" --reports reports --corpus "$(CORPUS)" --check

# Build is intentionally NOT auto-run by other targets: cargo workspace
# builds are slow and the harness wants them backgrounded.
keyhog:
	cd $(REPO_ROOT) && cargo build --release -p keyhog --bin keyhog

clean:
	cd $(BENCH_DIR) && rm -rf bench/__pycache__ bench/**/__pycache__ .pytest_cache
