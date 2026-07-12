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
#   make analyze           # print top FP/FN examples for SCANNER on CORPUS
#   make bench             # run all SCANNERS over CORPUS -> results/<host>/
#   make leaderboard       # alias of bench (run SCANNERS over CORPUS into OUT)
#   make report            # render reports/ + inject the leaderboard into ../README.md
#   make report-check      # CI gate: fail if the README tables are stale
#   make org-audit         # fail on stale claims and generated organization bloat
#   make gate              # regression + differential gate (keyhog must lead + not regress)
#   make cross-device-gate # require 10x speed dominance vs BetterLeaks/Kingfisher on every OS
#   make loop              # full improvement loop: corpus->leaderboard->calibrate->report->gate
#   make keyhog            # build the release binary (run in background; cargo is slow)

BENCH_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
REPO_ROOT := $(abspath $(BENCH_DIR)/..)
PY        ?= python3

# Optional explicit binary override. If unset, the Keyhog adapter resolves the
# freshly built release binary from CARGO_TARGET_DIR, cargo config, repo target,
# then PATH.
SCANNER          ?= keyhog
SCANNERS         ?= keyhog,betterleaks,kingfisher,noseyparker,trufflehog,titus
CORPUS           ?= mirror
OUTPUT           ?= -
OUT              ?= results
ANALYZE_TOP      ?= 15

# Gate / loop knobs. The loop measures every available scanner but gates
# keyhog against the required competitors plus the committed regression anchor;
# EPSILON is the allowed F1 slack.
GATE_SCANNERS    ?= keyhog,betterleaks,kingfisher
REQUIRE_COMPETITORS ?= betterleaks,kingfisher
BASELINE         ?= baselines/mirror-keyhog-baseline.json
EPSILON          ?= 0.005
CALIBRATION_OUT  ?= reports/calibration.toml

ifneq ($(strip $(KEYHOG_BIN)),)
export KEYHOG_BIN
endif

.PHONY: help test host mirror creddata kernel-info run analyze bench leaderboard report report-check org-audit gate cross-device-gate loop keyhog clean

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

analyze:
	cd $(BENCH_DIR) && $(PY) -m bench analyze --scanner "$(SCANNER)" --corpus "$(CORPUS)" --top "$(ANALYZE_TOP)"

bench leaderboard:
	cd $(BENCH_DIR) && $(PY) -m bench leaderboard --corpus "$(CORPUS)" --scanners "$(SCANNERS)" --out "$(OUT)"

report:
	cd $(BENCH_DIR) && $(PY) -m bench report --results "$(OUT)" --reports reports --corpus "$(CORPUS)" --inject

report-check:
	cd $(BENCH_DIR) && $(PY) -m bench report --results "$(OUT)" --reports reports --corpus "$(CORPUS)" --check

org-audit:
	cd $(REPO_ROOT) && $(PY) scripts/org_audit.py

# Regression + differential gate. Consumes the existing results/ (run `make
# leaderboard` first, or `make loop` to do the whole chain). Fails non-zero if
# keyhog doesn't lead every available competitor or regresses past BASELINE.
gate:
	cd $(BENCH_DIR) && $(PY) -m bench gate --corpus "$(CORPUS)" --results "$(OUT)" \
		--scanners "$(GATE_SCANNERS)" --baseline "$(BASELINE)" --epsilon "$(EPSILON)" \
		--require-competitors "$(REQUIRE_COMPETITORS)"

cross-device-gate:
	cd $(BENCH_DIR) && $(PY) -m bench cross-device --corpus "$(CORPUS)" \
		--root results-cross-device --dominance-gate --factor 10 \
		--required-oses linux,macos,windows

# Production continuous-improvement loop. One command runs the whole chain:
# scorer self-tests -> ensure corpus -> measure every scanner (detection + speed)
# -> recalibrate per-detector floors -> regenerate README tables -> GATE. A
# regression (competitor overtakes keyhog, or F1 drops past the committed
# baseline) fails the target non-zero. This is the local mirror of the
# bench-nightly + differential-bench workflows.
loop:
	cd $(BENCH_DIR) && $(PY) -m pytest -q bench/tests
	cd $(BENCH_DIR) && $(PY) -m bench.corpora.mirror --ensure
	cd $(BENCH_DIR) && $(PY) -m bench leaderboard --corpus "$(CORPUS)" --scanners "$(SCANNERS)" --out "$(OUT)"
	cd $(BENCH_DIR) && $(PY) -m bench calibrate --corpus "$(CORPUS)" --emit-toml "$(CALIBRATION_OUT)"
	cd $(BENCH_DIR) && $(PY) -m bench report --results "$(OUT)" --reports reports --corpus "$(CORPUS)"
	cd $(BENCH_DIR) && $(PY) -m bench gate --corpus "$(CORPUS)" --results "$(OUT)" \
		--scanners "$(GATE_SCANNERS)" --baseline "$(BASELINE)" --epsilon "$(EPSILON)" \
		--require-competitors "$(REQUIRE_COMPETITORS)"
	@echo "loop OK. README injection is a deliberate full-scanner step: make report"

# Build is intentionally NOT auto-run by other targets: cargo workspace
# builds are slow and the harness wants them backgrounded.
keyhog:
	cd $(REPO_ROOT) && cargo build --release -p keyhog --bin keyhog

clean:
	# `bench/**/__pycache__` is a bash globstar, but make runs recipes with /bin/sh
	# where `**` collapses to a single-level `*` and misses nested __pycache__.
	# `find` is POSIX and recurses to every depth.
	cd $(BENCH_DIR) && find bench -type d -name __pycache__ -prune -exec rm -rf {} +; rm -rf .pytest_cache
