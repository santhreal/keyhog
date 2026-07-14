# keyhog benchmarking framework - entrypoints.
#
# Every target is a thin wrapper over `python3 -m bench ...` so the logic
# lives in the tested package, not the Makefile. Paths resolve relative to
# this file so it works from any cwd.
#
#   make test              # pytest the bench package
#   make host              # print host hardware JSON
#   make mirror            # generate the 15k synthetic mirror corpus if absent
#   make ioc-recovery-corpus  # generate the 4,368-file P0-P12 recovery corpus
#   make ioc-recovery         # compare all four KeyHog presets on recovery phases
#   make agentre-corpus       # verify sources and build the pinned Linux binaries
#   make leakage-audit        # prove train/calibration/sealed-test split isolation
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
#   make cross-device-gate # require 10x speed dominance vs Betterleaks/Kingfisher on every OS
#   make loop              # full improvement loop: corpus->leaderboard->calibrate->report->gate
#   make keyhog            # build the release binary (run in background; cargo is slow)

BENCH_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
REPO_ROOT := $(abspath $(BENCH_DIR)/..)
PY        ?= python3
export PYTHONDONTWRITEBYTECODE := 1

# Optional explicit binary override. If unset, the KeyHog adapter resolves the
# freshly built release binary from CARGO_TARGET_DIR, cargo config, repo target,
# then PATH.
SCANNER          ?= keyhog
SCANNERS         ?= keyhog,betterleaks,kingfisher,noseyparker,trufflehog,titus
CORPUS           ?= mirror
OUTPUT           ?= -
OUT              ?= results
ANALYZE_TOP      ?= 15
IOC_RECOVERY_SAMPLES ?= 336
IOC_RECOVERY_OUT ?= results-ioc-recovery
LEAKAGE_MANIFEST ?=
LEAKAGE_CONTENT_ROOT ?=
LEAKAGE_RECEIPT ?= reports/leakage-receipt.json

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

.PHONY: help test targets host mirror ioc-recovery-corpus ioc-recovery agentre-corpus leakage-audit creddata kernel-info run analyze bench leaderboard report report-check org-audit gate cross-device-gate loop keyhog clean

help:
	@grep -E '^#   make ' $(lastword $(MAKEFILE_LIST)) | sed 's/^#   /  /'

test:
	cd $(BENCH_DIR) && PYTHONDONTWRITEBYTECODE=1 $(PY) -B -m pytest -p no:cacheprovider -q -m 'not target_spec' bench/tests

targets:
	cd $(BENCH_DIR) && PYTHONDONTWRITEBYTECODE=1 $(PY) -B -m pytest -p no:cacheprovider -q -m target_spec bench/tests

host:
	cd $(BENCH_DIR) && $(PY) -m bench host

mirror:
	cd $(BENCH_DIR) && $(PY) -m bench.corpora.mirror --ensure

ioc-recovery-corpus:
	cd $(BENCH_DIR) && $(PY) -m bench.corpora.ioc_recovery --ensure --samples "$(IOC_RECOVERY_SAMPLES)"

ioc-recovery: ioc-recovery-corpus
	cd $(BENCH_DIR) && $(PY) -m bench leaderboard --corpus ioc-recovery \
		--scanners keyhog --matrix mode --out "$(IOC_RECOVERY_OUT)"

agentre-corpus:
	cd $(BENCH_DIR) && $(PY) -m bench.agentre_build --ensure

leakage-audit:
	@test -n "$(LEAKAGE_MANIFEST)" || { echo "LEAKAGE_MANIFEST is required" >&2; exit 2; }
	@test -n "$(LEAKAGE_CONTENT_ROOT)" || { echo "LEAKAGE_CONTENT_ROOT is required" >&2; exit 2; }
	cd $(BENCH_DIR) && $(PY) -m bench.leakage_guard "$(LEAKAGE_MANIFEST)" \
		--content-root "$(LEAKAGE_CONTENT_ROOT)" --receipt "$(LEAKAGE_RECEIPT)"

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
	cd $(BENCH_DIR) && PYTHONDONTWRITEBYTECODE=1 $(PY) -B -m pytest -p no:cacheprovider -q -m 'not target_spec' bench/tests
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
	# Make uses /bin/sh, so use POSIX find instead of a bash globstar. Clean both
	# the importable package and generator modules at every nesting depth.
	cd $(BENCH_DIR) && find bench generators -type d -name __pycache__ -prune -exec rm -rf {} +; rm -rf .pytest_cache
