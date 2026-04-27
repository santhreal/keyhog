#!/usr/bin/env bash
set -euo pipefail

cargo run -p xtask --bin xtask -- abstraction-gate
